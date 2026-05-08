/*
 * EATAN — ESP32 Sensor Node Firmware
 * eatan/esp32/eatan_node/eatan_node.ino
 *
 * Target:   ESP32-N32R16V-M (8MB flash, 16MB PSRAM)
 * Board:    "ESP32 Dev Module" in Arduino IDE
 *           (Partition: "No OTA (2MB APP/2MB SPIFFS)" or custom)
 *
 * Libraries required (install via Arduino Library Manager):
 *   - PubSubClient          (Nick O'Leary)         MQTT
 *   - ArduinoJson           (Benoit Blanchon)       JSON
 *   - ESP32 BLE Arduino     (built-in with esp32)   BLE scan
 *
 * Board package:
 *   - esp32 by Espressif (≥ 2.0.14) via Arduino Boards Manager
 *     URL: https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json
 *
 * What this firmware does:
 *   1. Connects to the EATAN internal WiFi AP (hosted by the RPi)
 *   2. Connects to Mosquitto MQTT on the RPi (192.168.4.1:1883 by default)
 *   3. Runs continuous BLE passive scan — publishes each unique advertisement
 *   4. Runs WiFi promiscuous mode sniffer — publishes 802.11 probe requests
 *      and management frames (does NOT inject or interfere with traffic)
 *   5. Buffers records in PSRAM ring buffer when MQTT is unavailable
 *   6. Publishes heartbeat every 30s
 *   7. Subscribes to eatan/system/cmd/{node_id} for remote commands:
 *      {"cmd":"reboot"} | {"cmd":"status"} | {"cmd":"set_ble_interval","value":5000}
 *
 * MQTT topics published:
 *   eatan/raw/ble          — BLE advertisement records
 *   eatan/raw/wifi_probe   — 802.11 probe request records
 *   eatan/system/heartbeat — node health
 */

// ── Compile-time configuration ────────────────────────────────────────────────
// Edit these before flashing. Node ID should be unique per board.
#define EATAN_NODE_ID        "esp32-alpha"
#define EATAN_WIFI_SSID      "EATAN-NET"          // RPi internal AP SSID
#define EATAN_WIFI_PASSWORD  "eatanmk1field"      // Change before deployment
#define MQTT_SERVER          "192.168.4.1"        // RPi AP gateway IP
#define MQTT_PORT            1883
#define MQTT_TOPIC_PREFIX    "eatan"

// Scanning parameters
#define BLE_SCAN_WINDOW_MS   100    // BLE scan window (ms)
#define BLE_SCAN_INTERVAL_MS 200    // BLE scan interval (ms) — duty cycle 50%
#define BLE_SCAN_DURATION_S  5      // seconds per scan pass (0 = continuous)
#define WIFI_SNIFFER_ENABLED true   // Set false if only BLE is wanted
#define HEARTBEAT_INTERVAL_MS 30000

// PSRAM ring buffer — stores JSON strings while MQTT is down
// 16MB PSRAM → allocate 2MB for the buffer (~8000 typical records)
#define BUFFER_SIZE_BYTES    (2 * 1024 * 1024)

// ── Includes ──────────────────────────────────────────────────────────────────
#include <Arduino.h>
#include <WiFi.h>
#include <WiFiClient.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <BLEDevice.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>
#include <esp_wifi.h>
#include <esp_wifi_types.h>
#include "esp_heap_caps.h"

// ── Forward declarations ──────────────────────────────────────────────────────
void wifi_sniffer_packet_handler(void* buf, wifi_promiscuous_pkt_type_t type);
void mqtt_callback(char* topic, byte* payload, unsigned int length);
bool mqtt_publish_buffered(const char* topic, const char* payload);

// ── PSRAM ring buffer ─────────────────────────────────────────────────────────
// Simple append-only ring buffer with length-prefixed entries (4 bytes + data)
// Stored in PSRAM — does not consume precious DRAM.

struct PsramBuffer {
    uint8_t* base    = nullptr;
    size_t   size    = 0;
    size_t   head    = 0;   // write position
    size_t   tail    = 0;   // read position
    size_t   count   = 0;   // number of records

    bool init(size_t bytes) {
        base = (uint8_t*)heap_caps_malloc(bytes, MALLOC_CAP_SPIRAM);
        if (!base) return false;
        size = bytes;
        return true;
    }

    // Push a null-terminated string + its topic (encoded as "TOPIC\nPAYLOAD\0")
    bool push(const char* topic, const char* payload) {
        // Format: [4-byte length][topic\npayload\0]
        char entry[768];
        int  len = snprintf(entry, sizeof(entry), "%s\n%s", topic, payload);
        if (len <= 0 || len >= (int)sizeof(entry)) return false;
        uint32_t entry_len = (uint32_t)(len + 1);
        uint32_t needed    = 4 + entry_len;
        if (needed > size / 2) return false;   // entry too large

        // Wrap if needed (simple — may overwrite oldest on overflow)
        if (head + needed > size) head = 0;
        memcpy(base + head, &entry_len, 4);
        memcpy(base + head + 4, entry, entry_len);
        head += 4 + entry_len;
        count++;
        if (tail == head) tail = (tail + needed) % size;  // advance tail on overflow
        return true;
    }

    // Pop one record; returns false if empty
    bool pop(char* topic_out, size_t topic_len,
             char* payload_out, size_t payload_len) {
        if (count == 0 || tail == head) return false;
        uint32_t entry_len;
        memcpy(&entry_len, base + tail, 4);
        if (entry_len == 0 || entry_len > 768) { tail = 0; count = 0; return false; }
        char entry[768] = {};
        memcpy(entry, base + tail + 4, min((uint32_t)767, entry_len));
        tail += 4 + entry_len;
        if (tail >= size) tail = 0;
        count = (count > 0) ? count - 1 : 0;

        // Split at first newline
        char* nl = strchr(entry, '\n');
        if (!nl) return false;
        *nl = '\0';
        strncpy(topic_out, entry, topic_len - 1);
        strncpy(payload_out, nl + 1, payload_len - 1);
        return true;
    }

    bool empty() { return count == 0 || tail == head; }
} psram_buf;

// ── MQTT / WiFi globals ───────────────────────────────────────────────────────
WiFiClient   wifi_client;
PubSubClient mqtt_client(wifi_client);
unsigned long last_heartbeat  = 0;
unsigned long last_reconnect  = 0;
unsigned long ble_scan_count  = 0;
unsigned long probe_count     = 0;
bool          psram_available = false;

// ── BLE ───────────────────────────────────────────────────────────────────────
BLEScan* ble_scan = nullptr;
SemaphoreHandle_t mqtt_mutex;

// ── WiFi sniffer frame structures ─────────────────────────────────────────────
// 802.11 management frame header (simplified)
typedef struct {
    uint8_t  frame_ctrl[2];
    uint16_t duration;
    uint8_t  dest[6];
    uint8_t  source[6];
    uint8_t  bssid[6];
    uint16_t seq_ctrl;
} __attribute__((packed)) wifi_mgmt_header_t;

typedef struct {
    wifi_mgmt_header_t hdr;
    uint8_t            payload[0];
} __attribute__((packed)) wifi_mgmt_frame_t;

// ── Helpers ───────────────────────────────────────────────────────────────────

String mac_to_str(const uint8_t* mac) {
    char buf[18];
    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return String(buf);
}

String mac_to_str(const String& mac_str) { return mac_str; }

// Vendor OUI table — compact set for common devices
const char* lookup_oui(const uint8_t* mac) {
    uint32_t oui = ((uint32_t)mac[0] << 16) | ((uint32_t)mac[1] << 8) | mac[2];
    switch (oui) {
        case 0xF0189B: return "Apple";
        case 0xDC2B2A: return "Apple";
        case 0xA4C361: return "Apple";
        case 0xB4CD27: return "Raspberry Pi";
        case 0xD83ADD: return "Raspberry Pi";
        case 0x001BC5: return "Ubiquiti";
        case 0x001A11: return "Google";
        case 0xB8E856: return "Samsung";
        case 0xC4574F: return "Samsung";
        case 0x001D72: return "Huawei";
        case 0x001E10: return "Huawei";
        case 0x0090A9: return "Alfa";
        default:       return nullptr;
    }
}

int64_t timestamp_ms() {
    // ESP32 doesn't have RTC synced to UTC without NTP.
    // We send millis() offset; the RPi bridge adds the wall-clock timestamp.
    return (int64_t)millis();
}

// ── MQTT helpers ──────────────────────────────────────────────────────────────

bool mqtt_publish_buffered(const char* topic, const char* payload) {
    if (xSemaphoreTake(mqtt_mutex, pdMS_TO_TICKS(50)) == pdTRUE) {
        bool ok = false;
        if (mqtt_client.connected()) {
            ok = mqtt_client.publish(topic, payload, false);
            // Also drain buffer if connected
            if (ok && psram_available && !psram_buf.empty()) {
                char buf_topic[128], buf_payload[640];
                int drained = 0;
                while (!psram_buf.empty() && drained < 10) {
                    if (psram_buf.pop(buf_topic, sizeof(buf_topic),
                                      buf_payload, sizeof(buf_payload))) {
                        mqtt_client.publish(buf_topic, buf_payload, false);
                        drained++;
                    } else break;
                }
            }
        } else {
            // Buffer for later
            if (psram_available) {
                psram_buf.push(topic, payload);
                ok = true;
            }
        }
        xSemaphoreGive(mqtt_mutex);
        return ok;
    }
    return false;
}

void mqtt_callback(char* topic, byte* payload, unsigned int length) {
    // Handle incoming commands on eatan/system/cmd/{node_id}
    StaticJsonDocument<256> doc;
    if (deserializeJson(doc, payload, length) != DeserializationError::Ok) return;

    const char* cmd = doc["cmd"];
    if (!cmd) return;

    if (strcmp(cmd, "reboot") == 0) {
        Serial.println("[EATAN] Remote reboot command received");
        delay(500);
        ESP.restart();
    } else if (strcmp(cmd, "status") == 0) {
        // Publish status response
        StaticJsonDocument<384> status;
        status["node_id"]       = EATAN_NODE_ID;
        status["uptime_ms"]     = millis();
        status["ble_scanned"]   = ble_scan_count;
        status["probes_seen"]   = probe_count;
        status["buf_count"]     = psram_available ? (int)psram_buf.count : -1;
        status["free_heap"]     = ESP.getFreeHeap();
        status["free_psram"]    = ESP.getFreePsram();
        status["wifi_rssi"]     = WiFi.RSSI();
        char out[384];
        serializeJson(status, out, sizeof(out));
        char resp_topic[64];
        snprintf(resp_topic, sizeof(resp_topic), "%s/system/node_status", MQTT_TOPIC_PREFIX);
        mqtt_client.publish(resp_topic, out);
    } else if (strcmp(cmd, "set_ble_interval") == 0) {
        // Future: dynamically adjust BLE scan timing
        Serial.printf("[EATAN] set_ble_interval: %d ms\n", (int)doc["value"]);
    }
}

bool mqtt_connect() {
    char client_id[48];
    snprintf(client_id, sizeof(client_id), "eatan-%s", EATAN_NODE_ID);

    char cmd_topic[64];
    snprintf(cmd_topic, sizeof(cmd_topic), "%s/system/cmd/%s",
             MQTT_TOPIC_PREFIX, EATAN_NODE_ID);

    if (mqtt_client.connect(client_id)) {
        mqtt_client.subscribe(cmd_topic);
        Serial.printf("[MQTT] Connected as %s\n", client_id);
        return true;
    }
    return false;
}

// ── BLE Scanner ───────────────────────────────────────────────────────────────

class EatanBLECallback : public BLEAdvertisedDeviceCallbacks {
public:
    void onResult(BLEAdvertisedDevice device) override {
        // Build JSON record
        StaticJsonDocument<640> doc;
        doc["node_id"]     = EATAN_NODE_ID;
        doc["sensor_type"] = "ble";
        doc["ts_offset"]   = timestamp_ms();   // RPi adds wall clock
        doc["rssi"]        = device.getRSSI();

        String mac = device.getAddress().toString().c_str();
        mac.toUpperCase();
        doc["mac_address"] = mac;

        if (device.haveName())
            doc["name"] = device.getName().c_str();

        if (device.haveServiceUUID())
            doc["service_uuid"] = device.getServiceUUID().toString().c_str();

        if (device.haveManufacturerData()) {
            std::string mfr = device.getManufacturerData();
            // First 2 bytes are company ID (little-endian)
            if (mfr.size() >= 2) {
                uint16_t company_id = (uint8_t)mfr[0] | ((uint8_t)mfr[1] << 8);
                doc["company_id"] = company_id;
                // Common company IDs
                switch (company_id) {
                    case 0x004C: doc["company"] = "Apple";        break;
                    case 0x0006: doc["company"] = "Microsoft";    break;
                    case 0x0075: doc["company"] = "Samsung";      break;
                    case 0x00E0: doc["company"] = "Google";       break;
                    case 0x0131: doc["company"] = "Xiaomi";       break;
                    default:     doc["company"] = "Unknown";      break;
                }
            }
        }

        // BLE device type classification
        int addr_type = (int)device.getAddressType();
        if (addr_type == 1) {
            doc["addr_type"] = "random";    // likely privacy-rotating — mobile device
        } else {
            doc["addr_type"] = "public";    // fixed MAC — IoT / wearable / beacon
        }

        // TX Power (useful for rough distance estimation)
        if (device.haveTXPower())
            doc["tx_power"] = device.getTXPower();

        // Build device key
        char device_key[80];
        snprintf(device_key, sizeof(device_key), "ble:%s", mac.c_str());
        doc["device_key"] = device_key;

        char payload[640];
        serializeJson(doc, payload, sizeof(payload));

        char topic[64];
        snprintf(topic, sizeof(topic), "%s/raw/ble", MQTT_TOPIC_PREFIX);

        mqtt_publish_buffered(topic, payload);
        ble_scan_count++;
    }
};

EatanBLECallback ble_callback;

// BLE scan task — runs on Core 0 (WiFi uses Core 1 by default on ESP32)
void ble_scan_task(void* param) {
    Serial.println("[BLE] Scan task started on Core 0");
    ble_scan = BLEDevice::getScan();
    ble_scan->setAdvertisedDeviceCallbacks(&ble_callback, false);  // false = report duplicates
    ble_scan->setActiveScan(false);    // PASSIVE — do not send scan requests
    ble_scan->setWindow(BLE_SCAN_WINDOW_MS);
    ble_scan->setInterval(BLE_SCAN_INTERVAL_MS);

    for (;;) {
        // BLE_SCAN_DURATION_S = 0 → continuous; >0 → batch mode
        ble_scan->start(BLE_SCAN_DURATION_S, false);
        ble_scan->clearResults();
        vTaskDelay(pdMS_TO_TICKS(100));
    }
}

// ── WiFi Promiscuous Sniffer ──────────────────────────────────────────────────
// Captures 802.11 management frames, extracts probe requests.
// Probe requests are sent by devices searching for known SSIDs —
// they reveal devices in range before they associate with any AP.

void wifi_sniffer_packet_handler(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT) return;

    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    wifi_mgmt_header_t* hdr = (wifi_mgmt_header_t*)pkt->payload;

    // Frame control byte 0: bits 2-3 = type (0=mgmt), bits 4-5 = subtype
    uint8_t fc0     = pkt->payload[0];
    uint8_t fc1     = pkt->payload[1];
    uint8_t subtype = (fc0 >> 4) & 0x0F;
    uint8_t ftype   = (fc0 >> 2) & 0x03;

    // Only management frames (type 0)
    if (ftype != 0) return;

    // Subtypes of interest:
    // 0x04 = Probe Request
    // 0x00 = Association Request
    // 0x02 = Reassociation Request
    // 0x08 = Beacon (from APs)
    // 0x05 = Probe Response (from APs responding to probes)
    bool is_probe_req    = (subtype == 0x04);
    bool is_beacon       = (subtype == 0x08);
    bool is_probe_resp   = (subtype == 0x05);

    if (!is_probe_req && !is_beacon && !is_probe_resp) return;

    int8_t rssi = pkt->rx_ctrl.rssi;

    StaticJsonDocument<640> doc;
    doc["node_id"]     = EATAN_NODE_ID;
    doc["sensor_type"] = "wifi_probe";
    doc["ts_offset"]   = timestamp_ms();
    doc["rssi"]        = rssi;
    doc["channel"]     = pkt->rx_ctrl.channel;

    // Source MAC
    String src_mac = mac_to_str(hdr->source);
    doc["mac_address"] = src_mac;

    // OUI lookup
    const char* vendor = lookup_oui(hdr->source);
    if (vendor) doc["vendor_oui"] = vendor;

    // Build device key
    char device_key[80];
    snprintf(device_key, sizeof(device_key), "wifi:%s", src_mac.c_str());
    doc["device_key"] = device_key;

    if (is_probe_req) {
        doc["frame_type"] = "probe_req";
        // Parse SSID from probe request body (tag ID 0)
        // Payload starts at offset 24 (after 802.11 header)
        if (pkt->rx_ctrl.sig_len > 26) {
            uint8_t* body   = pkt->payload + 24;
            int      remain = pkt->rx_ctrl.sig_len - 24;
            if (remain > 2 && body[0] == 0) {
                // Tag 0 = SSID
                uint8_t ssid_len = body[1];
                if (ssid_len > 0 && ssid_len <= 32 && (2 + ssid_len) <= remain) {
                    char ssid[33] = {};
                    memcpy(ssid, body + 2, ssid_len);
                    // Sanitise — only printable ASCII
                    bool printable = true;
                    for (int i = 0; i < ssid_len; i++) {
                        if (ssid[i] < 0x20 || ssid[i] > 0x7E) { printable = false; break; }
                    }
                    if (printable)
                        doc["probed_ssid"] = ssid;
                }
            }
        }
    } else if (is_beacon || is_probe_resp) {
        doc["frame_type"] = (is_beacon) ? "beacon" : "probe_resp";
        // BSSID is the AP address (field 3 in management frame)
        doc["bssid"]      = mac_to_str(hdr->bssid);
        doc["dest_mac"]   = mac_to_str(hdr->dest);
        // Parse SSID from beacon body (offset 36: fixed params = 12 bytes after header)
        if (pkt->rx_ctrl.sig_len > 38) {
            uint8_t* body   = pkt->payload + 36;
            int      remain = pkt->rx_ctrl.sig_len - 36;
            if (remain > 2 && body[0] == 0) {
                uint8_t ssid_len = body[1];
                if (ssid_len > 0 && ssid_len <= 32 && (2 + ssid_len) <= remain) {
                    char ssid[33] = {};
                    memcpy(ssid, body + 2, ssid_len);
                    bool printable = true;
                    for (int i = 0; i < ssid_len; i++) {
                        if (ssid[i] < 0x20 || ssid[i] > 0x7E) { printable = false; break; }
                    }
                    if (printable)
                        doc["ssid"] = ssid;
                }
            }
        }
    }

    char payload[640];
    serializeJson(doc, payload, sizeof(payload));

    char topic[64];
    snprintf(topic, sizeof(topic), "%s/raw/wifi_probe", MQTT_TOPIC_PREFIX);
    mqtt_publish_buffered(topic, payload);
    probe_count++;
}

// ── WiFi connection ───────────────────────────────────────────────────────────

void connect_wifi() {
    Serial.printf("[WiFi] Connecting to %s", EATAN_WIFI_SSID);
    WiFi.mode(WIFI_STA);
    WiFi.begin(EATAN_WIFI_SSID, EATAN_WIFI_PASSWORD);

    int attempts = 0;
    while (WiFi.status() != WL_CONNECTED && attempts < 30) {
        delay(500);
        Serial.print(".");
        attempts++;
    }
    if (WiFi.status() == WL_CONNECTED) {
        Serial.printf("\n[WiFi] Connected. IP: %s  RSSI: %d dBm\n",
                      WiFi.localIP().toString().c_str(), WiFi.RSSI());
    } else {
        Serial.println("\n[WiFi] Failed to connect — will retry");
    }
}

// ── Heartbeat ─────────────────────────────────────────────────────────────────

void publish_heartbeat() {
    StaticJsonDocument<384> doc;
    doc["module"]      = "esp32_node";
    doc["node_id"]     = EATAN_NODE_ID;
    doc["status"]      = "ok";
    doc["timestamp"]   = timestamp_ms();
    doc["uptime_ms"]   = millis();
    doc["ble_scanned"] = ble_scan_count;
    doc["probes_seen"] = probe_count;
    doc["wifi_rssi"]   = WiFi.RSSI();
    doc["free_heap"]   = ESP.getFreeHeap();
    doc["free_psram"]  = ESP.getFreePsram();
    doc["buf_count"]   = psram_available ? (int)psram_buf.count : -1;
    doc["ip"]          = WiFi.localIP().toString();

    char payload[384];
    serializeJson(doc, payload, sizeof(payload));

    char topic[64];
    snprintf(topic, sizeof(topic), "%s/system/heartbeat", MQTT_TOPIC_PREFIX);
    mqtt_client.publish(topic, payload);
}

// ── Sniffer channel rotation ──────────────────────────────────────────────────
// Rotates through WiFi channels so probe requests on all channels are captured.
// BLE is unaffected (operates on a different radio path on ESP32).

const uint8_t CHANNELS_24[]  = {1, 6, 11, 2, 7, 3, 8, 4, 9, 5, 10, 12, 13};
const uint8_t CHANNELS_5[]   = {36, 40, 44, 48, 52, 56, 60, 64};
uint8_t ch_idx_24 = 0;
uint8_t ch_idx_5  = 0;
bool    band_5ghz = false;   // flip between bands
unsigned long last_ch_hop = 0;
#define CH_HOP_INTERVAL_MS 300   // dwell time per channel

void hop_channel() {
    if (millis() - last_ch_hop < CH_HOP_INTERVAL_MS) return;
    last_ch_hop = millis();

    uint8_t ch;
    if (!band_5ghz) {
        ch = CHANNELS_24[ch_idx_24 % (sizeof(CHANNELS_24))];
        ch_idx_24++;
        if (ch_idx_24 >= sizeof(CHANNELS_24)) { ch_idx_24 = 0; band_5ghz = true; }
    } else {
        ch = CHANNELS_5[ch_idx_5 % (sizeof(CHANNELS_5))];
        ch_idx_5++;
        if (ch_idx_5 >= sizeof(CHANNELS_5)) { ch_idx_5 = 0; band_5ghz = false; }
    }
    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
}

// ── setup() ──────────────────────────────────────────────────────────────────

void setup() {
    Serial.begin(115200);
    delay(500);

    Serial.println("\n\n════════════════════════════════════");
    Serial.println("  EATAN ESP32 Sensor Node");
    Serial.printf ("  Node ID: %s\n", EATAN_NODE_ID);
    Serial.println("════════════════════════════════════\n");

    // ── PSRAM ─────────────────────────────────────────────────────────────────
    if (psramFound()) {
        Serial.printf("[PSRAM] Found: %u bytes free\n", ESP.getFreePsram());
        psram_available = psram_buf.init(BUFFER_SIZE_BYTES);
        if (psram_available) {
            Serial.printf("[PSRAM] Ring buffer allocated: %u bytes\n", BUFFER_SIZE_BYTES);
        } else {
            Serial.println("[PSRAM] Buffer allocation failed");
        }
    } else {
        Serial.println("[PSRAM] Not found — buffering disabled");
    }

    // ── Mutex ─────────────────────────────────────────────────────────────────
    mqtt_mutex = xSemaphoreCreateMutex();

    // ── BLE ───────────────────────────────────────────────────────────────────
    BLEDevice::init("");
    Serial.println("[BLE] Initialised");

    // ── WiFi → connect then switch to promiscuous ──────────────────────────────
    connect_wifi();

    // ── MQTT ──────────────────────────────────────────────────────────────────
    mqtt_client.setServer(MQTT_SERVER, MQTT_PORT);
    mqtt_client.setCallback(mqtt_callback);
    mqtt_client.setBufferSize(768);   // accommodate larger JSON payloads
    mqtt_client.setKeepAlive(30);

    if (mqtt_connect()) {
        publish_heartbeat();
    }

    // ── WiFi promiscuous sniffer ───────────────────────────────────────────────
    // IMPORTANT: promiscuous mode is set AFTER normal WiFi connect.
    // The ESP32 maintains its station association while sniffing.
    if (WIFI_SNIFFER_ENABLED) {
        esp_wifi_set_promiscuous(true);
        esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);
        Serial.println("[WiFi] Promiscuous mode active — sniffing management frames");
    }

    // ── BLE scan task on Core 0 ───────────────────────────────────────────────
    xTaskCreatePinnedToCore(
        ble_scan_task,
        "ble_scan",
        8192,        // stack size (bytes)
        nullptr,
        1,           // priority
        nullptr,
        0            // Core 0
    );
    Serial.println("[BLE] Scan task created on Core 0");
    Serial.println("[EATAN] Setup complete\n");
}

// ── loop() ────────────────────────────────────────────────────────────────────

void loop() {
    // ── WiFi reconnect ────────────────────────────────────────────────────────
    if (WiFi.status() != WL_CONNECTED) {
        if (millis() - last_reconnect > 10000) {
            last_reconnect = millis();
            Serial.println("[WiFi] Disconnected — reconnecting...");
            WiFi.reconnect();
        }
    }

    // ── MQTT reconnect ────────────────────────────────────────────────────────
    if (!mqtt_client.connected() && WiFi.status() == WL_CONNECTED) {
        if (millis() - last_reconnect > 5000) {
            last_reconnect = millis();
            Serial.println("[MQTT] Reconnecting...");
            if (mqtt_connect()) {
                publish_heartbeat();
            }
        }
    }

    mqtt_client.loop();

    // ── Heartbeat ─────────────────────────────────────────────────────────────
    if (millis() - last_heartbeat > HEARTBEAT_INTERVAL_MS) {
        last_heartbeat = millis();
        if (mqtt_client.connected()) {
            publish_heartbeat();
        }
    }

    // ── Channel hop ───────────────────────────────────────────────────────────
    if (WIFI_SNIFFER_ENABLED) {
        hop_channel();
    }

    // Small yield to prevent watchdog triggers
    delay(1);
}
