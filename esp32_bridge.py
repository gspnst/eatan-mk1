#!/usr/bin/env python3
"""
EATAN — ESP32 Bridge Module
eatan/modules/esp32/esp32_bridge.py

Sits between the ESP32 nodes and the rest of the EATAN system.

Responsibilities:
  - Subscribe to eatan/raw/ble and eatan/raw/wifi_probe (published by ESP32 nodes)
  - Add wall-clock timestamps (ESP32 sends millis() offsets, not UTC)
  - Normalise into canonical DeviceRecord format
  - Re-publish to the same topics so the analysis engine sees them identically
    to records from other sensors
  - Track which ESP32 nodes are alive (heartbeat watchdog)
  - Expose per-node status for the operator dashboard
  - Allow sending commands to individual nodes (reboot, status request, etc.)

Run:
    ~/eatan/.venv/bin/python ~/eatan/modules/esp32/esp32_bridge.py
    (does NOT require root)
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from eatan_bus import (
    EatanBus, EatanConfig, EatanDB, DeviceRecord,
    AlertRecord, Topics, now_ms, lookup_vendor, configure_logging,
)

# ── Constants ─────────────────────────────────────────────────────────────────

MODULE_NAME = "esp32_bridge"

# If an ESP32 node hasn't sent a heartbeat in this long, mark it offline
NODE_TIMEOUT_SEC  = 90
NODE_CHECK_INTERVAL = 30.0

# BLE address types
BLE_ADDR_PUBLIC  = "public"
BLE_ADDR_RANDOM  = "random"   # privacy-rotating — common on iOS/Android

# BLE company IDs → classification hints
BLE_COMPANY_CLASSES: dict[int, str] = {
    0x004C: "Apple",       # iBeacon, AirDrop, AirPods, Find My
    0x0006: "Microsoft",   # Swift Pair, Surface
    0x0075: "Samsung",     # SmartThings, Galaxy
    0x00E0: "Google",      # Nearby Share, Fast Pair
    0x0131: "Xiaomi",
    0x0002: "IBM",
    0x004F: "Qualcomm",
    0x0059: "Nordic Semi", # common in IoT dev boards
}


# ── Node state tracking ────────────────────────────────────────────────────────

@dataclass
class NodeState:
    node_id:        str
    first_seen:     int = field(default_factory=now_ms)
    last_heartbeat: int = field(default_factory=now_ms)
    last_ts_offset: int = 0       # last millis() value received
    last_ts_wall:   int = 0       # wall clock at that moment (ms)
    wifi_rssi:      int | None = None
    free_heap:      int | None = None
    free_psram:     int | None = None
    buf_count:      int | None = None
    ble_scanned:    int = 0
    probes_seen:    int = 0
    ip:             str = ""
    online:         bool = True
    total_records:  int = 0

    def update_from_heartbeat(self, payload: dict) -> None:
        self.last_heartbeat  = now_ms()
        self.online          = True
        self.last_ts_offset  = payload.get("uptime_ms", 0)
        self.last_ts_wall    = now_ms()
        self.wifi_rssi       = payload.get("wifi_rssi")
        self.free_heap       = payload.get("free_heap")
        self.free_psram      = payload.get("free_psram")
        self.buf_count       = payload.get("buf_count")
        self.ble_scanned     = payload.get("ble_scanned", self.ble_scanned)
        self.probes_seen     = payload.get("probes_seen", self.probes_seen)
        self.ip              = payload.get("ip", self.ip)

    def estimate_wall_time(self, ts_offset: int) -> int:
        """
        Convert an ESP32 millis() offset to a wall-clock ms timestamp.
        Uses the most recent heartbeat sync point as reference.
        """
        if self.last_ts_wall == 0 or self.last_ts_offset == 0:
            return now_ms()
        elapsed_since_sync = ts_offset - self.last_ts_offset
        return self.last_ts_wall + elapsed_since_sync

    def is_timed_out(self) -> bool:
        return (now_ms() - self.last_heartbeat) > (NODE_TIMEOUT_SEC * 1000)

    def to_dict(self) -> dict:
        return {
            "node_id":        self.node_id,
            "online":         self.online,
            "last_heartbeat": self.last_heartbeat,
            "wifi_rssi":      self.wifi_rssi,
            "free_heap":      self.free_heap,
            "free_psram":     self.free_psram,
            "buf_count":      self.buf_count,
            "ble_scanned":    self.ble_scanned,
            "probes_seen":    self.probes_seen,
            "total_records":  self.total_records,
            "ip":             self.ip,
        }


# ── BLE record normaliser ─────────────────────────────────────────────────────

def normalise_ble(raw: dict, node: NodeState) -> DeviceRecord | None:
    """
    Convert a raw BLE record from an ESP32 into a canonical DeviceRecord.
    """
    mac = raw.get("mac_address", "").upper().strip()
    if not mac:
        return None

    # Resolve wall-clock timestamp
    ts_offset = raw.get("ts_offset", 0)
    timestamp = node.estimate_wall_time(ts_offset) if ts_offset else now_ms()

    # Classify device
    addr_type  = raw.get("addr_type", "public")
    company_id = raw.get("company_id")
    company    = raw.get("company", "Unknown")
    name       = raw.get("name")

    if addr_type == BLE_ADDR_RANDOM and company_id == 0x004C:
        dev_class = "Apple_mobile"   # rotating MAC + Apple = iPhone/iPad
    elif addr_type == BLE_ADDR_RANDOM:
        dev_class = "mobile_device"  # rotating MAC = modern smartphone/tablet
    elif company_id in BLE_COMPANY_CLASSES:
        dev_class = f"BLE_{BLE_COMPANY_CLASSES[company_id]}"
    elif name:
        dev_class = "named_ble"
    else:
        dev_class = "BLE_IoT"        # fixed MAC, no company = likely sensor/beacon

    # Enrich vendor from our OUI table (BLE public MACs share the same OUI space)
    vendor = lookup_vendor(mac) or company or "Unknown"

    return DeviceRecord(
        device_key   = raw.get("device_key") or f"ble:{mac}",
        sensor_type  = "ble",
        timestamp    = timestamp,
        rssi         = raw.get("rssi"),
        mac_address  = mac,
        vendor_oui   = vendor,
        device_class = dev_class,
        raw_data     = {
            "source_node": node.node_id,
            "addr_type":   addr_type,
            "company_id":  company_id,
            "company":     company,
            "name":        name,
            "service_uuid": raw.get("service_uuid"),
            "tx_power":    raw.get("tx_power"),
        },
    )


# ── WiFi probe record normaliser ──────────────────────────────────────────────

def normalise_wifi_probe(raw: dict, node: NodeState) -> DeviceRecord | None:
    """
    Convert a raw WiFi probe/beacon/probe-response record from an ESP32
    into a canonical DeviceRecord.
    """
    mac = raw.get("mac_address", "").upper().strip()
    if not mac:
        return None

    ts_offset = raw.get("ts_offset", 0)
    timestamp = node.estimate_wall_time(ts_offset) if ts_offset else now_ms()

    frame_type   = raw.get("frame_type", "probe_req")
    probed_ssid  = raw.get("probed_ssid")
    ssid         = raw.get("ssid")
    vendor       = raw.get("vendor_oui") or lookup_vendor(mac) or "Unknown"

    if frame_type == "probe_req":
        dev_class = "client"    # device actively probing for networks
        ssid_field = probed_ssid
    elif frame_type == "beacon":
        dev_class = "AP"
        ssid_field = ssid
    else:
        dev_class = "AP"
        ssid_field = ssid

    return DeviceRecord(
        device_key   = raw.get("device_key") or f"wifi:{mac}",
        sensor_type  = "wifi",
        timestamp    = timestamp,
        rssi         = raw.get("rssi"),
        mac_address  = mac,
        vendor_oui   = vendor,
        device_class = dev_class,
        ssid         = ssid_field,
        channel      = raw.get("channel"),
        raw_data     = {
            "source_node": node.node_id,
            "frame_type":  frame_type,
            "bssid":       raw.get("bssid"),
            "probed_ssid": probed_ssid,
        },
    )


# ── Bridge ────────────────────────────────────────────────────────────────────

class ESP32Bridge:

    def __init__(self, cfg: EatanConfig):
        self.cfg     = cfg
        self.bus     = EatanBus(cfg, MODULE_NAME)
        self.db      = EatanDB(cfg.db_path)
        self.topics  = Topics(cfg.prefix)
        self.log     = configure_logging(MODULE_NAME, cfg.log_level)
        self._nodes: dict[str, NodeState] = {}
        self._running = False

    async def setup(self) -> None:
        await self.db.connect()
        await self.bus.connect()

        # Subscribe to ESP32 raw feeds
        self.bus.subscribe(self.topics.raw("ble"),        self._on_ble)
        self.bus.subscribe(self.topics.raw("wifi_probe"), self._on_wifi_probe)
        self.bus.subscribe(self.topics.system("heartbeat"), self._on_heartbeat)

        self.log.info("esp32_bridge_ready",
                       hint="Waiting for ESP32 nodes to connect...")
        await self.db.write_system_event("esp32_bridge_start", "ESP32 bridge started")

    async def run(self) -> None:
        self._running = True
        await asyncio.gather(
            self.bus.heartbeat_loop(30),
            self._node_watchdog(),
            self._status_publisher(),
        )

    # ── Message handlers ──────────────────────────────────────────────────────

    async def _on_ble(self, topic: str, payload: dict) -> None:
        node_id = payload.get("node_id", "unknown")
        node    = self._get_or_create_node(node_id)
        rec     = normalise_ble(payload, node)
        if rec is None:
            return
        rec.node_id = f"{self.cfg.node_id}/{node_id}"
        node.total_records += 1

        # Re-publish the normalised record — analysis engine picks it up
        await self.bus.publish_raw("ble", rec)

        self.log.debug("ble_record_bridged",
                        node=node_id, mac=rec.mac_address,
                        class_=rec.device_class, rssi=rec.rssi)

    async def _on_wifi_probe(self, topic: str, payload: dict) -> None:
        node_id = payload.get("node_id", "unknown")
        node    = self._get_or_create_node(node_id)
        rec     = normalise_wifi_probe(payload, node)
        if rec is None:
            return
        rec.node_id = f"{self.cfg.node_id}/{node_id}"
        node.total_records += 1

        # Re-publish as a wifi record — same pipeline as Kismet data
        await self.bus.publish_raw("wifi", rec)

        self.log.debug("wifi_probe_bridged",
                        node=node_id, mac=rec.mac_address,
                        frame=payload.get("frame_type"), ssid=rec.ssid)

    async def _on_heartbeat(self, topic: str, payload: dict) -> None:
        node_id = payload.get("node_id")
        if not node_id:
            return

        node      = self._get_or_create_node(node_id)
        was_online = node.online
        node.update_from_heartbeat(payload)

        if not was_online:
            # Node came back online
            self.log.info("esp32_node_online", node=node_id,
                           ip=node.ip, rssi=node.wifi_rssi)
            alert = AlertRecord(
                severity   = "INFO",
                alert_type = "esp32_node_online",
                message    = f"ESP32 node back online: {node_id} ({node.ip})",
                raw_data   = node.to_dict(),
            )
            await self.bus.publish_alert(alert)
        else:
            self.log.debug("esp32_heartbeat",
                            node=node_id, rssi=node.wifi_rssi,
                            ble=node.ble_scanned, probes=node.probes_seen,
                            heap=node.free_heap)

    # ── Background tasks ──────────────────────────────────────────────────────

    async def _node_watchdog(self) -> None:
        """Alert when an ESP32 node stops sending heartbeats."""
        while self._running:
            await asyncio.sleep(NODE_CHECK_INTERVAL)
            for node in self._nodes.values():
                if node.online and node.is_timed_out():
                    node.online = False
                    self.log.warning("esp32_node_offline",
                                      node=node.node_id,
                                      last_seen_sec=int(
                                          (now_ms() - node.last_heartbeat) / 1000
                                      ))
                    alert = AlertRecord(
                        severity   = "WARN",
                        alert_type = "esp32_node_offline",
                        message    = f"ESP32 node offline: {node.node_id}",
                        raw_data   = node.to_dict(),
                    )
                    await self.bus.publish_alert(alert)
                    await self.db.write_alert(alert)

    async def _status_publisher(self) -> None:
        """Publish combined node status every 30 seconds."""
        while self._running:
            await asyncio.sleep(30)
            if self._nodes:
                await self.bus.publish_event("esp32_nodes", {
                    "timestamp":  now_ms(),
                    "node_count": len(self._nodes),
                    "online":     sum(1 for n in self._nodes.values() if n.online),
                    "nodes":      {nid: n.to_dict()
                                   for nid, n in self._nodes.items()},
                })

    # ── Remote commands ───────────────────────────────────────────────────────

    async def cmd_reboot_node(self, node_id: str) -> None:
        """Send a reboot command to a specific ESP32 node."""
        topic = self.topics.system(f"cmd/{node_id}")
        payload = json.dumps({"cmd": "reboot"})
        self.bus._publish(topic, payload)
        self.log.info("sent_reboot_cmd", node=node_id)

    async def cmd_status_node(self, node_id: str) -> None:
        """Request a status dump from a specific ESP32 node."""
        topic = self.topics.system(f"cmd/{node_id}")
        payload = json.dumps({"cmd": "status"})
        self.bus._publish(topic, payload)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _get_or_create_node(self, node_id: str) -> NodeState:
        if node_id not in self._nodes:
            self._nodes[node_id] = NodeState(node_id=node_id)
            self.log.info("esp32_node_registered", node=node_id)
        return self._nodes[node_id]

    def get_node_status(self) -> list[dict]:
        return [n.to_dict() for n in self._nodes.values()]

    async def teardown(self) -> None:
        self._running = False
        await self.db.write_system_event("esp32_bridge_stop", "ESP32 bridge stopped",
                                          {"node_count": len(self._nodes)})
        await self.db.close()
        self.bus.disconnect()


# ── Entry point ───────────────────────────────────────────────────────────────

async def main() -> None:
    cfg    = EatanConfig()
    bridge = ESP32Bridge(cfg)

    try:
        await bridge.setup()
        await bridge.run()
    except KeyboardInterrupt:
        pass
    finally:
        await bridge.teardown()


if __name__ == "__main__":
    asyncio.run(main())
