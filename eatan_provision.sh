#!/usr/bin/env bash
# =============================================================================
# EATAN — Environmental Awareness Tactical Array Node
# Mk1 Base Provisioning Script
# Target: Raspberry Pi 5, RPi OS (Bookworm, 64-bit)
# Run as: sudo bash eatan_provision.sh
# =============================================================================

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log()  { echo -e "${CYAN}[EATAN]${NC} $*"; }
ok()   { echo -e "${GREEN}[  OK  ]${NC} $*"; }
warn() { echo -e "${YELLOW}[ WARN ]${NC} $*"; }
die()  { echo -e "${RED}[ FAIL ]${NC} $*"; exit 1; }
hr()   { echo -e "${BOLD}────────────────────────────────────────────────────${NC}"; }

# ── Root check ────────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && die "Run as root: sudo bash $0"

REAL_USER="${SUDO_USER:-pi}"
REAL_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)
EATAN_ROOT="$REAL_HOME/eatan"

hr
echo -e "${BOLD}  EATAN Mk1 — Base Provisioning${NC}"
echo    "  Target user : $REAL_USER"
echo    "  EATAN root  : $EATAN_ROOT"
hr

# =============================================================================
# 1. SYSTEM UPDATE
# =============================================================================
log "Updating package lists..."
apt-get update -qq

log "Upgrading installed packages..."
apt-get upgrade -y -qq
ok "System up to date"

# =============================================================================
# 2. CORE DEPENDENCIES
# =============================================================================
log "Installing core dependencies..."

PKGS=(
    # Build essentials
    build-essential cmake git curl wget unzip

    # Python
    python3 python3-pip python3-venv python3-dev

    # RTL-SDR (NESDR Smart / RTL2832U + R860)
    rtl-sdr librtlsdr-dev

    # SDR tools
    sox libsox-fmt-all

    # WiFi / network scanning
    aircrack-ng wireless-tools iw net-tools

    # Bluetooth scanning
    bluetooth bluez bluez-tools python3-bluez libbluetooth-dev

    # MQTT broker
    mosquitto mosquitto-clients

    # Database
    sqlite3 libsqlite3-dev

    # System utilities
    usbutils pciutils lsof htop tmux jq

    # Watchdog & process supervision
    supervisor

    # Network & security
    ufw nmap

    # Kismet dependencies
    libpcap-dev libcap-dev libnl-3-dev libnl-genl-3-dev

    # GPS (optional, future)
    gpsd gpsd-clients

    # Time sync (critical for signal timestamps)
    chrony

    # Avahi for local .local resolution without internet
    avahi-daemon
)

apt-get install -y -qq "${PKGS[@]}" 2>/dev/null || {
    warn "Some packages failed; retrying individually..."
    for pkg in "${PKGS[@]}"; do
        apt-get install -y -qq "$pkg" 2>/dev/null || warn "Skipped: $pkg"
    done
}
ok "Core packages installed"

# =============================================================================
# 3. RTL-SDR: BLACKLIST DVB KERNEL MODULES
#    (prevents the kernel from grabbing the dongle before rtl-sdr can)
# =============================================================================
log "Blacklisting DVB kernel modules for RTL-SDR..."

BLACKLIST_FILE="/etc/modprobe.d/eatan-rtlsdr.conf"
cat > "$BLACKLIST_FILE" << 'EOF'
# EATAN: Prevent kernel DVB drivers from claiming the RTL-SDR dongle
blacklist dvb_usb_rtl28xxu
blacklist rtl2832
blacklist rtl2830
blacklist dvb_usb_v2
blacklist dvb_core
EOF

ok "DVB modules blacklisted → $BLACKLIST_FILE"
warn "A reboot is required for this to take full effect"

# =============================================================================
# 4. UDEV RULES — RTL-SDR & WIFI ADAPTER
# =============================================================================
log "Installing udev rules..."

cat > /etc/udev/rules.d/99-eatan.rules << 'EOF'
# EATAN udev rules

# RTL-SDR: RTL2832U (Nooelec NESDR Smart / most RTL-SDR dongles)
SUBSYSTEM=="usb", ATTRS{idVendor}=="0bda", ATTRS{idProduct}=="2838", GROUP="plugdev", MODE="0664", SYMLINK+="eatan_sdr"

# RTL-SDR: RTL2832U alternate product ID
SUBSYSTEM=="usb", ATTRS{idVendor}=="0bda", ATTRS{idProduct}=="2832", GROUP="plugdev", MODE="0664", SYMLINK+="eatan_sdr"

# Alfa AWUS036ACH (RTL8812AU) — common 2021 dual-antenna model
SUBSYSTEM=="usb", ATTRS{idVendor}=="0bda", ATTRS{idProduct}=="8812", GROUP="plugdev", MODE="0664", SYMLINK+="eatan_wifi"

# Alfa AWUS036AXML (MT7921AU)
SUBSYSTEM=="usb", ATTRS{idVendor}=="0e8d", ATTRS{idProduct}=="7961", GROUP="plugdev", MODE="0664", SYMLINK+="eatan_wifi"

# Alfa AWUS036ACM (MT7612U)
SUBSYSTEM=="usb", ATTRS{idVendor}=="0e8d", ATTRS{idProduct}=="7612", GROUP="plugdev", MODE="0664", SYMLINK+="eatan_wifi"
EOF

udevadm control --reload-rules
udevadm trigger
ok "udev rules installed"

# Add real user to plugdev and dialout
usermod -aG plugdev,dialout "$REAL_USER"
ok "User '$REAL_USER' added to plugdev, dialout"

# =============================================================================
# 5. KISMET — build from source (latest stable is more reliable than apt)
# =============================================================================
log "Checking for Kismet..."

if command -v kismet &>/dev/null; then
    ok "Kismet already installed: $(kismet --version 2>/dev/null | head -1)"
else
    log "Installing Kismet from Kismet repository..."
    # Use the official Kismet apt repo for Bookworm
    wget -O /tmp/kismet.gpg.key "https://www.kismetwireless.net/repos/kismet-release.gpg.key" 2>/dev/null || {
        warn "Could not fetch Kismet GPG key — network may be offline. Skipping Kismet apt repo."
        warn "Install Kismet manually later: https://www.kismetwireless.net/packages/"
    }

    if [[ -f /tmp/kismet.gpg.key ]]; then
        gpg --dearmor < /tmp/kismet.gpg.key > /usr/share/keyrings/kismet-archive-keyring.gpg
        echo "deb [signed-by=/usr/share/keyrings/kismet-archive-keyring.gpg] https://www.kismetwireless.net/repos/apt/release/bookworm bookworm main" \
            > /etc/apt/sources.list.d/kismet.list
        apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y kismet 2>/dev/null && ok "Kismet installed" \
            || warn "Kismet install failed — run 'sudo apt install kismet' manually after provisioning"
    fi
fi

# Add user to kismet group if it exists
if getent group kismet &>/dev/null; then
    usermod -aG kismet "$REAL_USER"
    ok "User '$REAL_USER' added to kismet group"
fi

# =============================================================================
# 6. rtl_433 — for IoT/sensor signal decoding
# =============================================================================
log "Installing rtl_433..."
if command -v rtl_433 &>/dev/null; then
    ok "rtl_433 already installed"
else
    apt-get install -y -qq rtl-433 2>/dev/null || {
        warn "rtl-433 not in apt — building from source..."
        if [[ ! -d /tmp/rtl_433_build ]]; then
            git clone --depth 1 https://github.com/merbanan/rtl_433.git /tmp/rtl_433_build 2>/dev/null || \
                warn "Could not clone rtl_433 (offline?). Install manually later."
        fi
        if [[ -d /tmp/rtl_433_build ]]; then
            cd /tmp/rtl_433_build
            mkdir -p build && cd build
            cmake .. -DCMAKE_BUILD_TYPE=Release -DENABLE_RTLSDR=ON -DENABLE_SOAPYSDR=OFF 2>/dev/null
            make -j4 2>/dev/null && make install 2>/dev/null && ok "rtl_433 built and installed" \
                || warn "rtl_433 build failed — install manually later"
        fi
    }
fi

# =============================================================================
# 7. DIRECTORY STRUCTURE
# =============================================================================
log "Creating EATAN directory tree..."

DIRS=(
    "$EATAN_ROOT"
    "$EATAN_ROOT/bin"              # EATAN executables / launchers
    "$EATAN_ROOT/config"           # All configuration files
    "$EATAN_ROOT/data"             # Runtime data (SQLite DB, logs)
    "$EATAN_ROOT/data/logs"        # Per-module logs
    "$EATAN_ROOT/data/captures"    # Raw packet captures / IQ recordings
    "$EATAN_ROOT/data/exports"     # Operator-triggered exports
    "$EATAN_ROOT/modules"          # Sensor + analysis modules
    "$EATAN_ROOT/modules/wifi"
    "$EATAN_ROOT/modules/sdr"
    "$EATAN_ROOT/modules/bluetooth"
    "$EATAN_ROOT/modules/analysis"
    "$EATAN_ROOT/api"              # FastAPI backend
    "$EATAN_ROOT/api/routers"
    "$EATAN_ROOT/ui"               # Frontend (built assets go here)
    "$EATAN_ROOT/plugins"          # Third-party / future capability plugins
    "$EATAN_ROOT/keys"             # Encryption keys (mode 700)
    "$EATAN_ROOT/tmp"              # Ephemeral scratch space
)

for d in "${DIRS[@]}"; do
    mkdir -p "$d"
done

chmod 700 "$EATAN_ROOT/keys"
chown -R "$REAL_USER:$REAL_USER" "$EATAN_ROOT"
ok "Directory tree created under $EATAN_ROOT"

# =============================================================================
# 8. PYTHON VIRTUAL ENVIRONMENT
# =============================================================================
log "Creating Python virtual environment..."

sudo -u "$REAL_USER" python3 -m venv "$EATAN_ROOT/.venv"

VENV_PIP="$EATAN_ROOT/.venv/bin/pip"

sudo -u "$REAL_USER" "$VENV_PIP" install --quiet --upgrade pip

PYTHON_PKGS=(
    # MQTT
    paho-mqtt

    # Database
    aiosqlite

    # SDR
    pyrtlsdr

    # API framework
    fastapi
    uvicorn[standard]
    websockets

    # Data processing
    numpy
    scipy

    # Scheduling / async
    apscheduler

    # Config
    python-dotenv
    pydantic
    pydantic-settings

    # Serialisation
    orjson

    # Logging
    structlog

    # Security
    cryptography
    python-jose[cryptography]
    passlib[bcrypt]
)

log "Installing Python packages into venv (this may take a minute)..."
sudo -u "$REAL_USER" "$VENV_PIP" install --quiet "${PYTHON_PKGS[@]}" && ok "Python packages installed" \
    || warn "Some Python packages failed — check pip output manually"

# =============================================================================
# 9. MOSQUITTO CONFIGURATION (EATAN internal broker)
# =============================================================================
log "Configuring Mosquitto MQTT broker..."

MQTT_CONF="/etc/mosquitto/conf.d/eatan.conf"
cat > "$MQTT_CONF" << 'EOF'
# EATAN MQTT broker config
# Listens on localhost only — not exposed externally

listener 1883 127.0.0.1
allow_anonymous true

# Persistence
persistence true
persistence_location /var/lib/mosquitto/

# Logging
log_dest file /var/log/mosquitto/mosquitto.log
log_type error
log_type warning
log_type information

# Keep-alive
max_keepalive 60
EOF

systemctl enable mosquitto --quiet
systemctl restart mosquitto
ok "Mosquitto configured and running on localhost:1883"

# =============================================================================
# 10. EATAN CONFIGURATION FILE
# =============================================================================
log "Writing EATAN configuration..."

cat > "$EATAN_ROOT/config/eatan.env" << EOF
# EATAN Runtime Configuration
# Edit this file to match your hardware

# ── Identity ─────────────────────────────
EATAN_NODE_ID=node-alpha
EATAN_CODENAME=EATAN-MK1

# ── Paths ────────────────────────────────
EATAN_ROOT=$EATAN_ROOT
EATAN_DB=$EATAN_ROOT/data/eatan.db
EATAN_LOG_DIR=$EATAN_ROOT/data/logs
EATAN_CAPTURES_DIR=$EATAN_ROOT/data/captures

# ── MQTT ─────────────────────────────────
MQTT_HOST=127.0.0.1
MQTT_PORT=1883
MQTT_TOPIC_PREFIX=eatan

# ── SDR ──────────────────────────────────
SDR_DEVICE_INDEX=0
SDR_GAIN=auto
SDR_SAMPLE_RATE=2400000
SDR_PPM_CORRECTION=0

# ── WiFi ─────────────────────────────────
# Set to your monitor-mode interface name (confirmed during hardware check)
WIFI_INTERFACE=wlan1
WIFI_MONITOR_INTERFACE=wlan1mon

# ── Bluetooth ────────────────────────────
BT_INTERFACE=hci0

# ── Collection ───────────────────────────
# Calibration window in seconds before alerting on new devices
BASELINE_DURATION_SEC=900

# Alert on new device after baseline
ALERT_NEW_DEVICE=true

# ── API ──────────────────────────────────
API_HOST=0.0.0.0
API_PORT=8888
API_SECRET_KEY=CHANGE_ME_BEFORE_DEPLOYMENT

# ── Logging ──────────────────────────────
LOG_LEVEL=INFO
EOF

chown "$REAL_USER:$REAL_USER" "$EATAN_ROOT/config/eatan.env"
chmod 600 "$EATAN_ROOT/config/eatan.env"
ok "Configuration written to $EATAN_ROOT/config/eatan.env"

# =============================================================================
# 11. SQLITE DATABASE INITIALISATION
# =============================================================================
log "Initialising EATAN database schema..."

sudo -u "$REAL_USER" sqlite3 "$EATAN_ROOT/data/eatan.db" << 'SQL'
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

-- ── Observed devices ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS devices (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    device_key      TEXT NOT NULL UNIQUE,   -- canonical fingerprint / MAC / UUID
    sensor_type     TEXT NOT NULL,          -- wifi | ble | sdr_iot | adsb | etc
    mac_address     TEXT,
    vendor_oui      TEXT,
    device_class    TEXT,                   -- AP | client | IoT | unknown | ...
    first_seen      INTEGER NOT NULL,       -- Unix timestamp (ms)
    last_seen       INTEGER NOT NULL,
    times_seen      INTEGER DEFAULT 1,
    is_baseline     INTEGER DEFAULT 0,      -- 1 = seen during calibration window
    is_known_hostile INTEGER DEFAULT 0,
    notes           TEXT
);

-- ── Raw signal observations ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS observations (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    device_key  TEXT NOT NULL,
    sensor_type TEXT NOT NULL,
    timestamp   INTEGER NOT NULL,           -- Unix timestamp (ms)
    rssi        REAL,                       -- signal strength dBm
    channel     INTEGER,
    frequency   REAL,                       -- Hz
    ssid        TEXT,                       -- WiFi SSID if applicable
    raw_data    TEXT,                       -- JSON blob of full sensor record
    FOREIGN KEY (device_key) REFERENCES devices(device_key)
);

-- ── Alert log ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   INTEGER NOT NULL,
    severity    TEXT NOT NULL,              -- INFO | WARN | CRIT
    alert_type  TEXT NOT NULL,             -- new_device | known_hostile | anomaly | etc
    device_key  TEXT,
    message     TEXT NOT NULL,
    acknowledged INTEGER DEFAULT 0,
    ack_time    INTEGER,
    raw_data    TEXT                        -- JSON context
);

-- ── System events ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS system_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   INTEGER NOT NULL,
    event_type  TEXT NOT NULL,             -- startup | baseline_start | baseline_end | etc
    message     TEXT,
    data        TEXT
);

-- ── Threat signatures (local database) ───────────────────────────────────────
CREATE TABLE IF NOT EXISTS threat_signatures (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    sig_type    TEXT NOT NULL,             -- mac_prefix | ssid_pattern | rf_pattern
    pattern     TEXT NOT NULL,
    description TEXT,
    severity    TEXT NOT NULL DEFAULT 'WARN',
    source      TEXT,
    added_at    INTEGER NOT NULL
);

-- ── Indexes ───────────────────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_obs_device    ON observations(device_key);
CREATE INDEX IF NOT EXISTS idx_obs_timestamp ON observations(timestamp);
CREATE INDEX IF NOT EXISTS idx_obs_sensor    ON observations(sensor_type);
CREATE INDEX IF NOT EXISTS idx_dev_sensor    ON devices(sensor_type);
CREATE INDEX IF NOT EXISTS idx_dev_seen      ON devices(last_seen);
CREATE INDEX IF NOT EXISTS idx_alert_ts      ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alert_ack     ON alerts(acknowledged);
SQL

chown "$REAL_USER:$REAL_USER" "$EATAN_ROOT/data/eatan.db"
ok "Database initialised: $EATAN_ROOT/data/eatan.db"

# =============================================================================
# 12. MQTT TOPIC HELPER — documents the topic schema
# =============================================================================
cat > "$EATAN_ROOT/config/mqtt_topics.md" << 'EOF'
# EATAN MQTT Topic Schema

## Sensor publishers  →  eatan/raw/{sensor}
| Topic                    | Publisher         | Payload |
|--------------------------|-------------------|---------|
| eatan/raw/wifi           | wifi_scanner      | JSON device record from Kismet/airodump |
| eatan/raw/ble            | bt_scanner        | JSON BLE advertisement record |
| eatan/raw/sdr_iot        | sdr_iot_scanner   | JSON rtl_433 decoded record |
| eatan/raw/adsb           | sdr_adsb_scanner  | JSON ADS-B aircraft record |
| eatan/raw/rf_spectrum    | sdr_wideband      | JSON FFT snapshot |

## Analysis publishers  →  eatan/events/{type}
| Topic                    | Publisher         | Payload |
|--------------------------|-------------------|---------|
| eatan/events/device_seen | analysis_engine   | {device_key, sensor_type, rssi, ...} |
| eatan/events/new_device  | analysis_engine   | {device_key, first_seen, ...} |
| eatan/events/device_lost | analysis_engine   | {device_key, last_seen, ...} |

## Alert publishers  →  eatan/alerts/{severity}
| Topic                    | Publisher         | Payload |
|--------------------------|-------------------|---------|
| eatan/alerts/info        | analysis_engine   | {alert_type, message, device_key} |
| eatan/alerts/warn        | analysis_engine   | {alert_type, message, device_key} |
| eatan/alerts/crit        | analysis_engine   | {alert_type, message, device_key} |

## System  →  eatan/system/{type}
| Topic                    | Publisher         | Payload |
|--------------------------|-------------------|---------|
| eatan/system/heartbeat   | any module        | {module, ts, status} |
| eatan/system/status      | orchestrator      | {phase, uptime, device_count} |
EOF

chown "$REAL_USER:$REAL_USER" "$EATAN_ROOT/config/mqtt_topics.md"

# =============================================================================
# 13. HARDWARE VERIFICATION SCRIPT
# =============================================================================
log "Writing hardware verification script..."

cat > "$EATAN_ROOT/bin/check_hardware.sh" << 'HWCHECK'
#!/usr/bin/env bash
# EATAN hardware verification — run this after provisioning to confirm
# all hardware is recognised correctly.

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

pass() { echo -e "  ${GREEN}✓${NC}  $*"; }
fail() { echo -e "  ${RED}✗${NC}  $*"; }
warn() { echo -e "  ${YELLOW}!${NC}  $*"; }
info() { echo -e "  ${CYAN}→${NC}  $*"; }

echo -e "\n${BOLD}EATAN Hardware Verification${NC}"
echo    "─────────────────────────────────────────────"

# ── RTL-SDR ──────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}[1] RTL-SDR Dongle (NESDR Smart)${NC}"

if lsusb | grep -qiE "0bda:(2838|2832|2831)"; then
    LSUSB_LINE=$(lsusb | grep -iE "0bda:(2838|2832|2831)" | head -1)
    pass "USB detected: $LSUSB_LINE"
else
    fail "RTL2832U USB device NOT found — check connection"
fi

if command -v rtl_test &>/dev/null; then
    pass "rtl_test binary found"
    info "Testing SDR (5 second sample count test)..."
    RTL_OUT=$(timeout 8 rtl_test -t 2>&1 || true)
    if echo "$RTL_OUT" | grep -q "No errors"; then
        pass "SDR self-test PASSED — no sample drops"
    elif echo "$RTL_OUT" | grep -q "Found"; then
        warn "SDR found but sample test incomplete — may still work"
        echo "$RTL_OUT" | grep -E "(Found|Tuner|Sampling|lost)" | sed 's/^/       /'
    else
        fail "SDR test failed or device not opened"
        echo "$RTL_OUT" | tail -5 | sed 's/^/       /'
    fi
else
    fail "rtl_test not found — rtl-sdr package may not be installed"
fi

# ── WiFi Adapter ─────────────────────────────────────────────────────────────
echo -e "\n${BOLD}[2] WiFi Adapter (Alfa)${NC}"

# Show all USB WiFi devices
USB_WIFI=$(lsusb | grep -iE "(0bda:8812|0bda:8813|0e8d:7961|0e8d:7612|148f:5572|0846:9052)" || true)
if [[ -n "$USB_WIFI" ]]; then
    pass "USB WiFi adapter detected:"
    echo "$USB_WIFI" | sed 's/^/       /'
    # Identify chipset
    if echo "$USB_WIFI" | grep -q "8812\|8813"; then
        warn "Chipset: RTL8812AU — requires out-of-tree driver (8812au)"
        info "If monitor mode fails, install driver with:"
        info "  sudo apt install dkms"
        info "  git clone https://github.com/aircrack-ng/rtl8812au.git"
        info "  cd rtl8812au && sudo make dkms_install"
    elif echo "$USB_WIFI" | grep -q "7961"; then
        info "Chipset: MT7921AU — in-tree driver, should work out of box"
    elif echo "$USB_WIFI" | grep -q "7612"; then
        info "Chipset: MT7612U — in-tree driver (mt76), should work"
    fi
else
    warn "No recognised Alfa adapter found via USB ID — trying interface scan..."
fi

# Show all WiFi interfaces
echo ""
info "Available wireless interfaces:"
iw dev 2>/dev/null | grep -E "(Interface|type|addr)" | sed 's/^/       /' || warn "iw returned no results"

# Check for monitor mode capability
for IFACE in $(iw dev 2>/dev/null | awk '/Interface/{print $2}'); do
    MODES=$(iw phy phy$(iw dev "$IFACE" info 2>/dev/null | awk '/wiphy/{print $2}') info 2>/dev/null \
        | grep -A20 "Supported interface modes" | grep -E "monitor" || true)
    if [[ -n "$MODES" ]]; then
        pass "$IFACE supports monitor mode"
    else
        warn "$IFACE: monitor mode NOT listed (may still work)"
    fi
done

# ── Bluetooth ─────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}[3] Bluetooth${NC}"
if hciconfig 2>/dev/null | grep -q "hci"; then
    pass "Bluetooth interface found:"
    hciconfig 2>/dev/null | grep -E "(hci|BD Address|UP|DOWN)" | sed 's/^/       /'
else
    warn "No Bluetooth interface found (built-in RPi BT may need enabling)"
fi

# ── MQTT Broker ───────────────────────────────────────────────────────────────
echo -e "\n${BOLD}[4] MQTT Broker (Mosquitto)${NC}"
if systemctl is-active --quiet mosquitto; then
    pass "Mosquitto is running"
    # Quick publish/subscribe test
    MQTT_TEST=$(mosquitto_pub -h 127.0.0.1 -t "eatan/system/test" -m '{"test":true}' 2>&1)
    if [[ -z "$MQTT_TEST" ]]; then
        pass "MQTT publish test successful"
    else
        warn "MQTT publish returned: $MQTT_TEST"
    fi
else
    fail "Mosquitto is NOT running — try: sudo systemctl start mosquitto"
fi

# ── Python venv ───────────────────────────────────────────────────────────────
echo -e "\n${BOLD}[5] Python Environment${NC}"
VENV_PATH="$(dirname "$(dirname "$0")")/.venv"
if [[ -f "$VENV_PATH/bin/python" ]]; then
    PY_VER=$("$VENV_PATH/bin/python" --version 2>&1)
    pass "Virtual environment found: $PY_VER"

    REQUIRED_PKGS=(paho fastapi uvicorn aiosqlite rtlsdr structlog cryptography)
    for pkg in "${REQUIRED_PKGS[@]}"; do
        if "$VENV_PATH/bin/python" -c "import ${pkg//-/_}" 2>/dev/null; then
            pass "  python: $pkg"
        else
            warn "  python: $pkg NOT importable"
        fi
    done
else
    fail "Python venv not found at $VENV_PATH"
fi

# ── Kismet ────────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}[6] Kismet${NC}"
if command -v kismet &>/dev/null; then
    KISMET_VER=$(kismet --version 2>/dev/null | head -1 || echo "version unknown")
    pass "Kismet installed: $KISMET_VER"
else
    warn "Kismet not found — install it to enable full WiFi scanning"
    info "  sudo apt install kismet"
fi

# ── rtl_433 ───────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}[7] rtl_433${NC}"
if command -v rtl_433 &>/dev/null; then
    RTL433_VER=$(rtl_433 -V 2>&1 | head -1 || echo "version unknown")
    pass "rtl_433 installed: $RTL433_VER"
else
    warn "rtl_433 not found — IoT signal decoding unavailable"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo -e "\n─────────────────────────────────────────────"
echo -e "${BOLD}Next step:${NC} Run the MQTT bus test:"
echo    "  source ~/eatan/.venv/bin/activate"
echo    "  python ~/eatan/bin/mqtt_test.py"
echo ""
HWCHECK

chmod +x "$EATAN_ROOT/bin/check_hardware.sh"
chown "$REAL_USER:$REAL_USER" "$EATAN_ROOT/bin/check_hardware.sh"

# =============================================================================
# 14. MQTT BUS TEST SCRIPT (Python)
# =============================================================================
log "Writing MQTT bus test script..."

cat > "$EATAN_ROOT/bin/mqtt_test.py" << 'PYEOF'
#!/usr/bin/env python3
"""
EATAN — MQTT bus connectivity test.
Publishes a test message on each topic tier and confirms round-trip receipt.
Run from the eatan venv: python ~/eatan/bin/mqtt_test.py
"""
import json
import time
import sys
import threading
import paho.mqtt.client as mqtt

BROKER = "127.0.0.1"
PORT   = 1883
PREFIX = "eatan"

received: dict[str, bool] = {}
lock = threading.Lock()

TEST_TOPICS = [
    f"{PREFIX}/raw/wifi",
    f"{PREFIX}/raw/ble",
    f"{PREFIX}/raw/sdr_iot",
    f"{PREFIX}/events/device_seen",
    f"{PREFIX}/alerts/warn",
    f"{PREFIX}/system/heartbeat",
]

def on_connect(client, userdata, flags, rc, properties=None):
    if rc == 0:
        print(f"  ✓  Connected to Mosquitto on {BROKER}:{PORT}")
        for topic in TEST_TOPICS:
            client.subscribe(topic)
    else:
        print(f"  ✗  Connection failed, rc={rc}")
        sys.exit(1)

def on_message(client, userdata, msg):
    with lock:
        received[msg.topic] = True

def main():
    print("\nEATAN MQTT Bus Test")
    print("─" * 42)

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.on_connect = on_connect
    client.on_message = on_message

    try:
        client.connect(BROKER, PORT, keepalive=10)
    except ConnectionRefusedError:
        print("  ✗  Cannot connect — is Mosquitto running?")
        print("     sudo systemctl start mosquitto")
        sys.exit(1)

    client.loop_start()
    time.sleep(0.5)  # let subscriptions settle

    print(f"\n  Publishing test messages on {len(TEST_TOPICS)} topics...\n")

    for topic in TEST_TOPICS:
        payload = json.dumps({
            "test": True,
            "topic": topic,
            "ts": int(time.time() * 1000),
            "node": "eatan-provision-test",
        })
        client.publish(topic, payload, qos=0)
        time.sleep(0.1)

    time.sleep(1.0)  # allow messages to round-trip

    client.loop_stop()
    client.disconnect()

    print("  Results:")
    all_ok = True
    for topic in TEST_TOPICS:
        ok = received.get(topic, False)
        status = "\033[0;32m✓\033[0m" if ok else "\033[0;31m✗\033[0m"
        print(f"    {status}  {topic}")
        if not ok:
            all_ok = False

    print()
    if all_ok:
        print("  \033[0;32mAll topics operational — MQTT bus is ready.\033[0m")
    else:
        print("  \033[1;33mSome topics failed — check Mosquitto logs:\033[0m")
        print("  sudo journalctl -u mosquitto -n 20")

    print()
    return 0 if all_ok else 1

if __name__ == "__main__":
    sys.exit(main())
PYEOF

chmod +x "$EATAN_ROOT/bin/mqtt_test.py"
chown "$REAL_USER:$REAL_USER" "$EATAN_ROOT/bin/mqtt_test.py"

# =============================================================================
# 15. FIREWALL — basic rules
# =============================================================================
log "Configuring firewall (ufw)..."
ufw --force reset > /dev/null 2>&1
ufw default deny incoming > /dev/null 2>&1
ufw default allow outgoing > /dev/null 2>&1

# Allow SSH (don't lock yourself out)
ufw allow ssh > /dev/null 2>&1

# EATAN API — only on local interfaces, not internet
# (will tighten further once we know which interface the operator AP uses)
ufw allow from 192.168.0.0/16 to any port 8888 > /dev/null 2>&1
ufw allow from 10.0.0.0/8    to any port 8888 > /dev/null 2>&1

ufw --force enable > /dev/null 2>&1
ok "Firewall configured"

# =============================================================================
# 16. CHRONY — time sync (critical for accurate signal timestamps)
# =============================================================================
log "Configuring Chrony time sync..."
systemctl enable chrony --quiet
systemctl restart chrony
ok "Chrony running"

# =============================================================================
# DONE
# =============================================================================
hr
echo -e "${GREEN}${BOLD}  EATAN provisioning complete!${NC}"
hr
echo ""
echo -e "  ${BOLD}Step 1:${NC} Reboot to apply DVB module blacklist"
echo    "          sudo reboot"
echo ""
echo -e "  ${BOLD}Step 2:${NC} After reboot, verify hardware"
echo    "          bash $EATAN_ROOT/bin/check_hardware.sh"
echo ""
echo -e "  ${BOLD}Step 3:${NC} Test the MQTT bus"
echo    "          source $EATAN_ROOT/.venv/bin/activate"
echo    "          python $EATAN_ROOT/bin/mqtt_test.py"
echo ""
echo -e "  ${BOLD}Config:${NC} Edit $EATAN_ROOT/config/eatan.env"
echo    "          (set your WiFi interface name after hardware check)"
echo ""
hr
