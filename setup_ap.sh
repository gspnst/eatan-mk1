#!/usr/bin/env bash
# =============================================================================
# EATAN — Internal Access Point Setup
# eatan/bin/setup_ap.sh
#
# Creates an isolated WPA2 WiFi AP on the RPi's built-in wlan0 interface.
# ESP32 nodes and operator devices connect to this AP.
# The AP is airgapped — no internet routing.
#
# Network:  192.168.4.0/24
# Gateway:  192.168.4.1 (RPi)
# DHCP:     192.168.4.100 – 192.168.4.200
#
# Run once: sudo bash ~/eatan/bin/setup_ap.sh
# The AP will then start automatically on boot via systemd.
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log()  { echo -e "${CYAN}[AP]${NC} $*"; }
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${YELLOW}[!!]${NC} $*"; }
die()  { echo -e "${RED}[FAIL]${NC} $*"; exit 1; }

[[ $EUID -ne 0 ]] && die "Run as root: sudo bash $0"

EATAN_ROOT="${EATAN_ROOT:-$(getent passwd "${SUDO_USER:-pi}" | cut -d: -f6)/eatan}"

# ── Configuration — edit these if needed ──────────────────────────────────────
AP_IFACE="wlan0"           # RPi built-in WiFi (NOT the Alfa adapter — that's for scanning)
AP_SSID="EATAN-NET"        # Must match EATAN_WIFI_SSID in ESP32 firmware
AP_PASSWORD="eatanmk1field" # Must match EATAN_WIFI_PASSWORD in ESP32 firmware
AP_CHANNEL="6"
AP_IP="192.168.4.1"
AP_SUBNET="192.168.4.0"
AP_NETMASK="255.255.255.0"
DHCP_START="192.168.4.100"
DHCP_END="192.168.4.200"
DHCP_LEASE="24h"

log "Setting up EATAN internal AP"
echo    "  SSID     : $AP_SSID"
echo    "  Channel  : $AP_CHANNEL"
echo    "  IP       : $AP_IP"
echo    "  Interface: $AP_IFACE"
echo ""

# ── Install dependencies ──────────────────────────────────────────────────────
log "Installing hostapd and dnsmasq..."
apt-get install -y -qq hostapd dnsmasq
ok "hostapd and dnsmasq installed"

# ── Stop services while we configure ─────────────────────────────────────────
systemctl stop hostapd  2>/dev/null || true
systemctl stop dnsmasq  2>/dev/null || true
rfkill unblock wlan     2>/dev/null || true

# ── Static IP for AP interface ────────────────────────────────────────────────
log "Configuring static IP on $AP_IFACE..."
DHCPCD_CONF="/etc/dhcpcd.conf"

# Remove any existing EATAN block
sed -i '/# EATAN AP/,/# END EATAN AP/d' "$DHCPCD_CONF" 2>/dev/null || true

cat >> "$DHCPCD_CONF" << EOF

# EATAN AP
interface $AP_IFACE
    static ip_address=$AP_IP/24
    nohook wpa_supplicant
# END EATAN AP
EOF
ok "Static IP configured: $AP_IP"

# ── dnsmasq (DHCP for the AP) ─────────────────────────────────────────────────
log "Configuring dnsmasq DHCP..."
DNSMASQ_EATAN="/etc/dnsmasq.d/eatan.conf"
cat > "$DNSMASQ_EATAN" << EOF
# EATAN internal DHCP
interface=$AP_IFACE
dhcp-range=$DHCP_START,$DHCP_END,$AP_NETMASK,$DHCP_LEASE
domain=eatan.local
address=/eatan.local/$AP_IP

# Assign fixed IPs to known ESP32 nodes (add more as needed)
# dhcp-host=AA:BB:CC:DD:EE:FF,esp32-alpha,192.168.4.50
EOF
ok "dnsmasq configured → $DNSMASQ_EATAN"

# ── hostapd ───────────────────────────────────────────────────────────────────
log "Configuring hostapd..."
cat > /etc/hostapd/hostapd.conf << EOF
# EATAN hostapd configuration
interface=$AP_IFACE
driver=nl80211
ssid=$AP_SSID
hw_mode=g
channel=$AP_CHANNEL
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=$AP_PASSWORD
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP

# Log to syslog
logger_syslog=-1
logger_syslog_level=2
EOF

# Point hostapd to the config
echo 'DAEMON_CONF="/etc/hostapd/hostapd.conf"' > /etc/default/hostapd
ok "hostapd configured"

# ── Mosquitto: allow connections from AP subnet ───────────────────────────────
log "Updating Mosquitto to accept AP subnet..."
MQTT_CONF="/etc/mosquitto/conf.d/eatan.conf"
# Replace the localhost-only listener with one that also accepts AP subnet
cat > "$MQTT_CONF" << EOF
# EATAN MQTT — accepts connections from localhost AND the internal AP
listener 1883
allow_anonymous true
bind_address 0.0.0.0

# Persistence
persistence true
persistence_location /var/lib/mosquitto/

log_dest file /var/log/mosquitto/mosquitto.log
log_type error
log_type warning
log_type information

max_keepalive 60
EOF
ok "Mosquitto updated to listen on all interfaces (AP-only via firewall)"

# ── Firewall: allow AP clients to reach MQTT ─────────────────────────────────
log "Updating firewall rules for AP subnet..."
ufw allow from "$AP_SUBNET/24" to any port 1883 > /dev/null 2>&1   # MQTT
ufw allow from "$AP_SUBNET/24" to any port 8888 > /dev/null 2>&1   # EATAN API
ufw allow from "$AP_SUBNET/24" to any port 53   > /dev/null 2>&1   # DNS (dnsmasq)
ufw allow from "$AP_SUBNET/24" to any port 67   > /dev/null 2>&1   # DHCP
ok "Firewall rules updated"

# ── Update eatan.env with AP details ─────────────────────────────────────────
ENV_FILE="$EATAN_ROOT/config/eatan.env"
if [[ -f "$ENV_FILE" ]]; then
    # Replace or append AP settings
    grep -q "^AP_IFACE=" "$ENV_FILE" && \
        sed -i "s|^AP_IFACE=.*|AP_IFACE=$AP_IFACE|" "$ENV_FILE" || \
        echo "AP_IFACE=$AP_IFACE" >> "$ENV_FILE"
    grep -q "^AP_IP=" "$ENV_FILE" && \
        sed -i "s|^AP_IP=.*|AP_IP=$AP_IP|" "$ENV_FILE" || \
        echo "AP_IP=$AP_IP" >> "$ENV_FILE"
    grep -q "^AP_SSID=" "$ENV_FILE" && \
        sed -i "s|^AP_SSID=.*|AP_SSID=$AP_SSID|" "$ENV_FILE" || \
        echo "AP_SSID=$AP_SSID" >> "$ENV_FILE"
    ok "eatan.env updated with AP settings"
fi

# ── Update MQTT_HOST in eatan.env for ESP32 bridge ───────────────────────────
# The ESP32 bridge and other modules should keep using 127.0.0.1 internally.
# ESP32 firmware connects to 192.168.4.1 (AP_IP) — that's set at compile time.

# ── Enable services ───────────────────────────────────────────────────────────
log "Enabling services..."
systemctl unmask hostapd 2>/dev/null || true
systemctl enable hostapd
systemctl enable dnsmasq
ok "hostapd and dnsmasq enabled for autostart"

# ── Apply now (requires dhcpcd restart) ───────────────────────────────────────
log "Bringing up AP (brief network interruption expected)..."
systemctl restart dhcpcd   2>/dev/null || true
sleep 2
systemctl restart dnsmasq
sleep 1
systemctl restart hostapd
sleep 2
systemctl restart mosquitto

# ── Verify ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}AP Status:${NC}"
if systemctl is-active --quiet hostapd; then
    ok "hostapd: RUNNING"
else
    warn "hostapd: NOT RUNNING — check: sudo journalctl -u hostapd -n 20"
fi

if systemctl is-active --quiet dnsmasq; then
    ok "dnsmasq: RUNNING"
else
    warn "dnsmasq: NOT RUNNING"
fi

if ip addr show "$AP_IFACE" | grep -q "$AP_IP"; then
    ok "$AP_IFACE: IP $AP_IP assigned"
else
    warn "$AP_IFACE: IP not yet assigned — may need reboot"
fi

echo ""
echo -e "${BOLD}EATAN Internal AP Summary:${NC}"
echo "  SSID:      $AP_SSID"
echo "  Password:  $AP_PASSWORD"
echo "  RPi IP:    $AP_IP"
echo "  MQTT:      $AP_IP:1883"
echo "  EATAN API: $AP_IP:8888"
echo ""
echo -e "${BOLD}ESP32 firmware constants to verify:${NC}"
echo "  EATAN_WIFI_SSID     = \"$AP_SSID\""
echo "  EATAN_WIFI_PASSWORD = \"$AP_PASSWORD\""
echo "  MQTT_SERVER         = \"$AP_IP\""
echo ""
warn "Change AP_PASSWORD and the ESP32 firmware password before field deployment!"
