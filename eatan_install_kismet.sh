#!/usr/bin/env bash
# =============================================================================
# EATAN — Kismet Build from Source
# Target: Raspberry Pi OS Bookworm (64-bit), RPi 5
# Run as: sudo bash eatan_install_kismet.sh
#
# Builds and installs the latest stable Kismet release from source.
# Takes 15-25 minutes on an RPi 5 (parallel build on all 4 cores).
# The result is identical to what the apt package would give you.
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log()  { echo -e "${CYAN}[KISMET]${NC} $*"; }
ok()   { echo -e "${GREEN}[  OK  ]${NC} $*"; }
warn() { echo -e "${YELLOW}[ WARN ]${NC} $*"; }
die()  { echo -e "${RED}[ FAIL ]${NC} $*"; exit 1; }
hr()   { echo -e "${BOLD}────────────────────────────────────────────────────${NC}"; }

[[ $EUID -ne 0 ]] && die "Run as root: sudo bash $0"

REAL_USER="${SUDO_USER:-pi}"
BUILD_DIR="/tmp/kismet_build"
KISMET_REPO="https://github.com/kismetwireless/kismet.git"

# Use the latest stable release tag.
# Check https://github.com/kismetwireless/kismet/releases for newer tags.
KISMET_TAG="kismet-2024-02-R1"

hr
echo -e "${BOLD}  EATAN — Kismet Build from Source${NC}"
echo    "  Tag    : $KISMET_TAG"
echo    "  User   : $REAL_USER"
echo    "  Build  : $BUILD_DIR"
hr
echo ""
warn "This will take 15-25 minutes on RPi 5. Don't close the terminal."
echo ""

# =============================================================================
# 1. BUILD DEPENDENCIES
# =============================================================================
log "Installing build dependencies..."

BUILD_DEPS=(
    build-essential
    git
    pkg-config
    zlib1g-dev
    libnl-3-dev
    libnl-genl-3-dev
    libcap-dev
    libpcap-dev
    libnm-dev
    libdw-dev
    libsqlite3-dev
    libprotobuf-dev
    libprotobuf-c-dev
    protobuf-compiler
    protobuf-c-compiler
    libsensors-dev
    libusb-1.0-0-dev
    python3
    python3-setuptools
    python3-protobuf
    python3-requests
    python3-numpy
    python3-serial
    python3-usb
    python3-dev
    librtlsdr-dev
    libwebsockets-dev
    # Web UI
    nodejs
    npm
)

apt-get update -qq
apt-get install -y -qq "${BUILD_DEPS[@]}" 2>/dev/null || {
    warn "Some build deps failed individually — retrying..."
    for pkg in "${BUILD_DEPS[@]}"; do
        apt-get install -y -qq "$pkg" 2>/dev/null || warn "  Skipped: $pkg"
    done
}
ok "Build dependencies installed"

# =============================================================================
# 2. CLONE OR UPDATE SOURCE
# =============================================================================
log "Fetching Kismet source (tag: $KISMET_TAG)..."

if [[ -d "$BUILD_DIR/.git" ]]; then
    log "Existing clone found — fetching updates..."
    cd "$BUILD_DIR"
    git fetch --tags --quiet
else
    rm -rf "$BUILD_DIR"
    git clone --depth 1 --branch "$KISMET_TAG" \
        "$KISMET_REPO" "$BUILD_DIR" 2>/dev/null || {
        # Some tags are formatted differently — try without the branch flag
        warn "Tagged clone failed, trying default branch..."
        git clone --depth 1 "$KISMET_REPO" "$BUILD_DIR"
        cd "$BUILD_DIR"
        # Checkout the tag if it exists
        git fetch --tags --quiet
        git checkout "$KISMET_TAG" 2>/dev/null || \
            warn "Tag $KISMET_TAG not found — building from HEAD (latest dev)"
    }
fi

cd "$BUILD_DIR"
ACTUAL_VERSION=$(git describe --tags 2>/dev/null || echo "dev-$(git rev-parse --short HEAD)")
log "Building version: $ACTUAL_VERSION"

# =============================================================================
# 3. CONFIGURE
# =============================================================================
log "Configuring build..."

./configure \
    --prefix=/usr \
    --sysconfdir=/etc/kismet \
    --disable-python-tools \
    2>&1 | tail -5

# Verify configure succeeded
[[ -f Makefile ]] || die "Configure failed — check output above"
ok "Configure complete"

# =============================================================================
# 4. BUILD
# =============================================================================
CORES=$(nproc)
log "Building with $CORES cores (this is the slow part — ~15 min)..."
echo ""

# Show a progress indicator
make -j"$CORES" 2>&1 | grep -E \
    "^\[|^Making|^Building|error:|Error|warning: un" \
    --line-buffered | head -200 &
GREP_PID=$!

make -j"$CORES" 2>&1 >> /tmp/kismet_build.log || {
    kill $GREP_PID 2>/dev/null || true
    echo ""
    die "Build failed. Last 30 lines of build log:"
    tail -30 /tmp/kismet_build.log
}

kill $GREP_PID 2>/dev/null || true
echo ""
ok "Build complete"

# =============================================================================
# 5. INSTALL
# =============================================================================
log "Installing Kismet..."
make suidinstall 2>&1 | tail -10
# suidinstall sets the correct setuid-root permissions on kismet_cap_*
# binaries so unprivileged users can capture without running kismet as root

ok "Kismet installed"

# =============================================================================
# 6. POST-INSTALL SETUP
# =============================================================================
log "Configuring Kismet groups and permissions..."

# Create kismet group if it doesn't exist
if ! getent group kismet &>/dev/null; then
    groupadd kismet
    ok "Created kismet group"
fi

# Add the real user to kismet group
usermod -aG kismet "$REAL_USER"
ok "Added $REAL_USER to kismet group"

# Ensure cap_ binaries have correct permissions
for cap_bin in /usr/bin/kismet_cap_*; do
    [[ -f "$cap_bin" ]] || continue
    chown root:kismet "$cap_bin"
    chmod 4750 "$cap_bin"    # setuid root, group kismet
done
ok "Capture binary permissions set"

# =============================================================================
# 7. KISMET CONFIG FOR EATAN
# =============================================================================
log "Writing EATAN Kismet configuration..."

mkdir -p /etc/kismet
mkdir -p /var/log/kismet

# Main kismet config override for EATAN use
cat > /etc/kismet/kismet_site.conf << 'KCONF'
# EATAN Kismet site configuration
# This file overrides kismet.conf defaults for EATAN deployment.
# It is preserved across Kismet upgrades.

# ── Logging ───────────────────────────────────────────────────────────────────
# Log to EATAN captures directory
log_prefix=/root/eatan/data/captures/kismet
log_types=kismet,pcapng

# ── REST API ──────────────────────────────────────────────────────────────────
# EATAN wifi_scanner.py connects to this API
httpd_bind_address=127.0.0.1
httpd_port=2501

# Default credentials — change before field use
httpd_username=kismet
httpd_password=kismet_eatan

# Allow unauthenticated status page (safe on localhost)
httpd_allow_cors=false

# ── Sources ───────────────────────────────────────────────────────────────────
# Uncomment and set to your monitor interface after running check_hardware.sh
# source=wlan1mon:name=alfa,type=linuxwifi,hop=true,hop_rate=5/sec

# ── Channel hopping ────────────────────────────────────────────────────────────
channel_hop=true
channel_hop_speed=5/sec

# ── Performance ───────────────────────────────────────────────────────────────
# Reduce memory footprint on RPi
tracker_device_timeout=300
tracker_max_devices=5000

# ── Alert tuning ──────────────────────────────────────────────────────────────
# Kismet's built-in alerts — we use these in addition to EATAN's own alerts
alert=APSPOOF,5/min,1/sec
alert=BCOM,5/min,1/sec
alert=CRYPTODROP,5/min,1/sec
alert=DISCONNCRYPT,5/min,1/sec
alert=DEAUTHFLOOD,5/min,1/sec
alert=NETSTUMBLER,5/min,1/sec
KCONF

chown -R root:kismet /etc/kismet
chmod 750 /etc/kismet
chmod 640 /etc/kismet/kismet_site.conf

ok "Kismet config written to /etc/kismet/kismet_site.conf"

# =============================================================================
# 8. SYSTEMD SERVICE (optional — for auto-start)
# =============================================================================
log "Writing Kismet systemd service..."

cat > /etc/systemd/system/kismet-eatan.service << EOF
[Unit]
Description=Kismet WiFi scanner (EATAN)
After=network.target mosquitto.service
Wants=mosquitto.service

[Service]
Type=simple
User=$REAL_USER
Group=kismet
# Interface is set via kismet_site.conf or -c flag
ExecStart=/usr/bin/kismet --no-console-wrapper --daemonize --pid-file /tmp/kismet-eatan.pid
ExecStop=/bin/kill -TERM \$MAINPID
Restart=on-failure
RestartSec=10

# Allow capture binaries to use raw sockets
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW

[Install]
WantedBy=multi-user.target
EOF

# Don't enable by default — EATAN's orchestrator starts Kismet manually
# to let us set the interface dynamically. Enable with:
#   sudo systemctl enable kismet-eatan
ok "Systemd service written (not enabled — orchestrator manages Kismet)"

# =============================================================================
# 9. VERIFY
# =============================================================================
log "Verifying installation..."
echo ""

if command -v kismet &>/dev/null; then
    KISMET_VER=$(kismet --version 2>/dev/null | head -1 || echo "version unknown")
    ok "kismet binary found: $KISMET_VER"
else
    die "kismet binary not found in PATH after install"
fi

for cap_bin in \
    /usr/bin/kismet_cap_linux_wifi \
    /usr/bin/kismet_cap_linux_bluetooth; do
    if [[ -f "$cap_bin" ]]; then
        ok "$(basename $cap_bin): present"
    else
        warn "$(basename $cap_bin): not found (may be named differently)"
    fi
done

# =============================================================================
# DONE
# =============================================================================
echo ""
hr
echo -e "${GREEN}${BOLD}  Kismet installed successfully!${NC}"
hr
echo ""
echo -e "  ${BOLD}Important:${NC} Log out and back in (or run 'newgrp kismet')"
echo    "  for group membership to take effect."
echo ""
echo -e "  ${BOLD}Quick test:${NC}"
echo    "    kismet --version"
echo    "    # Check your monitor interface name:"
echo    "    bash ~/eatan/bin/check_hardware.sh"
echo ""
echo -e "  ${BOLD}Edit source interface in:${NC}"
echo    "    /etc/kismet/kismet_site.conf"
echo    "    (uncomment the 'source=' line and set your wlan interface)"
echo ""
echo -e "  ${BOLD}Build log saved to:${NC} /tmp/kismet_build.log"
echo ""
