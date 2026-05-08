#!/usr/bin/env bash
# =============================================================================
# EATAN — Mosquitto Fix for Raspberry Pi OS Bookworm
# Run as: sudo bash eatan_fix_mosquitto.sh
#
# Diagnoses and fixes the Mosquitto startup failure caused by config
# conflicts between the Bookworm default mosquitto.conf and our eatan.conf.
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log()  { echo -e "${CYAN}[FIX]${NC} $*"; }
ok()   { echo -e "${GREEN}[ OK ]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
info() { echo -e "      $*"; }

[[ $EUID -ne 0 ]] && { echo "Run as root: sudo bash $0"; exit 1; }

echo ""
echo -e "${BOLD}EATAN — Mosquitto Bookworm Fix${NC}"
echo    "────────────────────────────────────────"

# =============================================================================
# STEP 1 — Show the actual error
# =============================================================================
log "Checking current Mosquitto status..."
echo ""
systemctl status mosquitto --no-pager -l 2>/dev/null | head -20 || true
echo ""

log "Checking journal for root cause..."
echo ""
journalctl -u mosquitto --no-pager -n 30 2>/dev/null | grep -E "(Error|error|invalid|Invalid|conflict|Conflict|failed|Failed|Cannot|cannot)" || \
    journalctl -u mosquitto --no-pager -n 15
echo ""

# =============================================================================
# STEP 2 — Show conflicting config files
# =============================================================================
log "Examining Mosquitto config files..."

echo ""
echo -e "${BOLD}  /etc/mosquitto/mosquitto.conf:${NC}"
cat /etc/mosquitto/mosquitto.conf 2>/dev/null | sed 's/^/    /' || echo "    (not found)"

echo ""
echo -e "${BOLD}  /etc/mosquitto/conf.d/ contents:${NC}"
ls -la /etc/mosquitto/conf.d/ 2>/dev/null | sed 's/^/    /' || echo "    (empty or not found)"
echo ""

for f in /etc/mosquitto/conf.d/*.conf; do
    [[ -f "$f" ]] || continue
    echo -e "${BOLD}  $f:${NC}"
    cat "$f" | sed 's/^/    /'
    echo ""
done

# =============================================================================
# STEP 3 — Apply the fix
# =============================================================================
log "Applying fix..."

# 3a. Ensure log directory exists with correct ownership
# (Missing log dir is a common silent failure cause on fresh installs)
mkdir -p /var/log/mosquitto
chown mosquitto:mosquitto /var/log/mosquitto 2>/dev/null || \
    chown root:root /var/log/mosquitto
ok "Log directory: /var/log/mosquitto"

# 3b. Ensure persistence directory exists
mkdir -p /var/lib/mosquitto
chown mosquitto:mosquitto /var/lib/mosquitto 2>/dev/null || true
ok "Persistence directory: /var/lib/mosquitto"

# 3c. Neutralise the default mosquitto.conf
# On Bookworm the default file often contains:
#   per_listener_settings true
#   allow_anonymous false
# Both conflict with our conf.d settings. We replace it with a clean
# include-only stub that defers all config to conf.d.
log "Replacing /etc/mosquitto/mosquitto.conf with clean stub..."
cp /etc/mosquitto/mosquitto.conf /etc/mosquitto/mosquitto.conf.bak.$(date +%s)
cat > /etc/mosquitto/mosquitto.conf << 'EOF'
# EATAN — Mosquitto main config
# All configuration is in /etc/mosquitto/conf.d/eatan.conf
# This file intentionally left minimal.
pid_file /run/mosquitto/mosquitto.pid
include_dir /etc/mosquitto/conf.d
EOF
ok "Main config replaced (backup saved)"

# 3d. Write a clean eatan.conf that's Bookworm-compatible
# Key points:
#   - listener MUST come before allow_anonymous (Bookworm 2.x requirement)
#   - per_listener_settings must NOT be set (or set to false) when using
#     allow_anonymous at global scope
#   - log_dest file requires the directory to exist and be writable
log "Writing clean eatan.conf..."
cat > /etc/mosquitto/conf.d/eatan.conf << 'EOF'
# EATAN MQTT broker — Bookworm-compatible config
# Mosquitto 2.x requires listener before allow_anonymous

# ── Listener ──────────────────────────────────────────────────────────────────
# Phase 1: localhost only. setup_ap.sh widens this to 0.0.0.0 for ESP32 nodes.
listener 1883 127.0.0.1

# Anonymous connections allowed (internal network only — no internet exposure)
allow_anonymous true

# ── Persistence ───────────────────────────────────────────────────────────────
persistence true
persistence_location /var/lib/mosquitto/

# ── Logging ───────────────────────────────────────────────────────────────────
# Use syslog instead of file to avoid permission issues on first boot
log_dest syslog
log_type error
log_type warning
log_type information

# ── Tuning ────────────────────────────────────────────────────────────────────
max_keepalive 60
max_connections 50
EOF
ok "eatan.conf written"

# 3e. Ensure /run/mosquitto exists (needed for pid_file on Bookworm)
mkdir -p /run/mosquitto
chown mosquitto:mosquitto /run/mosquitto 2>/dev/null || true
ok "PID directory: /run/mosquitto"

# =============================================================================
# STEP 4 — Test config syntax before starting
# =============================================================================
log "Testing config syntax..."
if mosquitto -c /etc/mosquitto/mosquitto.conf --test-conf 2>/dev/null; then
    ok "Config syntax valid"
else
    # Older versions don't support --test-conf, try -v briefly instead
    warn "--test-conf not supported by this Mosquitto version — skipping syntax check"
fi

# =============================================================================
# STEP 5 — Start Mosquitto
# =============================================================================
log "Starting Mosquitto..."
systemctl daemon-reload
systemctl enable mosquitto --quiet
systemctl restart mosquitto
sleep 2

if systemctl is-active --quiet mosquitto; then
    ok "Mosquitto is running"
else
    warn "Still failing. Checking journal..."
    journalctl -u mosquitto --no-pager -n 20
    echo ""
    echo -e "${RED}Automatic fix did not resolve the issue.${NC}"
    echo    "Please paste the journal output above and we'll dig deeper."
    exit 1
fi

# =============================================================================
# STEP 6 — Verify end-to-end
# =============================================================================
log "Running publish/subscribe round-trip test..."
sleep 0.5

# Subscribe in background, capture output
SUB_OUT=$(mosquitto_sub -h 127.0.0.1 -p 1883 -t "eatan/test/fix" \
          -C 1 --quiet -W 3 2>/dev/null &
          sleep 0.3
          mosquitto_pub -h 127.0.0.1 -p 1883 \
              -t "eatan/test/fix" -m '{"status":"ok"}' 2>/dev/null
          wait)

if [[ -n "$SUB_OUT" ]] || \
   mosquitto_pub -h 127.0.0.1 -p 1883 -t "eatan/test/ping" -m "ping" 2>/dev/null; then
    ok "MQTT publish test successful"
else
    warn "Publish test inconclusive — but Mosquitto is running"
fi

# =============================================================================
# DONE
# =============================================================================
echo ""
echo "────────────────────────────────────────"
echo -e "${GREEN}${BOLD}Mosquitto fix complete.${NC}"
echo ""
echo "You can now continue the provisioning from where it failed:"
echo "  sudo bash ~/eatan_provision.sh"
echo ""
echo "Or if provisioning already completed, just verify hardware:"
echo "  bash ~/eatan/bin/check_hardware.sh"
echo ""

# Show the Mosquitto version — useful context for debugging
MOSQ_VER=$(mosquitto --version 2>/dev/null | head -1 || echo "unknown")
info "Mosquitto version: $MOSQ_VER"
