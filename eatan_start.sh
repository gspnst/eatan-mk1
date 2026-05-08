#!/usr/bin/env bash
# =============================================================================
# EATAN — Orchestrator / Launcher
# eatan/bin/eatan_start.sh
#
# Starts all EATAN modules in a tmux session with one pane per module.
# Each module restarts automatically on failure (via tmux-based loop).
#
# Usage:
#   bash ~/eatan/bin/eatan_start.sh          # start
#   bash ~/eatan/bin/eatan_start.sh stop     # stop
#   bash ~/eatan/bin/eatan_start.sh status   # show status
#   bash ~/eatan/bin/eatan_start.sh attach   # attach to tmux
# =============================================================================

set -euo pipefail

EATAN_ROOT="${EATAN_ROOT:-$HOME/eatan}"
VENV="$EATAN_ROOT/.venv/bin/python"
SESSION="eatan"

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log()  { echo -e "${CYAN}[EATAN]${NC} $*"; }
ok()   { echo -e "${GREEN}[  OK  ]${NC} $*"; }
warn() { echo -e "${YELLOW}[ WARN ]${NC} $*"; }
die()  { echo -e "${RED}[ FAIL ]${NC} $*"; exit 1; }

# ── Helpers ───────────────────────────────────────────────────────────────────

session_exists() {
    tmux has-session -t "$SESSION" 2>/dev/null
}

# Create a tmux pane running a module with auto-restart
# Usage: launch_module <window_name> <command> [requires_root]
launch_module() {
    local name="$1"
    local cmd="$2"
    local root="${3:-false}"

    local run_cmd
    if [[ "$root" == "true" ]]; then
        # Run as root via sudo (module requires raw socket / monitor mode)
        run_cmd="while true; do sudo $cmd; echo '[EATAN] $name exited — restarting in 5s'; sleep 5; done"
    else
        run_cmd="while true; do $cmd; echo '[EATAN] $name exited — restarting in 5s'; sleep 5; done"
    fi

    tmux new-window -t "$SESSION" -n "$name"
    tmux send-keys -t "$SESSION:$name" "$run_cmd" Enter
}

# ── Command: start ────────────────────────────────────────────────────────────

cmd_start() {
    if session_exists; then
        warn "EATAN tmux session already running. Use 'attach' or 'stop' first."
        exit 0
    fi

    # Verify prerequisites
    command -v tmux    &>/dev/null || die "tmux not installed: sudo apt install tmux"
    [[ -f "$VENV" ]]              || die "Python venv not found at $VENV — run eatan_provision.sh first"

    # Ensure Mosquitto is up
    if ! systemctl is-active --quiet mosquitto; then
        log "Starting Mosquitto..."
        sudo systemctl start mosquitto || die "Could not start Mosquitto"
    fi
    ok "Mosquitto running"

    log "Starting EATAN in tmux session '$SESSION'..."

    # Create session with a dashboard pane (window 0)
    tmux new-session -d -s "$SESSION" -n "dashboard"
    tmux send-keys -t "$SESSION:dashboard" \
        "watch -n 2 'mosquitto_sub -h 127.0.0.1 -t \"eatan/events/system_status\" -C 1 2>/dev/null | python3 -m json.tool 2>/dev/null || echo Waiting for data...'" \
        Enter

    # Window 1: Analysis engine (no root needed)
    launch_module "analysis" \
        "$VENV $EATAN_ROOT/modules/analysis/analysis_engine.py" \
        false

    # Window 2: WiFi scanner (root — needs monitor mode)
    launch_module "wifi" \
        "$VENV $EATAN_ROOT/modules/wifi/wifi_scanner.py" \
        true

    # Window 3: SDR scanner (root — needs USB device access)
    launch_module "sdr" \
        "$VENV $EATAN_ROOT/modules/sdr/sdr_scanner.py" \
        true

    # Window 4: Bluetooth scanner (root — needs hci raw socket)
    launch_module "bluetooth" \
        "$VENV $EATAN_ROOT/modules/bluetooth/bt_scanner.py" \
        true

    # Window 5: ESP32 bridge (no root needed — MQTT subscriber only)
    launch_module "esp32" \
        "$VENV $EATAN_ROOT/modules/esp32/esp32_bridge.py" \
        false

    # Window 6: Alert tail (subscribe to all alerts)
    tmux new-window -t "$SESSION" -n "alerts"
    tmux send-keys -t "$SESSION:alerts" \
        "mosquitto_sub -h 127.0.0.1 -t 'eatan/alerts/#' -v | while read line; do echo \"\$(date '+%H:%M:%S') \$line\"; done" \
        Enter

    # Window 7: Event stream
    tmux new-window -t "$SESSION" -n "events"
    tmux send-keys -t "$SESSION:events" \
        "mosquitto_sub -h 127.0.0.1 -t 'eatan/events/#' -v | while read line; do echo \"\$(date '+%H:%M:%S') \$line\"; done" \
        Enter

    # Go back to dashboard
    tmux select-window -t "$SESSION:dashboard"

    ok "EATAN started. Windows: dashboard | analysis | wifi | sdr | bluetooth | esp32 | alerts | events"
    echo ""
    echo -e "  ${BOLD}Attach:${NC}  tmux attach -t $SESSION"
    echo -e "  ${BOLD}Stop:${NC}    bash $EATAN_ROOT/bin/eatan_start.sh stop"
    echo -e "  ${BOLD}Status:${NC}  bash $EATAN_ROOT/bin/eatan_start.sh status"
    echo ""
}

# ── Command: stop ─────────────────────────────────────────────────────────────

cmd_stop() {
    if session_exists; then
        tmux kill-session -t "$SESSION"
        ok "EATAN tmux session '$SESSION' terminated"
    else
        warn "No EATAN session running"
    fi
}

# ── Command: status ───────────────────────────────────────────────────────────

cmd_status() {
    echo -e "\n${BOLD}EATAN System Status${NC}"
    echo "────────────────────────────────────"

    # tmux session
    if session_exists; then
        ok "tmux session '$SESSION' is running"
        tmux list-windows -t "$SESSION" 2>/dev/null | sed 's/^/  /'
    else
        warn "tmux session '$SESSION' is NOT running"
    fi

    # Mosquitto
    echo ""
    if systemctl is-active --quiet mosquitto; then
        ok "Mosquitto MQTT broker: running"
    else
        warn "Mosquitto MQTT broker: STOPPED"
    fi

    # Quick MQTT status pull (1 second timeout)
    echo ""
    log "Latest system status from MQTT:"
    STATUS=$(timeout 2 mosquitto_sub -h 127.0.0.1 -t "eatan/events/system_status" \
             -C 1 2>/dev/null || echo "{}")
    if [[ "$STATUS" != "{}" && -n "$STATUS" ]]; then
        echo "$STATUS" | python3 -m json.tool 2>/dev/null | sed 's/^/  /'
    else
        warn "No status data (analysis engine may not be running yet)"
    fi

    # DB stats
    echo ""
    DB="$EATAN_ROOT/data/eatan.db"
    if [[ -f "$DB" ]]; then
        DEVICE_COUNT=$(sqlite3 "$DB" "SELECT COUNT(*) FROM devices;" 2>/dev/null || echo "?")
        ALERT_COUNT=$(sqlite3 "$DB" "SELECT COUNT(*) FROM alerts;" 2>/dev/null || echo "?")
        UNACKED=$(sqlite3 "$DB" "SELECT COUNT(*) FROM alerts WHERE acknowledged=0;" 2>/dev/null || echo "?")
        ok "Database: $DEVICE_COUNT devices | $ALERT_COUNT alerts | $UNACKED unacknowledged"
    else
        warn "Database not found at $DB"
    fi
    echo ""
}

# ── Command: attach ───────────────────────────────────────────────────────────

cmd_attach() {
    if session_exists; then
        exec tmux attach -t "$SESSION"
    else
        die "No EATAN session running. Start first: bash $0 start"
    fi
}

# ── Dispatch ──────────────────────────────────────────────────────────────────

COMMAND="${1:-start}"

case "$COMMAND" in
    start)  cmd_start  ;;
    stop)   cmd_stop   ;;
    status) cmd_status ;;
    attach) cmd_attach ;;
    *)
        echo "Usage: $0 {start|stop|status|attach}"
        exit 1
        ;;
esac
