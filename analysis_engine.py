#!/usr/bin/env python3
"""
EATAN — Analysis Engine
eatan/modules/analysis/analysis_engine.py

The brain of EATAN Mk1.

Responsibilities:
  - Subscribe to ALL eatan/raw/# topics
  - Maintain the device ledger (DB upserts)
  - Run the baseline calibration window
  - Detect new devices (post-baseline) → fire alerts
  - Detect device disappearance (last-seen timeout)
  - Check signals against threat signature DB
  - Publish eatan/events/* and eatan/alerts/*

Run:
    ~/eatan/.venv/bin/python \
        ~/eatan/modules/analysis/analysis_engine.py
    (does NOT require root)
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent))
from eatan_bus import (
    EatanBus, EatanConfig, EatanDB, DeviceRecord,
    AlertRecord, Topics, now_ms, configure_logging,
)

# ── Constants ─────────────────────────────────────────────────────────────────

MODULE_NAME = "analysis_engine"

# How long without a signal before a device is considered "lost" (ms)
DEVICE_TIMEOUT_MS: dict[str, int] = {
    "wifi":       5  * 60 * 1000,    # 5 minutes
    "ble":        3  * 60 * 1000,    # 3 minutes
    "sdr_iot":   15  * 60 * 1000,    # 15 minutes (IoT devices transmit infrequently)
    "rf_spectrum":10 * 60 * 1000,    # 10 minutes
    "adsb":       2  * 60 * 1000,    # 2 minutes
    "default":    5  * 60 * 1000,
}

# How often to check for lost devices (seconds)
TIMEOUT_CHECK_INTERVAL = 60.0

# How often to publish the full status summary (seconds)
STATUS_PUBLISH_INTERVAL = 30.0

# Threat signature patterns (built-in, lightweight)
# Format: (pattern_type, pattern, description, severity)
BUILT_IN_SIGNATURES: list[tuple[str, str, str, str]] = [
    # Known surveillance WiFi SSIDs
    ("ssid_exact",    "Stingray",          "IMSI catcher SSID",            "CRIT"),
    ("ssid_exact",    "IMSI",              "IMSI catcher SSID",            "CRIT"),
    ("ssid_exact",    "Crossbow",          "Known IMSI catcher variant",   "CRIT"),
    ("ssid_prefix",   "AndroidAP",         "Phone hotspot (common cover)", "INFO"),

    # MAC OUI prefixes of devices commonly found in surveillance equipment
    # (these are not conclusive — treat as WARN triggers for human review)
    ("oui_prefix",    "00:13:EF",          "Cobham / Thales surveillance", "WARN"),

    # Suspicious SSID patterns (hidden cameras, rogue APs)
    ("ssid_contains", "hidden",            "Potential hidden device SSID", "WARN"),
    ("ssid_contains", "camera",            "Potential camera device SSID", "WARN"),
    ("ssid_contains", "spy",               "Suspicious SSID",              "WARN"),

    # IoT device classes that indicate active monitoring
    ("device_class",  "TPMS",             "Vehicle present (TPMS sensor)", "INFO"),
]


# ── Device state tracker ──────────────────────────────────────────────────────

@dataclass
class TrackedDevice:
    device_key:   str
    sensor_type:  str
    first_seen:   int           # ms
    last_seen:    int           # ms
    times_seen:   int = 1
    is_baseline:  bool = False
    is_lost:      bool = False
    rssi_history: list[float] = field(default_factory=list)  # last N RSSI values

    def update(self, rec: DeviceRecord) -> None:
        self.last_seen  = rec.timestamp
        self.times_seen += 1
        self.is_lost    = False
        if rec.rssi is not None:
            self.rssi_history.append(rec.rssi)
            if len(self.rssi_history) > 20:
                self.rssi_history.pop(0)

    @property
    def avg_rssi(self) -> float | None:
        if self.rssi_history:
            return sum(self.rssi_history) / len(self.rssi_history)
        return None

    @property
    def timeout_ms(self) -> int:
        return DEVICE_TIMEOUT_MS.get(self.sensor_type,
                                      DEVICE_TIMEOUT_MS["default"])

    def is_timed_out(self, now: int) -> bool:
        return (now - self.last_seen) > self.timeout_ms


# ── Threat matcher ────────────────────────────────────────────────────────────

class ThreatMatcher:
    """Checks a DeviceRecord against known threat signatures."""

    def __init__(self, signatures: list[tuple[str, str, str, str]]):
        self._sigs = signatures

    def check(self, rec: DeviceRecord) -> list[tuple[str, str, str]]:
        """
        Returns list of (description, severity, pattern_type) for each match.
        """
        matches = []
        for pattern_type, pattern, description, severity in self._sigs:
            hit = False
            if pattern_type == "ssid_exact" and rec.ssid:
                hit = rec.ssid.strip().lower() == pattern.lower()
            elif pattern_type == "ssid_prefix" and rec.ssid:
                hit = rec.ssid.strip().lower().startswith(pattern.lower())
            elif pattern_type == "ssid_contains" and rec.ssid:
                hit = pattern.lower() in rec.ssid.strip().lower()
            elif pattern_type == "oui_prefix" and rec.mac_address:
                hit = rec.mac_address.upper().startswith(pattern.upper())
            elif pattern_type == "device_class" and rec.device_class:
                hit = rec.device_class == pattern
            if hit:
                matches.append((description, severity, pattern_type))
        return matches


# ── Analysis Engine ───────────────────────────────────────────────────────────

class AnalysisEngine:

    def __init__(self, cfg: EatanConfig):
        self.cfg      = cfg
        self.bus      = EatanBus(cfg, MODULE_NAME)
        self.db       = EatanDB(cfg.db_path)
        self.topics   = Topics(cfg.prefix)
        self.log      = configure_logging(MODULE_NAME, cfg.log_level)
        self.matcher  = ThreatMatcher(BUILT_IN_SIGNATURES)

        # In-memory device state
        self._devices: dict[str, TrackedDevice] = {}

        # Baseline state
        self._baseline_active = True
        self._baseline_end_ms = now_ms() + (cfg.baseline_sec * 1000)
        self._baseline_device_count = 0

        # Stats
        self._alerts_fired  = 0
        self._events_processed = 0
        self._running = False

    # ── Setup ─────────────────────────────────────────────────────────────────

    async def setup(self) -> None:
        await self.db.connect()
        await self.bus.connect()

        # Subscribe to all raw sensor feeds
        self.bus.subscribe(self.topics.all_raw(), self._on_raw_message)

        await self.db.write_system_event(
            "analysis_engine_start",
            f"Analysis engine started. Baseline window: {self.cfg.baseline_sec}s",
            {"baseline_end_ms": self._baseline_end_ms},
        )
        self.log.info(
            "analysis_engine_started",
            baseline_sec=self.cfg.baseline_sec,
            baseline_ends_at=time.strftime(
                "%H:%M:%S", time.localtime(self._baseline_end_ms / 1000)
            ),
        )

        # Announce baseline start
        await self.bus.publish_event("baseline_start", {
            "message":         "Calibration window open — learning environment",
            "duration_sec":    self.cfg.baseline_sec,
            "ends_at_ms":      self._baseline_end_ms,
        })

    # ── Main run loop ─────────────────────────────────────────────────────────

    async def run(self) -> None:
        self._running = True
        await asyncio.gather(
            self.bus.heartbeat_loop(30),
            self._baseline_monitor(),
            self._timeout_checker(),
            self._status_publisher(),
        )

    # ── MQTT message handler ──────────────────────────────────────────────────

    async def _on_raw_message(self, topic: str, payload: dict) -> None:
        """Called for every message on eatan/raw/#."""
        try:
            rec = DeviceRecord.from_json(json.dumps(payload))
        except Exception as e:
            self.log.warning("parse_error", topic=topic, error=str(e))
            return

        self._events_processed += 1
        await self._process_device(rec)

    async def _process_device(self, rec: DeviceRecord) -> None:
        """Core logic: update ledger, check threats, fire events/alerts."""

        # ── 1. Update in-memory tracker ───────────────────────────────────────
        if rec.device_key in self._devices:
            tracked = self._devices[rec.device_key]
            tracked.update(rec)
            is_new = False
        else:
            is_new = True
            tracked = TrackedDevice(
                device_key  = rec.device_key,
                sensor_type = rec.sensor_type,
                first_seen  = rec.timestamp,
                last_seen   = rec.timestamp,
                is_baseline = self._baseline_active,
            )
            self._devices[rec.device_key] = tracked

        # ── 2. DB upsert (async, non-blocking) ───────────────────────────────
        db_is_new = await self.db.upsert_device(rec)
        if db_is_new and tracked.is_baseline:
            await self.db.mark_baseline(rec.device_key)

        # ── 3. Publish device_seen event ──────────────────────────────────────
        await self.bus.publish_event("device_seen", {
            "device_key":   rec.device_key,
            "sensor_type":  rec.sensor_type,
            "mac_address":  rec.mac_address,
            "vendor_oui":   rec.vendor_oui,
            "device_class": rec.device_class,
            "ssid":         rec.ssid,
            "rssi":         rec.rssi,
            "channel":      rec.channel,
            "frequency":    rec.frequency,
            "timestamp":    rec.timestamp,
            "is_baseline":  tracked.is_baseline,
            "times_seen":   tracked.times_seen,
            "avg_rssi":     tracked.avg_rssi,
        })

        # ── 4. New device alert (post-baseline only) ───────────────────────────
        if is_new and not self._baseline_active and self.cfg.alert_new_device:
            await self._fire_new_device_alert(rec, tracked)

        # ── 5. Threat signature check ──────────────────────────────────────────
        if is_new or rec.sensor_type == "wifi":   # re-check WiFi each time (SSID may change)
            await self._check_threats(rec)

    # ── Alerting ──────────────────────────────────────────────────────────────

    async def _fire_new_device_alert(self, rec: DeviceRecord,
                                      tracked: TrackedDevice) -> None:
        label = self._device_label(rec)
        alert = AlertRecord(
            severity   = "WARN",
            alert_type = "new_device",
            message    = f"New {rec.sensor_type.upper()} device detected: {label}",
            device_key = rec.device_key,
            raw_data   = {
                "mac_address":  rec.mac_address,
                "vendor_oui":   rec.vendor_oui,
                "device_class": rec.device_class,
                "ssid":         rec.ssid,
                "rssi":         rec.rssi,
                "frequency":    rec.frequency,
            },
        )
        await self.bus.publish_alert(alert)
        await self.db.write_alert(alert)
        self._alerts_fired += 1

        self.log.warning(
            "new_device_alert",
            device_key  = rec.device_key,
            label       = label,
            sensor_type = rec.sensor_type,
            rssi        = rec.rssi,
        )

    async def _check_threats(self, rec: DeviceRecord) -> None:
        matches = self.matcher.check(rec)
        for description, severity, pattern_type in matches:
            label = self._device_label(rec)
            alert = AlertRecord(
                severity   = severity,
                alert_type = "known_hostile_signature",
                message    = f"Threat match on {label}: {description}",
                device_key = rec.device_key,
                raw_data   = {
                    "pattern_type": pattern_type,
                    "description":  description,
                    "mac_address":  rec.mac_address,
                    "ssid":         rec.ssid,
                    "device_class": rec.device_class,
                },
            )
            await self.bus.publish_alert(alert)
            await self.db.write_alert(alert)
            self._alerts_fired += 1

            self.log.warning(
                "threat_signature_match",
                severity    = severity,
                description = description,
                device_key  = rec.device_key,
                label       = label,
            )

    async def _fire_device_lost_alert(self, tracked: TrackedDevice) -> None:
        await self.bus.publish_event("device_lost", {
            "device_key":  tracked.device_key,
            "sensor_type": tracked.sensor_type,
            "last_seen":   tracked.last_seen,
            "times_seen":  tracked.times_seen,
        })
        self.log.info(
            "device_lost",
            device_key  = tracked.device_key,
            sensor_type = tracked.sensor_type,
            last_seen_s = int((now_ms() - tracked.last_seen) / 1000),
        )

    # ── Background tasks ──────────────────────────────────────────────────────

    async def _baseline_monitor(self) -> None:
        """Watches for baseline window expiry."""
        while self._running and self._baseline_active:
            remaining_ms = self._baseline_end_ms - now_ms()
            if remaining_ms <= 0:
                await self._end_baseline()
                return
            # Log progress every minute
            if int(remaining_ms / 1000) % 60 == 0:
                self.log.info(
                    "baseline_in_progress",
                    remaining_sec = int(remaining_ms / 1000),
                    devices_seen  = len(self._devices),
                )
            await asyncio.sleep(5)

    async def _end_baseline(self) -> None:
        self._baseline_active = False
        self._baseline_device_count = len(self._devices)

        msg = (f"Baseline complete. {self._baseline_device_count} devices catalogued. "
               f"Alerting now active.")
        self.log.info("baseline_complete", device_count=self._baseline_device_count)

        await self.bus.publish_event("baseline_end", {
            "message":      msg,
            "device_count": self._baseline_device_count,
            "timestamp":    now_ms(),
        })

        # Fire an INFO alert so the operator dashboard sees the state change
        alert = AlertRecord(
            severity   = "INFO",
            alert_type = "baseline_complete",
            message    = msg,
            raw_data   = {"baseline_device_count": self._baseline_device_count},
        )
        await self.bus.publish_alert(alert)
        await self.db.write_alert(alert)

        await self.db.write_system_event("baseline_complete", msg,
                                          {"device_count": self._baseline_device_count})

    async def _timeout_checker(self) -> None:
        """Mark devices as lost when they haven't been seen for their timeout period."""
        while self._running:
            await asyncio.sleep(TIMEOUT_CHECK_INTERVAL)
            now = now_ms()
            for tracked in list(self._devices.values()):
                if not tracked.is_lost and tracked.is_timed_out(now):
                    tracked.is_lost = True
                    await self._fire_device_lost_alert(tracked)

    async def _status_publisher(self) -> None:
        """Periodically publish a system status summary."""
        while self._running:
            await asyncio.sleep(STATUS_PUBLISH_INTERVAL)
            counts: dict[str, int] = {}
            active = 0
            now = now_ms()

            for t in self._devices.values():
                counts[t.sensor_type] = counts.get(t.sensor_type, 0) + 1
                if not t.is_timed_out(now):
                    active += 1

            status = {
                "timestamp":        now,
                "uptime_sec":       int((now - (self._baseline_end_ms
                                               - self.cfg.baseline_sec * 1000)) / 1000),
                "baseline_active":  self._baseline_active,
                "total_devices":    len(self._devices),
                "active_devices":   active,
                "devices_by_type":  counts,
                "alerts_fired":     self._alerts_fired,
                "events_processed": self._events_processed,
            }
            await self.bus.publish_event("system_status", status)
            self.log.info("status", **{k: v for k, v in status.items()
                                        if k != "timestamp"})

    # ── Utilities ─────────────────────────────────────────────────────────────

    @staticmethod
    def _device_label(rec: DeviceRecord) -> str:
        """Build a human-readable label for a device."""
        parts = []
        if rec.ssid:
            parts.append(f'SSID:"{rec.ssid}"')
        if rec.vendor_oui:
            parts.append(rec.vendor_oui)
        if rec.mac_address:
            parts.append(rec.mac_address)
        if rec.device_class:
            parts.append(f"[{rec.device_class}]")
        if rec.frequency:
            parts.append(f"@ {rec.frequency/1e6:.1f} MHz")
        return " ".join(parts) if parts else rec.device_key

    async def teardown(self) -> None:
        self._running = False
        await self.db.write_system_event("analysis_engine_stop",
                                          "Analysis engine stopped",
                                          {"total_devices": len(self._devices),
                                           "alerts_fired":  self._alerts_fired})
        await self.db.close()
        self.bus.disconnect()


# ── Entry point ───────────────────────────────────────────────────────────────

async def main() -> None:
    cfg    = EatanConfig()
    engine = AnalysisEngine(cfg)

    try:
        await engine.setup()
        await engine.run()
    except KeyboardInterrupt:
        pass
    finally:
        await engine.teardown()


if __name__ == "__main__":
    asyncio.run(main())
