#!/usr/bin/env python3
"""
EATAN — Bluetooth Scanner Module
eatan/modules/bluetooth/bt_scanner.py

Passive Bluetooth scanner using the RPi's built-in Bluetooth radio.
Covers devices the ESP32s may not reach (immediate proximity to the RPi unit).

Two scan modes:
  1. BLE advertisements (primary) — catches modern phones, wearables,
     smart speakers, IoT sensors, AirTags, beacons, medical devices
  2. Classic Bluetooth inquiry (secondary, periodic) — catches older
     devices: laptops, headsets, car audio systems, legacy IoT

Published topic:  eatan/raw/ble
Payload model:    DeviceRecord (sensor_type="ble")

Run:
    sudo ~/eatan/.venv/bin/python \
         ~/eatan/modules/bluetooth/bt_scanner.py
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from eatan_bus import (
    EatanBus, EatanConfig, EatanDB, DeviceRecord,
    AlertRecord, now_ms, lookup_vendor, configure_logging,
)

# ── Constants ─────────────────────────────────────────────────────────────────

MODULE_NAME = "bt_scanner"

BLE_SCAN_INTERVAL_SEC   = 2.0    # seconds between hcitool lescan output polls
CLASSIC_SCAN_INTERVAL   = 120    # seconds between classic BT inquiry sweeps
HEARTBEAT_INTERVAL      = 30.0

# BLE address type detection (Linux hcitool / bluetoothctl conventions)
RANDOM_ADDR_PREFIXES = {
    "R": "random",   # hcitool lescan output suffix
}

# Known BLE service UUIDs and what they indicate
# (partial list — enough for common operational encounters)
SERVICE_UUID_MAP: dict[str, tuple[str, str]] = {
    # (service_name, device_class_hint)
    "0000180a": ("Device Information",     "generic"),
    "0000180d": ("Heart Rate",             "wearable"),
    "00001800": ("Generic Access",         "generic"),
    "0000fe9f": ("Google Fast Pair",       "Android_device"),
    "0000fd6f": ("COVID-19 Exposure",      "mobile_device"),
    "0000fea0": ("Google Nearby",          "Android_device"),
    "0000fd5a": ("FIDO2",                  "security_key"),
    "0000fef3": ("iCloud",                 "Apple"),
    "0000fd44": ("Exposure Notification",  "mobile_device"),
    "0000fd5c": ("MagSafe",                "Apple"),
    "d0611e78": ("Apple Continuity",       "Apple"),
    "9fa480e0": ("Apple AirDrop",          "Apple"),
    "0000fe26": ("Google",                 "Google_device"),
    "0000fe07": ("Tile",                   "tile_tracker"),
    "0000feaa": ("Eddystone Beacon",       "beacon"),
    "0000180f": ("Battery Service",        "IoT_device"),
    "0000181a": ("Environmental Sensing",  "sensor"),
    "00001802": ("Immediate Alert",        "IoT_device"),
    "0000ffe0": ("Custom HM-10 Serial",    "IoT_dev_board"),
}


# ── BLE scanner via hcitool + hcidump pipe ────────────────────────────────────
# We use subprocess-based scanning rather than BlueHydra (which has heavy
# dependencies) or python-bluetooth (which has incomplete BLE support).
# The approach: run `hcitool lescan` for passive scan + parse `hcidump` for
# richer advertisement data, falling back to simple lescan output when hcidump
# is unavailable.

class HcitoolBLEScanner:
    """
    Passive BLE scanner using hcitool lescan.
    Parses device addresses and (when available) RSSI from btmon output.
    """

    def __init__(self, interface: str = "hci0"):
        self.interface = interface
        self._proc_scan:  subprocess.Popen | None = None
        self._proc_btmon: subprocess.Popen | None = None

    def _reset_interface(self) -> None:
        """Bring the HCI interface up cleanly."""
        subprocess.run(["hciconfig", self.interface, "down"],
                       capture_output=True, timeout=5)
        time.sleep(0.3)
        subprocess.run(["hciconfig", self.interface, "up"],
                       capture_output=True, timeout=5)
        time.sleep(0.3)

    async def start(self, log) -> bool:
        """Start passive BLE scan. Returns True on success."""
        # Check interface exists
        result = subprocess.run(["hciconfig", self.interface],
                                capture_output=True, text=True, timeout=5)
        if self.interface not in result.stdout:
            log.error("bt_interface_not_found", interface=self.interface,
                       hint="Check 'hciconfig -a' output")
            return False

        self._reset_interface()

        # Start btmon for full advertisement data (RSSI, names, services)
        # btmon output is rich but needs parsing
        try:
            self._proc_btmon = subprocess.Popen(
                ["btmon", "--index", self.interface.replace("hci", "")],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            log.info("btmon_started", interface=self.interface)
        except FileNotFoundError:
            log.warning("btmon_not_found",
                         hint="Install: sudo apt install bluez — falling back to lescan only")

        # Start hcitool lescan (passive, report duplicates for RSSI tracking)
        try:
            self._proc_scan = subprocess.Popen(
                ["hcitool", "-i", self.interface, "lescan",
                 "--passive", "--duplicates"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            log.info("ble_lescan_started", interface=self.interface)
            return True
        except FileNotFoundError:
            log.error("hcitool_not_found",
                       hint="Install: sudo apt install bluez")
            return False

    async def read_btmon_events(self) -> list[dict]:
        """
        Parse btmon output to extract BLE advertisement records.
        btmon output format (relevant lines):
          @ MGMT Event: Device Found (0x0012) ... [hci0] 1.234567
            Address: XX:XX:XX:XX:XX:XX (Public)
            RSSI: -65 dBm (0xbf)
            Name (complete): MyDevice
        """
        if not self._proc_btmon or self._proc_btmon.poll() is not None:
            return []

        records: list[dict] = []
        current: dict = {}

        # Non-blocking read — collect up to 100 lines
        lines_read = 0
        try:
            import select
            if self._proc_btmon.stdout is None:
                return []
            rlist, _, _ = select.select([self._proc_btmon.stdout], [], [], 0.1)
            if not rlist:
                return []

            while lines_read < 200:
                line = self._proc_btmon.stdout.readline()
                if not line:
                    break
                line = line.strip()
                lines_read += 1

                if "Device Found" in line or "Device Connected" in line:
                    if current.get("mac"):
                        records.append(current)
                    current = {"ts": now_ms(), "frame": "adv"}

                elif current:
                    if line.startswith("Address:"):
                        # "Address: XX:XX:XX:XX:XX:XX (Public)"
                        m = re.match(r"Address:\s+([0-9A-Fa-f:]{17})\s*\((\w+)\)", line)
                        if m:
                            current["mac"]       = m.group(1).upper()
                            current["addr_type"] = m.group(2).lower()

                    elif line.startswith("RSSI:"):
                        m = re.search(r"RSSI:\s+(-?\d+)", line)
                        if m:
                            current["rssi"] = int(m.group(1))

                    elif line.startswith("Name (complete):") or \
                         line.startswith("Name (short):"):
                        current["name"] = line.split(":", 1)[1].strip()

                    elif line.startswith("UUID 16:") or \
                         line.startswith("Service UUID (complete)"):
                        uuids = current.setdefault("service_uuids", [])
                        m = re.search(r"([0-9a-fA-F]{4,8})", line)
                        if m:
                            uuids.append(m.group(1).lower().zfill(8))

                    elif "TX Power:" in line:
                        m = re.search(r"TX Power:\s+(-?\d+)", line)
                        if m:
                            current["tx_power"] = int(m.group(1))

                    elif "Company:" in line:
                        current["company"] = line.split(":", 1)[1].strip()

        except Exception:
            pass

        if current.get("mac"):
            records.append(current)

        return records

    async def read_lescan_lines(self) -> list[dict]:
        """
        Fallback: parse plain hcitool lescan output.
        Format: "XX:XX:XX:XX:XX:XX  DeviceName" or "XX:XX:XX:XX:XX:XX  (unknown)"
        """
        if not self._proc_scan or self._proc_scan.poll() is not None:
            return []

        records: list[dict] = []
        try:
            import select
            if self._proc_scan.stdout is None:
                return []
            rlist, _, _ = select.select([self._proc_scan.stdout], [], [], 0.1)
            if not rlist:
                return []

            lines_read = 0
            while lines_read < 100:
                line = self._proc_scan.stdout.readline()
                if not line:
                    break
                line = line.strip()
                lines_read += 1

                # Match MAC address lines
                m = re.match(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\s+(.*)", line)
                if m:
                    mac  = m.group(1).upper()
                    name = m.group(2).strip()
                    if name in ("(unknown)", ""):
                        name = None
                    records.append({
                        "mac":  mac,
                        "name": name,
                        "ts":   now_ms(),
                    })
        except Exception:
            pass

        return records

    def stop(self) -> None:
        for proc in [self._proc_scan, self._proc_btmon]:
            if proc:
                try:
                    proc.terminate()
                    proc.wait(timeout=3)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass


# ── Classic Bluetooth inquiry ─────────────────────────────────────────────────

async def classic_bt_inquiry(interface: str, log) -> list[dict]:
    """
    Run a classic Bluetooth inquiry scan (hcitool scan).
    This is active (sends inquiry packets) so use sparingly.
    Returns list of {mac, name} dicts.
    """
    log.info("classic_bt_inquiry_start")
    try:
        result = await asyncio.wait_for(
            asyncio.create_subprocess_exec(
                "hcitool", "-i", interface, "scan", "--flush",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            ),
            timeout=15,
        )
        stdout, _ = await asyncio.wait_for(result.communicate(), timeout=12)
        devices = []
        for line in stdout.decode().splitlines():
            m = re.match(r"\s+([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\s+(.*)", line)
            if m:
                devices.append({
                    "mac":  m.group(1).upper(),
                    "name": m.group(2).strip() or None,
                    "ts":   now_ms(),
                    "mode": "classic",
                })
        log.info("classic_bt_inquiry_done", found=len(devices))
        return devices
    except asyncio.TimeoutError:
        log.warning("classic_bt_inquiry_timeout")
        return []
    except Exception as e:
        log.warning("classic_bt_inquiry_error", error=str(e))
        return []


# ── Record converter ──────────────────────────────────────────────────────────

def build_device_record(raw: dict, node_id: str) -> DeviceRecord | None:
    mac = raw.get("mac", "").upper().strip()
    if not mac:
        return None

    addr_type = raw.get("addr_type", "public")
    name      = raw.get("name")
    rssi      = raw.get("rssi")
    company   = raw.get("company")
    tx_power  = raw.get("tx_power")
    uuids     = raw.get("service_uuids", [])
    mode      = raw.get("mode", "ble")

    # Classify device
    if mode == "classic":
        dev_class = "classic_bt"
    elif addr_type == "random":
        dev_class = "mobile_device"   # rotating MAC = smartphone
    elif name and any(k in name.lower() for k in ("airpod", "buds", "headphone", "earphone")):
        dev_class = "wearable_audio"
    elif name and any(k in name.lower() for k in ("watch", "band", "fit")):
        dev_class = "wearable"
    elif uuids:
        # Look up first known UUID
        for uuid in uuids:
            if uuid in SERVICE_UUID_MAP:
                _, class_hint = SERVICE_UUID_MAP[uuid]
                dev_class = class_hint
                break
        else:
            dev_class = "BLE_IoT"
    elif company:
        dev_class = f"BLE_{company.split()[0]}"
    else:
        dev_class = "BLE_unknown"

    vendor = lookup_vendor(mac) or company or "Unknown"

    return DeviceRecord(
        device_key   = f"ble:{mac}",
        sensor_type  = "ble",
        timestamp    = raw.get("ts", now_ms()),
        rssi         = float(rssi) if rssi is not None else None,
        mac_address  = mac,
        vendor_oui   = vendor,
        device_class = dev_class,
        raw_data     = {
            "source_module": MODULE_NAME,
            "addr_type":     addr_type,
            "name":          name,
            "company":       company,
            "tx_power":      tx_power,
            "service_uuids": uuids,
            "mode":          mode,
        },
        node_id = node_id,
    )


# ── Main scanner ──────────────────────────────────────────────────────────────

class BTScanner:

    def __init__(self, cfg: EatanConfig):
        self.cfg     = cfg
        self.bus     = EatanBus(cfg, MODULE_NAME)
        self.db      = EatanDB(cfg.db_path)
        self.log     = configure_logging(MODULE_NAME, cfg.log_level)
        self.iface   = cfg.get("BT_INTERFACE", "hci0")
        self._hci    = HcitoolBLEScanner(self.iface)
        self._seen:  set[str] = set()
        self._running = False
        self._use_btmon = False   # determined at startup

    async def setup(self) -> None:
        if os.geteuid() != 0:
            self.log.error("requires_root",
                            hint="sudo ~/eatan/.venv/bin/python bt_scanner.py")
            raise PermissionError("bt_scanner requires root")

        await self.db.connect()
        await self.bus.connect()

        started = await self._hci.start(self.log)
        if not started:
            raise RuntimeError("Failed to start BLE scanner — check Bluetooth hardware")

        # Check if btmon process started successfully
        self._use_btmon = (self._hci._proc_btmon is not None and
                            self._hci._proc_btmon.poll() is None)
        self.log.info("bt_scanner_started",
                       interface=self.iface,
                       btmon=self._use_btmon)
        await self.db.write_system_event(
            "bt_scanner_start",
            f"Bluetooth scanner started on {self.iface}",
            {"interface": self.iface, "btmon": self._use_btmon},
        )

    async def run(self) -> None:
        self._running = True
        self.log.info("bt_scanner_running",
                       interface=self.iface,
                       mode="btmon+lescan" if self._use_btmon else "lescan-only",
                       classic_interval_sec=CLASSIC_SCAN_INTERVAL)
        await asyncio.gather(
            self._ble_poll_loop(),
            self._classic_inquiry_loop(),
            self.bus.heartbeat_loop(HEARTBEAT_INTERVAL),
        )

    async def _ble_poll_loop(self) -> None:
        while self._running:
            try:
                # Prefer btmon (richer data) over plain lescan
                if self._use_btmon:
                    raw_records = await self._hci.read_btmon_events()
                else:
                    raw_records = await self._hci.read_lescan_lines()

                for raw in raw_records:
                    await self._process_raw(raw)

            except Exception as e:
                self.log.error("ble_poll_error", error=str(e))

            await asyncio.sleep(BLE_SCAN_INTERVAL_SEC)

    async def _classic_inquiry_loop(self) -> None:
        """Periodic classic BT inquiry — slower but catches non-BLE devices."""
        # Initial delay so BLE has a chance to establish baseline first
        await asyncio.sleep(30)
        while self._running:
            try:
                devices = await classic_bt_inquiry(self.iface, self.log)
                for d in devices:
                    await self._process_raw(d)
            except Exception as e:
                self.log.error("classic_inquiry_error", error=str(e))
            await asyncio.sleep(CLASSIC_SCAN_INTERVAL)

    async def _process_raw(self, raw: dict) -> None:
        rec = build_device_record(raw, self.cfg.node_id)
        if rec is None:
            return

        await self.bus.publish_raw("ble", rec)

        if rec.device_key not in self._seen:
            self._seen.add(rec.device_key)
            self.log.info("bt_device_first_seen",
                           mac=rec.mac_address,
                           class_=rec.device_class,
                           vendor=rec.vendor_oui,
                           name=raw.get("name"),
                           rssi=rec.rssi)

    async def teardown(self) -> None:
        self._running = False
        self._hci.stop()
        await self.db.write_system_event("bt_scanner_stop", "Bluetooth scanner stopped",
                                          {"total_seen": len(self._seen)})
        await self.db.close()
        self.bus.disconnect()


# ── Entry point ───────────────────────────────────────────────────────────────

async def main() -> None:
    cfg     = EatanConfig()
    scanner = BTScanner(cfg)

    try:
        await scanner.setup()
        await scanner.run()
    except KeyboardInterrupt:
        pass
    finally:
        await scanner.teardown()


if __name__ == "__main__":
    asyncio.run(main())
