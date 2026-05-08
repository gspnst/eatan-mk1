#!/usr/bin/env python3
"""
EATAN — WiFi Scanner Module
eatan/modules/wifi/wifi_scanner.py

Passively collects 802.11 device data by integrating with Kismet's REST API.
Falls back to parsing airodump-ng CSV output if Kismet is unavailable.

Published topic:  eatan/raw/wifi
Payload model:    DeviceRecord (sensor_type="wifi")

Run:
    sudo ~/eatan/.venv/bin/python \
         ~/eatan/modules/wifi/wifi_scanner.py

Requires:
    - WiFi adapter in monitor mode (script will attempt to set this up)
    - Kismet running OR aircrack-ng installed
"""

from __future__ import annotations

import asyncio
import csv
import io
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import aiohttp

# Add parent directory to path so we can import eatan_bus
sys.path.insert(0, str(Path(__file__).parent.parent))
from eatan_bus import (
    EatanBus, EatanConfig, EatanDB, DeviceRecord,
    AlertRecord, Topics, now_ms, lookup_vendor, configure_logging,
)

# ── Constants ─────────────────────────────────────────────────────────────────

MODULE_NAME  = "wifi_scanner"
KISMET_PORT  = 2501
KISMET_URL   = f"http://127.0.0.1:{KISMET_PORT}"
POLL_INTERVAL = 5.0   # seconds between Kismet polls
AIRODUMP_CSV  = "/tmp/eatan_airodump-01.csv"

# 802.11 device classes
CLASS_AP     = "AP"
CLASS_CLIENT = "client"
CLASS_PROBE  = "probe"   # device seen only via probe requests
CLASS_ADHOC  = "adhoc"
CLASS_UNKNOWN = "unknown"

# Kismet device type codes
KISMET_TYPE_AP     = "Wi-Fi AP"
KISMET_TYPE_CLIENT = "Wi-Fi Client"
KISMET_TYPE_ADHOC  = "Wi-Fi Ad-Hoc"
KISMET_TYPE_BRIDGE = "Wi-Fi Bridge"


# ── Monitor mode management ───────────────────────────────────────────────────

def check_root() -> None:
    if os.geteuid() != 0:
        print("ERROR: wifi_scanner must run as root (for monitor mode)")
        print("  sudo ~/eatan/.venv/bin/python ~/eatan/modules/wifi/wifi_scanner.py")
        sys.exit(1)


def get_wireless_interfaces() -> list[str]:
    """Return list of wireless interface names."""
    ifaces = []
    try:
        result = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=5)
        for line in result.stdout.splitlines():
            if "Interface" in line:
                ifaces.append(line.split()[-1])
    except Exception:
        pass
    return ifaces


def get_interface_mode(iface: str) -> str:
    """Return current mode of a wireless interface."""
    try:
        result = subprocess.run(
            ["iw", "dev", iface, "info"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            if "type" in line:
                return line.split()[-1].lower()
    except Exception:
        pass
    return "unknown"


def set_monitor_mode(iface: str, mon_iface: str, log) -> str | None:
    """
    Attempt to put a WiFi interface into monitor mode.
    Returns the monitor interface name on success, None on failure.

    Tries airmon-ng first (cleanest), then manual iw method.
    """
    log.info("setting_monitor_mode", interface=iface)

    # Method 1: airmon-ng (preferred — handles driver quirks)
    if shutil.which("airmon-ng"):
        try:
            subprocess.run(["airmon-ng", "check", "kill"],
                           capture_output=True, timeout=10)
            result = subprocess.run(
                ["airmon-ng", "start", iface],
                capture_output=True, text=True, timeout=15,
            )
            # airmon-ng usually creates wlan1mon or similar
            for candidate in [f"{iface}mon", mon_iface, "wlan0mon", "wlan1mon"]:
                mode = get_interface_mode(candidate)
                if mode == "monitor":
                    log.info("monitor_mode_set", interface=candidate, method="airmon-ng")
                    return candidate
        except Exception as e:
            log.warning("airmon_ng_failed", error=str(e))

    # Method 2: manual iw
    try:
        subprocess.run(["ip", "link", "set", iface, "down"],
                       capture_output=True, timeout=5)
        subprocess.run(["iw", "dev", iface, "set", "type", "monitor"],
                       capture_output=True, timeout=5)
        subprocess.run(["ip", "link", "set", iface, "up"],
                       capture_output=True, timeout=5)
        mode = get_interface_mode(iface)
        if mode == "monitor":
            log.info("monitor_mode_set", interface=iface, method="iw")
            return iface
    except Exception as e:
        log.warning("iw_monitor_failed", error=str(e))

    log.error("monitor_mode_failed", interface=iface)
    return None


def restore_managed_mode(mon_iface: str, log) -> None:
    """Restore interface to managed mode on shutdown."""
    log.info("restoring_managed_mode", interface=mon_iface)
    if shutil.which("airmon-ng"):
        subprocess.run(["airmon-ng", "stop", mon_iface],
                       capture_output=True, timeout=10)
    else:
        subprocess.run(["ip", "link", "set", mon_iface, "down"],
                       capture_output=True, timeout=5)
        subprocess.run(["iw", "dev", mon_iface, "set", "type", "managed"],
                       capture_output=True, timeout=5)
        subprocess.run(["ip", "link", "set", mon_iface, "up"],
                       capture_output=True, timeout=5)


# ── Kismet integration ────────────────────────────────────────────────────────

class KismetPoller:
    """
    Polls Kismet's REST API for device records.
    Kismet must be running separately (we don't manage its lifecycle here).
    """

    # Fields we request from Kismet — minimises response size
    DEVICE_FIELDS = [
        "kismet.device.base.macaddr",
        "kismet.device.base.type",
        "kismet.device.base.signal/kismet.common.signal.last_signal",
        "kismet.device.base.channel",
        "kismet.device.base.frequency",
        "kismet.device.base.manuf",
        "kismet.device.base.first_time",
        "kismet.device.base.last_time",
        "dot11.device/dot11.device.last_beaconed_ssid_record/dot11.advertisedssid.ssid",
        "dot11.device/dot11.device.probed_ssid_map",
    ]

    def __init__(self, base_url: str = KISMET_URL,
                 username: str = "kismet", password: str = "kismet"):
        self.url      = base_url
        self.auth     = aiohttp.BasicAuth(username, password)
        self._session: aiohttp.ClientSession | None = None

    async def start(self) -> None:
        self._session = aiohttp.ClientSession(auth=self.auth)

    async def stop(self) -> None:
        if self._session:
            await self._session.close()

    async def is_alive(self) -> bool:
        if not self._session:
            return False
        try:
            async with self._session.get(
                f"{self.url}/system/status.json", timeout=aiohttp.ClientTimeout(total=3)
            ) as r:
                return r.status == 200
        except Exception:
            return False

    async def get_devices(self) -> list[dict]:
        """Fetch all current devices from Kismet."""
        if not self._session:
            return []
        try:
            payload = {
                "fields": self.DEVICE_FIELDS,
            }
            async with self._session.post(
                f"{self.url}/devices/views/all/devices.json",
                json=payload,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as r:
                if r.status == 200:
                    return await r.json(content_type=None)
                return []
        except Exception:
            return []

    def parse_device(self, raw: dict) -> DeviceRecord | None:
        """Convert a Kismet device record to an EATAN DeviceRecord."""
        mac = raw.get("kismet.device.base.macaddr", "")
        if not mac:
            return None

        device_type = raw.get("kismet.device.base.type", "")
        if "AP" in device_type:
            dev_class = CLASS_AP
        elif "Client" in device_type:
            dev_class = CLASS_CLIENT
        elif "Ad-Hoc" in device_type:
            dev_class = CLASS_ADHOC
        else:
            dev_class = CLASS_UNKNOWN

        manuf  = raw.get("kismet.device.base.manuf") or lookup_vendor(mac) or "Unknown"
        ssid   = raw.get(
            "dot11.device/dot11.device.last_beaconed_ssid_record/dot11.advertisedssid.ssid"
        )
        signal = raw.get(
            "kismet.device.base.signal/kismet.common.signal.last_signal"
        )
        chan   = raw.get("kismet.device.base.channel")
        freq   = raw.get("kismet.device.base.frequency")

        # Probe requests (clients hunting for known SSIDs)
        probes: list[str] = []
        probe_map = raw.get("dot11.device/dot11.device.probed_ssid_map") or {}
        if isinstance(probe_map, dict):
            for v in probe_map.values():
                if isinstance(v, dict):
                    p = v.get("dot11.probedssid.ssid")
                    if p:
                        probes.append(p)
        elif isinstance(probe_map, list):
            for entry in probe_map:
                if isinstance(entry, dict):
                    p = entry.get("dot11.probedssid.ssid")
                    if p:
                        probes.append(p)

        return DeviceRecord(
            device_key   = f"wifi:{mac}",
            sensor_type  = "wifi",
            timestamp    = now_ms(),
            rssi         = float(signal) if signal is not None else None,
            mac_address  = mac,
            vendor_oui   = manuf,
            device_class = dev_class,
            ssid         = ssid,
            channel      = int(chan) if chan else None,
            frequency    = float(freq) if freq else None,
            raw_data     = {
                "kismet_type": device_type,
                "probe_ssids": probes,
                "first_seen_kismet": raw.get("kismet.device.base.first_time"),
            },
        )


# ── Airodump-ng fallback ──────────────────────────────────────────────────────

class AirodumpRunner:
    """
    Runs airodump-ng in the background and tails its CSV output.
    Used when Kismet is not available.
    """

    def __init__(self, interface: str, output_prefix: str = "/tmp/eatan_airodump"):
        self.interface = interface
        self.prefix    = output_prefix
        self.csv_path  = f"{output_prefix}-01.csv"
        self._proc: subprocess.Popen | None = None

    def start(self) -> bool:
        if not shutil.which("airodump-ng"):
            return False
        cmd = [
            "airodump-ng",
            "--write", self.prefix,
            "--output-format", "csv",
            "--write-interval", "5",
            "--band", "abg",      # scan 2.4 GHz + 5 GHz
            self.interface,
        ]
        self._proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        return True

    def stop(self) -> None:
        if self._proc:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()

    def read_devices(self) -> list[DeviceRecord]:
        """Parse the airodump CSV and return device records."""
        if not Path(self.csv_path).exists():
            return []
        records: list[DeviceRecord] = []
        try:
            content = Path(self.csv_path).read_text(errors="replace")
        except Exception:
            return []

        # Airodump CSV has two sections separated by a blank line:
        # 1. Access Points
        # 2. Stations (clients)
        sections = re.split(r"\n\s*\n", content, maxsplit=1)
        ts = now_ms()

        # -- Parse APs --
        try:
            ap_reader = csv.DictReader(io.StringIO(sections[0]))
            for row in ap_reader:
                mac = row.get(" BSSID", "").strip()
                if not mac or mac == "BSSID":
                    continue
                ssid  = row.get("                          ESSID", "").strip()
                power = row.get(" Power", "").strip()
                chan  = row.get("  CH", "").strip()
                vendor = lookup_vendor(mac) or "Unknown"
                records.append(DeviceRecord(
                    device_key   = f"wifi:{mac}",
                    sensor_type  = "wifi",
                    timestamp    = ts,
                    rssi         = float(power) if power and power.lstrip("-").isdigit() else None,
                    mac_address  = mac,
                    vendor_oui   = vendor,
                    device_class = CLASS_AP,
                    ssid         = ssid or None,
                    channel      = int(chan) if chan.isdigit() else None,
                    raw_data     = {"source": "airodump", "ssid": ssid},
                ))
        except Exception:
            pass

        # -- Parse Stations --
        if len(sections) > 1:
            try:
                sta_reader = csv.DictReader(io.StringIO(sections[1]))
                for row in sta_reader:
                    mac = row.get(" Station MAC", "").strip()
                    if not mac or mac == "Station MAC":
                        continue
                    power   = row.get(" Power", "").strip()
                    probed  = row.get("               Probed ESSIDs", "").strip()
                    vendor  = lookup_vendor(mac) or "Unknown"
                    records.append(DeviceRecord(
                        device_key   = f"wifi:{mac}",
                        sensor_type  = "wifi",
                        timestamp    = ts,
                        rssi         = float(power) if power and power.lstrip("-").isdigit() else None,
                        mac_address  = mac,
                        vendor_oui   = vendor,
                        device_class = CLASS_CLIENT,
                        raw_data     = {"source": "airodump", "probed_ssids": probed},
                    ))
            except Exception:
                pass

        return records


# ── Channel hopper ────────────────────────────────────────────────────────────

async def channel_hopper(interface: str, log, interval: float = 0.5) -> None:
    """
    Cycles through 2.4 GHz and 5 GHz channels.
    Only used when running with airodump-ng (Kismet manages hopping itself).
    """
    channels_24 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
    channels_5  = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104,
                   108, 112, 116, 120, 124, 128, 132, 136, 140]
    all_channels = channels_24 + channels_5

    while True:
        for ch in all_channels:
            try:
                subprocess.run(
                    ["iw", "dev", interface, "set", "channel", str(ch)],
                    capture_output=True, timeout=2,
                )
            except Exception:
                pass
            await asyncio.sleep(interval)


# ── Main scanner ──────────────────────────────────────────────────────────────

class WiFiScanner:

    def __init__(self, cfg: EatanConfig):
        self.cfg      = cfg
        self.bus      = EatanBus(cfg, MODULE_NAME)
        self.db       = EatanDB(cfg.db_path)
        self.log      = configure_logging(MODULE_NAME, cfg.log_level)
        self.iface    = cfg.get("WIFI_INTERFACE", "wlan1")
        self.mon_iface = cfg.get("WIFI_MONITOR_INTERFACE", "wlan1mon")
        self._kismet  = KismetPoller()
        self._airodump: AirodumpRunner | None = None
        self._use_kismet = False
        self._seen_keys: set[str] = set()   # in-memory cache to reduce DB load
        self._running = False

    async def setup(self) -> None:
        """Prepare hardware and connections."""
        # DB and MQTT
        await self.db.connect()
        await self.bus.connect()

        # Detect available interfaces
        ifaces = get_wireless_interfaces()
        self.log.info("wireless_interfaces_found", interfaces=ifaces)

        if not ifaces:
            self.log.error("no_wireless_interfaces",
                           hint="Plug in the Alfa adapter and check drivers")
            raise RuntimeError("No wireless interfaces found")

        # Determine which interface to use
        target = self.iface if self.iface in ifaces else ifaces[0]

        # Set monitor mode
        mon = set_monitor_mode(target, self.mon_iface, self.log)
        if mon:
            self.mon_iface = mon
            self.log.info("monitor_interface_ready", interface=mon)
        else:
            self.log.warning("monitor_mode_unavailable",
                             hint="Continuing with managed mode — passive capture limited")
            self.mon_iface = target

        # Try Kismet
        await self._kismet.start()
        self._use_kismet = await self._kismet.is_alive()
        if self._use_kismet:
            self.log.info("kismet_available", url=KISMET_URL)
        else:
            self.log.warning("kismet_not_available",
                             fallback="airodump-ng",
                             hint="Start Kismet for richer data: sudo kismet -c " + self.mon_iface)
            self._airodump = AirodumpRunner(self.mon_iface)
            if not self._airodump.start():
                self.log.error("airodump_not_available",
                               hint="Install aircrack-ng: sudo apt install aircrack-ng")

        await self.db.write_system_event("wifi_scanner_start",
                                          f"WiFi scanner started on {self.mon_iface}",
                                          {"interface": self.mon_iface,
                                           "mode": "kismet" if self._use_kismet else "airodump"})

    async def run(self) -> None:
        self._running = True
        self.log.info("wifi_scanner_running",
                       interface=self.mon_iface,
                       backend="kismet" if self._use_kismet else "airodump-ng",
                       poll_interval=POLL_INTERVAL)

        tasks = [
            asyncio.create_task(self._poll_loop()),
            asyncio.create_task(self.bus.heartbeat_loop(30)),
        ]
        if not self._use_kismet:
            # Channel hopper only needed when driving airodump ourselves
            tasks.append(asyncio.create_task(
                channel_hopper(self.mon_iface, self.log)
            ))

        await asyncio.gather(*tasks)

    async def _poll_loop(self) -> None:
        """Main polling coroutine."""
        while self._running:
            try:
                if self._use_kismet:
                    # Check Kismet is still alive
                    if not await self._kismet.is_alive():
                        self.log.warning("kismet_lost",
                                         action="falling_back_to_airodump")
                        self._use_kismet = False
                        if self._airodump:
                            self._airodump.start()
                    else:
                        devices = await self._kismet.get_devices()
                        records = [
                            r for raw in devices
                            if (r := self._kismet.parse_device(raw)) is not None
                        ]
                        await self._process_records(records)
                else:
                    if self._airodump:
                        records = self._airodump.read_devices()
                        await self._process_records(records)

            except Exception as e:
                self.log.error("poll_error", error=str(e))

            await asyncio.sleep(POLL_INTERVAL)

    async def _process_records(self, records: list[DeviceRecord]) -> None:
        """Publish each record to MQTT and write to DB."""
        for rec in records:
            # Set node ID
            rec.node_id = self.cfg.node_id

            # Publish raw record to MQTT bus
            await self.bus.publish_raw("wifi", rec)

            # Track new vs seen
            if rec.device_key not in self._seen_keys:
                self._seen_keys.add(rec.device_key)
                self.log.info("wifi_device_first_seen",
                               mac=rec.mac_address,
                               vendor=rec.vendor_oui,
                               class_=rec.device_class,
                               ssid=rec.ssid,
                               rssi=rec.rssi)

        if records:
            self.log.debug("wifi_poll_complete", device_count=len(records))

    async def teardown(self) -> None:
        self._running = False
        if self._airodump:
            self._airodump.stop()
        await self._kismet.stop()
        restore_managed_mode(self.mon_iface, self.log)
        await self.db.write_system_event("wifi_scanner_stop", "WiFi scanner stopped")
        await self.db.close()
        self.bus.disconnect()


# ── Entry point ───────────────────────────────────────────────────────────────

async def main() -> None:
    check_root()
    cfg     = EatanConfig()
    scanner = WiFiScanner(cfg)

    try:
        await scanner.setup()
        await scanner.run()
    except KeyboardInterrupt:
        pass
    finally:
        await scanner.teardown()


if __name__ == "__main__":
    asyncio.run(main())
