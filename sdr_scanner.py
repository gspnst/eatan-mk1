#!/usr/bin/env python3
"""
EATAN — SDR Scanner Module
eatan/modules/sdr/sdr_scanner.py

Two concurrent sub-scanners:

1. IoT Decoder  — runs rtl_433 as a subprocess, parses its JSON output.
   Catches: tyre pressure sensors, weather stations, smart meters, keyfobs,
            doorbells, baby monitors, garage door openers, and ~200 other
            common IoT/ISM-band devices.
   Published topic: eatan/raw/sdr_iot

2. Wideband Monitor — uses pyrtlsdr to sweep the 25 MHz – 1.7 GHz range
   in chunks, logs FFT power peaks, and detects carrier anomalies.
   Published topic: eatan/raw/rf_spectrum

Run:
    sudo ~/eatan/.venv/bin/python \
         ~/eatan/modules/sdr/sdr_scanner.py
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import AsyncIterator

import numpy as np

# Lazy import of rtlsdr — gracefully degrade if missing
try:
    from rtlsdr import RtlSdr
    RTL_AVAILABLE = True
except ImportError:
    RTL_AVAILABLE = False

sys.path.insert(0, str(Path(__file__).parent.parent))
from eatan_bus import (
    EatanBus, EatanConfig, EatanDB, DeviceRecord,
    AlertRecord, now_ms, configure_logging,
)

# ── Constants ─────────────────────────────────────────────────────────────────

MODULE_NAME = "sdr_scanner"

# rtl_433 IoT decoding
RTL433_FREQ     = 433.92e6   # Primary ISM band for most European IoT devices
RTL433_FREQ_868 = 868.0e6   # European LoRa / smart meters
RTL433_FREQ_915 = 915.0e6   # US ISM (useful for imported devices)
RTL433_SAMPLE_RATE = 250000

# Wideband sweep
SWEEP_BANDS: list[tuple[float, float, float]] = [
    # (start_hz, stop_hz, step_hz)
    (80.0e6,   108.0e6,  500e3),    # FM broadcast (environment reference)
    (108.0e6,  136.0e6,  500e3),    # Air band
    (136.0e6,  175.0e6,  500e3),    # VHF high (APRS, marine, etc.)
    (400.0e6,  470.0e6,  500e3),    # UHF (PMR446, LPD, etc.)
    (433.0e6,  435.0e6,  50e3),     # ISM 433 (high resolution)
    (850.0e6,  900.0e6,  1e6),      # GSM 850 / cellular
    (925.0e6,  960.0e6,  500e3),    # GSM 900 downlink
    (1090.0e6, 1092.0e6, 500e3),    # ADS-B / Mode-S
    (1575.42e6,1576.0e6, 100e3),    # GPS L1
]

FFT_SIZE          = 1024
SAMPLES_PER_CHUNK = FFT_SIZE * 8
SWEEP_INTERVAL    = 60.0     # seconds between full sweeps
PEAK_THRESHOLD_DB = -40.0    # dBFS — peaks above this are logged


# ── Helpers ───────────────────────────────────────────────────────────────────

def check_root() -> None:
    if os.geteuid() != 0:
        print("ERROR: sdr_scanner must run as root")
        sys.exit(1)


def db_to_power(samples: np.ndarray) -> np.ndarray:
    """Convert complex IQ samples to dBFS power spectrum via FFT."""
    window  = np.blackman(len(samples))
    fft_out = np.fft.fftshift(np.fft.fft(samples * window, n=FFT_SIZE))
    power   = 20 * np.log10(np.abs(fft_out) / FFT_SIZE + 1e-12)
    return power


def freq_label(hz: float) -> str:
    """Human-readable frequency string."""
    if hz >= 1e9:
        return f"{hz/1e9:.3f} GHz"
    if hz >= 1e6:
        return f"{hz/1e6:.3f} MHz"
    return f"{hz/1e3:.1f} kHz"


# ── rtl_433 IoT decoder ───────────────────────────────────────────────────────

class IotDecoder:
    """
    Runs rtl_433 as a managed subprocess and yields decoded JSON records.
    rtl_433 can decode ~250+ common IoT protocols out of the box.
    """

    def __init__(self, device_index: int = 0, ppm: int = 0):
        self.device_index = device_index
        self.ppm          = ppm
        self._procs: list[subprocess.Popen] = []

    def _build_cmd(self, frequency: float) -> list[str]:
        cmd = [
            "rtl_433",
            "-d", str(self.device_index),
            "-f", str(int(frequency)),
            "-s", str(RTL433_SAMPLE_RATE),
            "-F", "json",           # JSON output per decoded packet
            "-M", "time:usec",      # microsecond timestamps
            "-M", "level",          # include signal level
            "-M", "noise",          # include noise floor
            "-R", "0",              # enable all built-in protocols
        ]
        if self.ppm != 0:
            cmd += ["-p", str(self.ppm)]
        return cmd

    async def stream(self, frequency: float) -> AsyncIterator[dict]:
        """Async generator — yields decoded rtl_433 records."""
        if not shutil.which("rtl_433"):
            return

        cmd  = self._build_cmd(frequency)
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        self._procs.append(proc)

        try:
            while True:
                line = await proc.stdout.readline()
                if not line:
                    break
                try:
                    record = json.loads(line.decode("utf-8", errors="replace").strip())
                    yield record
                except json.JSONDecodeError:
                    continue
        finally:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=3)
            except asyncio.TimeoutError:
                proc.kill()
            if proc in self._procs:
                self._procs.remove(proc)

    def stop_all(self) -> None:
        for proc in self._procs:
            try:
                proc.terminate()
            except Exception:
                pass


def parse_iot_record(raw: dict) -> DeviceRecord | None:
    """Convert an rtl_433 JSON record to a DeviceRecord."""
    # rtl_433 records always have at least a model field
    model = raw.get("model", "")
    if not model:
        return None

    # Build a stable device key from available identifiers
    # Priority: id > channel > brand+model
    dev_id  = raw.get("id")
    channel = raw.get("channel")
    freq    = raw.get("freq")

    parts = [model]
    if dev_id is not None:
        parts.append(str(dev_id))
    if channel is not None:
        parts.append(f"ch{channel}")

    device_key = "sdr_iot:" + ":".join(parts).replace(" ", "_").lower()

    # Classify by model name heuristics
    model_lower = model.lower()
    if any(k in model_lower for k in ("tpms", "tire", "tyre")):
        dev_class = "TPMS"
    elif any(k in model_lower for k in ("weather", "temp", "humidity", "thermo")):
        dev_class = "weather_sensor"
    elif any(k in model_lower for k in ("meter", "energy", "power")):
        dev_class = "smart_meter"
    elif any(k in model_lower for k in ("door", "bell", "gate", "garage")):
        dev_class = "access_device"
    elif any(k in model_lower for k in ("remote", "keyfob", "key fob")):
        dev_class = "keyfob"
    elif any(k in model_lower for k in ("smoke", "co ", "carbon")):
        dev_class = "safety_sensor"
    else:
        dev_class = "IoT"

    rssi = raw.get("rssi") or raw.get("snr") or raw.get("signal")

    return DeviceRecord(
        device_key   = device_key,
        sensor_type  = "sdr_iot",
        timestamp    = now_ms(),
        rssi         = float(rssi) if rssi is not None else None,
        device_class = dev_class,
        frequency    = float(freq) if freq else None,
        raw_data     = raw,
    )


# ── Wideband RF sweep ─────────────────────────────────────────────────────────

@dataclass
class SpectrumSnapshot:
    """A single FFT snapshot at a given centre frequency."""
    centre_hz:    float
    timestamp:    int
    peak_db:      float
    peak_offset:  float    # Hz offset of peak from centre
    noise_floor:  float
    power_array:  list[float]   # dBFS per FFT bin
    sample_rate:  float


class WidebandMonitor:
    """
    Uses pyrtlsdr to perform wideband FFT sweeps.
    Does NOT conflict with rtl_433 — they must share the device by time-slicing.

    When IoT decoder is active on device 0, this runs on device 1 (if present),
    or it alternates with the IoT decoder via a lock.
    """

    def __init__(self, device_index: int = 0, ppm: int = 0,
                 gain: str | float = "auto"):
        self.device_index = device_index
        self.ppm          = ppm
        self.gain         = gain
        self._lock        = asyncio.Lock()   # serialise SDR access

    async def sweep_band(self, start: float, stop: float,
                          step: float) -> list[SpectrumSnapshot]:
        """Sweep a frequency range and return snapshots for each step."""
        if not RTL_AVAILABLE:
            return []

        snapshots: list[SpectrumSnapshot] = []
        freqs = np.arange(start, stop, step)

        async with self._lock:
            sdr = RtlSdr(device_index=self.device_index)
            try:
                sdr.ppm_error     = self.ppm
                sdr.sample_rate   = 2.4e6

                if self.gain == "auto":
                    sdr.gain = "auto"
                else:
                    sdr.gain = float(self.gain)

                for centre in freqs:
                    sdr.center_freq = centre
                    await asyncio.sleep(0.05)   # let AGC settle

                    # Collect samples in a thread to avoid blocking event loop
                    samples = await asyncio.get_event_loop().run_in_executor(
                        None, lambda: sdr.read_samples(SAMPLES_PER_CHUNK)
                    )
                    power = db_to_power(np.array(samples))

                    peak_db     = float(np.max(power))
                    noise_floor = float(np.percentile(power, 10))
                    peak_bin    = int(np.argmax(power))
                    # Convert bin index to frequency offset
                    peak_offset = (peak_bin - FFT_SIZE // 2) * (sdr.sample_rate / FFT_SIZE)

                    snap = SpectrumSnapshot(
                        centre_hz    = centre,
                        timestamp    = now_ms(),
                        peak_db      = peak_db,
                        peak_offset  = peak_offset,
                        noise_floor  = noise_floor,
                        power_array  = power.tolist(),
                        sample_rate  = float(sdr.sample_rate),
                    )
                    if peak_db > PEAK_THRESHOLD_DB:
                        snapshots.append(snap)

            finally:
                sdr.close()

        return snapshots

    def snapshot_to_device_record(self, snap: SpectrumSnapshot) -> DeviceRecord:
        actual_freq = snap.centre_hz + snap.peak_offset
        return DeviceRecord(
            device_key   = f"rf:{freq_label(actual_freq).replace(' ', '')}",
            sensor_type  = "rf_spectrum",
            timestamp    = snap.timestamp,
            rssi         = snap.peak_db,
            frequency    = actual_freq,
            device_class = "rf_emission",
            raw_data     = {
                "centre_hz":   snap.centre_hz,
                "peak_db":     snap.peak_db,
                "noise_floor": snap.noise_floor,
                "peak_offset": snap.peak_offset,
                "sample_rate": snap.sample_rate,
                # Store compressed power: only top-N bins to keep payload small
                "peak_bins": sorted(
                    enumerate(snap.power_array),
                    key=lambda x: x[1], reverse=True
                )[:10],
            },
        )


# ── Main SDR Scanner ──────────────────────────────────────────────────────────

class SDRScanner:

    def __init__(self, cfg: EatanConfig):
        self.cfg      = cfg
        self.bus      = EatanBus(cfg, MODULE_NAME)
        self.db       = EatanDB(cfg.db_path)
        self.log      = configure_logging(MODULE_NAME, cfg.log_level)
        self.dev_idx  = cfg.get_int("SDR_DEVICE_INDEX", 0)
        self.ppm      = cfg.get_int("SDR_PPM_CORRECTION", 0)
        self.gain     = cfg.get("SDR_GAIN", "auto")
        self._decoder = IotDecoder(device_index=self.dev_idx, ppm=self.ppm)
        self._monitor = WidebandMonitor(device_index=self.dev_idx,
                                         ppm=self.ppm, gain=self.gain)
        self._seen_iot: set[str] = set()
        self._running  = False

    async def setup(self) -> None:
        await self.db.connect()
        await self.bus.connect()

        if not shutil.which("rtl_433"):
            self.log.warning("rtl_433_not_found",
                             hint="Install: sudo apt install rtl-433")
        if not RTL_AVAILABLE:
            self.log.warning("pyrtlsdr_not_available",
                             hint="Install: pip install pyrtlsdr")

        await self.db.write_system_event("sdr_scanner_start", "SDR scanner started",
                                          {"device_index": self.dev_idx, "ppm": self.ppm})

    async def run(self) -> None:
        self._running = True
        self.log.info("sdr_scanner_running",
                       device_index=self.dev_idx,
                       ppm_correction=self.ppm,
                       gain=self.gain)

        tasks: list[asyncio.Task] = [
            asyncio.create_task(self.bus.heartbeat_loop(30)),
        ]

        if shutil.which("rtl_433"):
            # Run IoT decoder on primary ISM bands concurrently
            # Note: only one rtl_433 process can own the dongle at a time.
            # We run 433 MHz primary; add more frequencies via frequency hopping
            # in a future iteration.
            tasks.append(asyncio.create_task(self._iot_decode_loop(RTL433_FREQ)))
        else:
            self.log.warning("iot_decoder_disabled", reason="rtl_433 not installed")

        if RTL_AVAILABLE:
            tasks.append(asyncio.create_task(self._wideband_sweep_loop()))
        else:
            self.log.warning("wideband_monitor_disabled", reason="pyrtlsdr not available")

        if not tasks[1:]:
            self.log.error("no_sdr_backends_available",
                           hint="Install rtl_433 and/or pyrtlsdr")

        await asyncio.gather(*tasks)

    async def _iot_decode_loop(self, frequency: float) -> None:
        """Stream decoded IoT packets from rtl_433."""
        self.log.info("iot_decoder_started", frequency=freq_label(frequency))
        while self._running:
            try:
                async for raw in self._decoder.stream(frequency):
                    rec = parse_iot_record(raw)
                    if rec is None:
                        continue

                    rec.node_id = self.cfg.node_id
                    await self.bus.publish_raw("sdr_iot", rec)

                    is_new = rec.device_key not in self._seen_iot
                    if is_new:
                        self._seen_iot.add(rec.device_key)
                        self.log.info("iot_device_first_seen",
                                       model=raw.get("model"),
                                       device_key=rec.device_key,
                                       class_=rec.device_class,
                                       rssi=rec.rssi)

            except Exception as e:
                self.log.error("iot_decode_error", error=str(e))
                await asyncio.sleep(5)

    async def _wideband_sweep_loop(self) -> None:
        """Periodically sweep the RF environment and publish spectrum snapshots."""
        self.log.info("wideband_monitor_started",
                       bands=len(SWEEP_BANDS),
                       interval_sec=SWEEP_INTERVAL)
        while self._running:
            for start, stop, step in SWEEP_BANDS:
                if not self._running:
                    break
                try:
                    snapshots = await self._monitor.sweep_band(start, stop, step)
                    for snap in snapshots:
                        rec = self._monitor.snapshot_to_device_record(snap)
                        rec.node_id = self.cfg.node_id
                        await self.bus.publish_raw("rf_spectrum", rec)

                    if snapshots:
                        self.log.debug("band_sweep_complete",
                                        band=f"{freq_label(start)}-{freq_label(stop)}",
                                        peaks_found=len(snapshots))
                except Exception as e:
                    self.log.error("sweep_error",
                                   band=f"{freq_label(start)}-{freq_label(stop)}",
                                   error=str(e))

            self.log.info("wideband_sweep_cycle_complete",
                           next_in_sec=SWEEP_INTERVAL)
            await asyncio.sleep(SWEEP_INTERVAL)

    async def teardown(self) -> None:
        self._running = False
        self._decoder.stop_all()
        await self.db.write_system_event("sdr_scanner_stop", "SDR scanner stopped")
        await self.db.close()
        self.bus.disconnect()


# ── Entry point ───────────────────────────────────────────────────────────────

async def main() -> None:
    check_root()
    cfg     = EatanConfig()
    scanner = SDRScanner(cfg)

    try:
        await scanner.setup()
        await scanner.run()
    except KeyboardInterrupt:
        pass
    finally:
        await scanner.teardown()


if __name__ == "__main__":
    asyncio.run(main())
