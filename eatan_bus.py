"""
EATAN — Shared Bus Library
eatan/modules/eatan_bus.py

Every sensor module and analysis module imports this.
Provides:
  - Config loading from eatan.env
  - Structured logging
  - MQTT publish/subscribe helpers
  - SQLite async helpers
  - Common data models (dataclasses)
  - Heartbeat mixin
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import time
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Any, Callable, Awaitable

import paho.mqtt.client as mqtt
import aiosqlite
import structlog

# ── Logging setup ─────────────────────────────────────────────────────────────

def configure_logging(module_name: str, level: str = "INFO") -> structlog.BoundLogger:
    logging.basicConfig(
        format="%(message)s",
        level=getattr(logging, level.upper(), logging.INFO),
    )
    structlog.configure(
        processors=[
            structlog.stdlib.add_log_level,
            structlog.stdlib.add_logger_name,
            structlog.processors.TimeStamper(fmt="%Y-%m-%d %H:%M:%S", utc=False),
            structlog.dev.ConsoleRenderer(colors=True),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level.upper(), logging.INFO)
        ),
        logger_factory=structlog.PrintLoggerFactory(),
    )
    return structlog.get_logger(module_name)


# ── Config ────────────────────────────────────────────────────────────────────

class EatanConfig:
    """
    Loads configuration from eatan.env (dotenv format).
    Falls back to sensible defaults so modules can run even if the file
    isn't fully populated yet.
    """

    _DEFAULTS: dict[str, str] = {
        "EATAN_NODE_ID":          "node-alpha",
        "EATAN_ROOT":             str(Path.home() / "eatan"),
        "EATAN_DB":               str(Path.home() / "eatan/data/eatan.db"),
        "EATAN_LOG_DIR":          str(Path.home() / "eatan/data/logs"),
        "EATAN_CAPTURES_DIR":     str(Path.home() / "eatan/data/captures"),
        "MQTT_HOST":              "127.0.0.1",
        "MQTT_PORT":              "1883",
        "MQTT_TOPIC_PREFIX":      "eatan",
        "SDR_DEVICE_INDEX":       "0",
        "SDR_GAIN":               "auto",
        "SDR_SAMPLE_RATE":        "2400000",
        "SDR_PPM_CORRECTION":     "0",
        "WIFI_INTERFACE":         "wlan1",
        "WIFI_MONITOR_INTERFACE": "wlan1mon",
        "BT_INTERFACE":           "hci0",
        "BASELINE_DURATION_SEC":  "900",
        "ALERT_NEW_DEVICE":       "true",
        "API_HOST":               "0.0.0.0",
        "API_PORT":               "8888",
        "API_SECRET_KEY":         "CHANGE_ME",
        "LOG_LEVEL":              "INFO",
    }

    def __init__(self, env_path: str | None = None):
        # Resolve config file location
        if env_path:
            p = Path(env_path)
        else:
            p = Path.home() / "eatan" / "config" / "eatan.env"

        self._values: dict[str, str] = dict(self._DEFAULTS)

        if p.exists():
            for line in p.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, _, v = line.partition("=")
                    self._values[k.strip()] = v.strip()

        # Also honour real environment variables (override file)
        for k in self._DEFAULTS:
            if k in os.environ:
                self._values[k] = os.environ[k]

    def get(self, key: str, fallback: str = "") -> str:
        return self._values.get(key, fallback)

    def get_int(self, key: str, fallback: int = 0) -> int:
        try:
            return int(self._values.get(key, str(fallback)))
        except ValueError:
            return fallback

    def get_bool(self, key: str, fallback: bool = False) -> bool:
        return self._values.get(key, str(fallback)).lower() in ("true", "1", "yes")

    @property
    def mqtt_host(self) -> str:       return self.get("MQTT_HOST")
    @property
    def mqtt_port(self) -> int:       return self.get_int("MQTT_PORT", 1883)
    @property
    def prefix(self) -> str:          return self.get("MQTT_TOPIC_PREFIX", "eatan")
    @property
    def db_path(self) -> str:         return self.get("EATAN_DB")
    @property
    def node_id(self) -> str:         return self.get("EATAN_NODE_ID")
    @property
    def log_level(self) -> str:       return self.get("LOG_LEVEL", "INFO")
    @property
    def baseline_sec(self) -> int:    return self.get_int("BASELINE_DURATION_SEC", 900)
    @property
    def alert_new_device(self) -> bool: return self.get_bool("ALERT_NEW_DEVICE", True)


# ── MQTT Topics ───────────────────────────────────────────────────────────────

class Topics:
    """Centralised topic name builder — single source of truth."""

    def __init__(self, prefix: str = "eatan"):
        self.p = prefix

    # Raw sensor feeds
    def raw(self, sensor: str) -> str:
        return f"{self.p}/raw/{sensor}"

    # Processed events
    def event(self, kind: str) -> str:
        return f"{self.p}/events/{kind}"

    # Alerts by severity
    def alert(self, severity: str) -> str:
        return f"{self.p}/alerts/{severity.lower()}"

    # System / housekeeping
    def system(self, kind: str) -> str:
        return f"{self.p}/system/{kind}"

    # Wildcard subscriptions
    def all_raw(self) -> str:    return f"{self.p}/raw/#"
    def all_events(self) -> str: return f"{self.p}/events/#"
    def all_alerts(self) -> str: return f"{self.p}/alerts/#"


# ── Data Models ───────────────────────────────────────────────────────────────

def now_ms() -> int:
    """Current time in milliseconds."""
    return int(time.time() * 1000)


@dataclass
class DeviceRecord:
    """
    Canonical device representation published to eatan/events/device_seen
    and written to the devices + observations tables.
    """
    device_key:   str            # stable identifier (MAC, BLE addr, rtl_433 id…)
    sensor_type:  str            # wifi | ble | sdr_iot | adsb
    timestamp:    int            # ms since epoch
    rssi:         float | None   = None
    mac_address:  str | None     = None
    vendor_oui:   str | None     = None
    device_class: str | None     = None   # AP | client | IoT | unknown
    ssid:         str | None     = None
    channel:      int | None     = None
    frequency:    float | None   = None   # Hz
    raw_data:     dict           = field(default_factory=dict)
    node_id:      str            = "node-alpha"

    def to_json(self) -> str:
        return json.dumps(asdict(self), default=str)

    @classmethod
    def from_json(cls, data: str | bytes) -> "DeviceRecord":
        d = json.loads(data)
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


@dataclass
class AlertRecord:
    severity:   str        # INFO | WARN | CRIT
    alert_type: str        # new_device | known_hostile | anomaly | sweep_detected
    message:    str
    timestamp:  int        = field(default_factory=now_ms)
    device_key: str | None = None
    raw_data:   dict       = field(default_factory=dict)
    node_id:    str        = "node-alpha"

    def to_json(self) -> str:
        return json.dumps(asdict(self), default=str)


@dataclass
class Heartbeat:
    module:    str
    status:    str   # ok | degraded | error
    timestamp: int   = field(default_factory=now_ms)
    data:      dict  = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(asdict(self), default=str)


# ── MQTT Client wrapper ───────────────────────────────────────────────────────

MessageHandler = Callable[[str, dict], Awaitable[None]]


class EatanBus:
    """
    Async-friendly MQTT wrapper.

    Usage:
        bus = EatanBus(config, module_name="wifi_scanner")
        await bus.connect()
        await bus.publish_raw("wifi", device_record)
        bus.subscribe(topics.all_raw(), my_handler)
        await bus.loop_forever()
    """

    def __init__(self, config: EatanConfig, module_name: str):
        self.cfg     = config
        self.module  = module_name
        self.topics  = Topics(config.prefix)
        self.log     = configure_logging(module_name, config.log_level)
        self._client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id=f"eatan-{module_name}-{socket.gethostname()}",
        )
        self._handlers:  dict[str, list[MessageHandler]] = {}
        self._loop:      asyncio.AbstractEventLoop | None = None
        self._connected: bool = False

        self._client.on_connect    = self._on_connect
        self._client.on_disconnect = self._on_disconnect
        self._client.on_message    = self._on_message

    # ── Connection ────────────────────────────────────────────────────────────

    async def connect(self, retries: int = 10, delay: float = 3.0) -> None:
        self._loop = asyncio.get_running_loop()
        for attempt in range(1, retries + 1):
            try:
                self._client.connect(self.cfg.mqtt_host, self.cfg.mqtt_port, keepalive=30)
                self._client.loop_start()
                # Wait for on_connect callback
                for _ in range(20):
                    if self._connected:
                        break
                    await asyncio.sleep(0.1)
                if self._connected:
                    self.log.info("mqtt_connected",
                                  broker=self.cfg.mqtt_host, port=self.cfg.mqtt_port)
                    await self._publish_heartbeat("ok")
                    return
            except (ConnectionRefusedError, OSError) as e:
                self.log.warning("mqtt_connect_failed",
                                 attempt=attempt, max=retries, error=str(e))
                await asyncio.sleep(delay)
        raise RuntimeError(f"Could not connect to MQTT broker after {retries} attempts")

    def disconnect(self) -> None:
        self._client.loop_stop()
        self._client.disconnect()
        self.log.info("mqtt_disconnected")

    # ── Publish helpers ───────────────────────────────────────────────────────

    async def publish_raw(self, sensor: str, record: DeviceRecord) -> None:
        topic = self.topics.raw(sensor)
        self._publish(topic, record.to_json())

    async def publish_event(self, kind: str, payload: dict) -> None:
        topic = self.topics.event(kind)
        self._publish(topic, json.dumps(payload, default=str))

    async def publish_alert(self, alert: AlertRecord) -> None:
        topic = self.topics.alert(alert.severity)
        self._publish(topic, alert.to_json())

    def _publish(self, topic: str, payload: str) -> None:
        result = self._client.publish(topic, payload, qos=0)
        if result.rc != mqtt.MQTT_ERR_SUCCESS:
            self.log.warning("mqtt_publish_failed", topic=topic, rc=result.rc)

    async def _publish_heartbeat(self, status: str = "ok", data: dict | None = None) -> None:
        hb = Heartbeat(module=self.module, status=status, data=data or {})
        self._publish(self.topics.system("heartbeat"), hb.to_json())

    # ── Subscribe helpers ─────────────────────────────────────────────────────

    def subscribe(self, topic: str, handler: MessageHandler) -> None:
        """Register an async handler for a topic pattern (wildcards supported)."""
        if topic not in self._handlers:
            self._handlers[topic] = []
            self._client.subscribe(topic, qos=0)
        self._handlers[topic].append(handler)

    # ── Periodic heartbeat ────────────────────────────────────────────────────

    async def heartbeat_loop(self, interval: float = 30.0) -> None:
        while True:
            await asyncio.sleep(interval)
            await self._publish_heartbeat("ok")

    # ── MQTT callbacks (called from paho thread) ───────────────────────────────

    def _on_connect(self, client, userdata, flags, rc, properties=None):
        if rc == 0:
            self._connected = True
            # Re-subscribe on reconnect
            for topic in self._handlers:
                client.subscribe(topic, qos=0)
        else:
            self.log.error("mqtt_on_connect_error", rc=rc)

    def _on_disconnect(self, client, userdata, disconnect_flags, rc, properties=None):
        self._connected = False
        if rc != 0:
            self.log.warning("mqtt_unexpected_disconnect", rc=rc)

    def _on_message(self, client, userdata, msg: mqtt.MQTTMessage):
        if self._loop is None or self._loop.is_closed():
            return
        try:
            payload = json.loads(msg.payload.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            payload = {"_raw": msg.payload.decode("utf-8", errors="replace")}

        topic = msg.topic
        # Find matching handlers (support wildcards via prefix match)
        for pattern, handlers in self._handlers.items():
            if self._topic_matches(pattern, topic):
                for handler in handlers:
                    asyncio.run_coroutine_threadsafe(
                        handler(topic, payload), self._loop
                    )

    @staticmethod
    def _topic_matches(pattern: str, topic: str) -> bool:
        """Simple MQTT wildcard matcher (+, #)."""
        if pattern == topic:
            return True
        pattern_parts = pattern.split("/")
        topic_parts   = topic.split("/")
        for i, pp in enumerate(pattern_parts):
            if pp == "#":
                return True
            if i >= len(topic_parts):
                return False
            if pp != "+" and pp != topic_parts[i]:
                return False
        return len(pattern_parts) == len(topic_parts)


# ── Database helpers ──────────────────────────────────────────────────────────

class EatanDB:
    """
    Async SQLite helper.
    Each module that needs DB access creates one instance.
    """

    def __init__(self, db_path: str):
        self.path = db_path
        self._db: aiosqlite.Connection | None = None

    async def connect(self) -> None:
        self._db = await aiosqlite.connect(self.path)
        self._db.row_factory = aiosqlite.Row
        await self._db.execute("PRAGMA journal_mode=WAL")
        await self._db.execute("PRAGMA foreign_keys=ON")
        await self._db.commit()

    async def close(self) -> None:
        if self._db:
            await self._db.close()

    async def upsert_device(self, rec: DeviceRecord) -> bool:
        """
        Insert or update a device record.
        Returns True if this is a genuinely new device.
        """
        if not self._db:
            raise RuntimeError("DB not connected")

        async with self._db.execute(
            "SELECT id, times_seen FROM devices WHERE device_key = ?",
            (rec.device_key,),
        ) as cur:
            row = await cur.fetchone()

        is_new = row is None

        if is_new:
            await self._db.execute(
                """
                INSERT INTO devices
                    (device_key, sensor_type, mac_address, vendor_oui,
                     device_class, first_seen, last_seen, times_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, 1)
                """,
                (rec.device_key, rec.sensor_type, rec.mac_address,
                 rec.vendor_oui, rec.device_class, rec.timestamp, rec.timestamp),
            )
        else:
            await self._db.execute(
                """
                UPDATE devices
                SET last_seen = ?, times_seen = times_seen + 1,
                    rssi = COALESCE(?, rssi)
                WHERE device_key = ?
                """,
                (rec.timestamp, rec.rssi, rec.device_key),
            )

        # Always write an observation row
        await self._db.execute(
            """
            INSERT INTO observations
                (device_key, sensor_type, timestamp, rssi,
                 channel, frequency, ssid, raw_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (rec.device_key, rec.sensor_type, rec.timestamp, rec.rssi,
             rec.channel, rec.frequency, rec.ssid, json.dumps(rec.raw_data)),
        )

        await self._db.commit()
        return is_new

    async def mark_baseline(self, device_key: str) -> None:
        if not self._db:
            return
        await self._db.execute(
            "UPDATE devices SET is_baseline = 1 WHERE device_key = ?",
            (device_key,),
        )
        await self._db.commit()

    async def write_alert(self, alert: AlertRecord) -> None:
        if not self._db:
            return
        await self._db.execute(
            """
            INSERT INTO alerts
                (timestamp, severity, alert_type, device_key, message, raw_data)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (alert.timestamp, alert.severity, alert.alert_type,
             alert.device_key, alert.message, json.dumps(alert.raw_data)),
        )
        await self._db.commit()

    async def write_system_event(self, event_type: str, message: str,
                                  data: dict | None = None) -> None:
        if not self._db:
            return
        await self._db.execute(
            "INSERT INTO system_events (timestamp, event_type, message, data) VALUES (?, ?, ?, ?)",
            (now_ms(), event_type, message, json.dumps(data or {})),
        )
        await self._db.commit()

    async def get_device_count(self, sensor_type: str | None = None) -> int:
        if not self._db:
            return 0
        query = "SELECT COUNT(*) FROM devices"
        params: tuple = ()
        if sensor_type:
            query += " WHERE sensor_type = ?"
            params = (sensor_type,)
        async with self._db.execute(query, params) as cur:
            row = await cur.fetchone()
            return row[0] if row else 0

    async def get_recent_devices(self, limit: int = 50,
                                  sensor_type: str | None = None) -> list[dict]:
        if not self._db:
            return []
        query = "SELECT * FROM devices"
        params: list = []
        if sensor_type:
            query += " WHERE sensor_type = ?"
            params.append(sensor_type)
        query += " ORDER BY last_seen DESC LIMIT ?"
        params.append(limit)
        async with self._db.execute(query, params) as cur:
            rows = await cur.fetchall()
            return [dict(r) for r in rows]

    async def get_unacked_alerts(self, limit: int = 100) -> list[dict]:
        if not self._db:
            return []
        async with self._db.execute(
            "SELECT * FROM alerts WHERE acknowledged = 0 ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        ) as cur:
            rows = await cur.fetchall()
            return [dict(r) for r in rows]


# ── OUI vendor lookup (offline) ───────────────────────────────────────────────

# Compact built-in OUI table for the most common vendors.
# A full ieee-data package can be installed for complete coverage.
_OUI_TABLE: dict[str, str] = {
    "000C29": "VMware",
    "001A11": "Google",
    "00265A": "Apple",
    "F0189B": "Apple",
    "DC2B2A": "Apple",
    "3C2EFF": "Apple",
    "A4C361": "Apple",
    "B8E856": "Samsung",
    "C4574F": "Samsung",
    "001D72": "Huawei",
    "001E10": "Huawei",
    "B4CD27": "Raspberry Pi Trading",
    "D83ADD": "Raspberry Pi Trading",
    "2CCF67": "Raspberry Pi Trading",
    "001BC5": "Ubiquiti",
    "788A20": "Ubiquiti",
    "ACBB56": "Cisco",
    "001A2F": "Cisco",
    "00E04C": "Realtek",
    "0090A9": "Alfa Network",
    "00C0CA": "Alfa Network",
}

def lookup_vendor(mac: str) -> str | None:
    """Return vendor string for a MAC address, or None if unknown."""
    if not mac:
        return None
    oui = mac.upper().replace(":", "").replace("-", "")[:6]
    return _OUI_TABLE.get(oui)
