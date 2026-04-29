"""TTLock V3 BLE client.

Uses bleak (cross-platform Python BLE) to:
1. Connect to TTLock by MAC address
2. Subscribe to notifications (0xfff4)
3. Send encrypted command frames (0xfff2)
4. Parse responses
"""
from __future__ import annotations

import asyncio
import logging
from typing import Awaitable, Callable

from bleak import BleakClient, BleakScanner

try:
    from bleak_retry_connector import establish_connection
    _HAS_RETRY_CONNECTOR = True
except ImportError:  # standalone use without HA
    _HAS_RETRY_CONNECTOR = False

try:
    from .ttlock_protocol import (
        Cmd, Frame, ENCRYPT_YES,
        build_check_user_time_command, parse_check_user_time_response,
        build_unlock_command, build_lock_command, build_init_command,
    )
except ImportError:
    from ttlock_protocol import (
        Cmd, Frame, ENCRYPT_YES,
        build_check_user_time_command, parse_check_user_time_response,
        build_unlock_command, build_lock_command, build_init_command,
    )

_LOGGER = logging.getLogger(__name__)

# Standard TTLock V3 BLE characteristics
SERVICE_UUID = "00001910-0000-1000-8000-00805f9b34fb"
WRITE_CHAR_UUID = "0000fff2-0000-1000-8000-00805f9b34fb"
NOTIFY_CHAR_UUID = "0000fff4-0000-1000-8000-00805f9b34fb"

MTU_CHUNK_SIZE = 20
FRAME_TERMINATOR = b"\x0D\x0A"


class TTLockBleClient:
    """Async BLE client for TTLock V3 locks."""

    def __init__(self, address_or_device, aes_key: bytes, user_id: int = 0, unlock_key: int = 0):
        # Accept either a MAC string or a BLEDevice (the latter is what HA's
        # bluetooth integration returns and is required for ESPHome BT proxies).
        self.address_or_device = address_or_device
        self.address = (
            address_or_device if isinstance(address_or_device, str)
            else getattr(address_or_device, "address", str(address_or_device))
        )
        self.aes_key = aes_key
        self.user_id = user_id
        self.unlock_key = unlock_key
        self._client: BleakClient | None = None
        self._response_buffer = bytearray()
        self._response_event = asyncio.Event()
        self._last_response: Frame | None = None
        self._ps_from_lock: int | None = None

    async def __aenter__(self):
        await self.connect()
        return self

    async def __aexit__(self, *exc):
        await self.disconnect()

    async def connect(self, timeout: float = 15.0, scan_first: bool = True) -> bool:
        """Connect to lock and subscribe to notifications.

        Tries up to 3 times with discovery scan in between to wake the lock.
        """
        device = None
        if scan_first:
            for attempt in range(3):
                _LOGGER.info("Scanning for %s (attempt %d/3)...", self.address, attempt + 1)
                device = await BleakScanner.find_device_by_address(self.address, timeout=10)
                if device:
                    _LOGGER.info("Found device: %s (%s)", device.name, device.address)
                    break
                _LOGGER.warning("Not found — touch lock keypad to wake it!")
                await asyncio.sleep(2)
            if device is None:
                raise RuntimeError(
                    f"Lock {self.address} not found after 3 scans. "
                    "Make sure it's awake (touch keypad) and in range."
                )

        _LOGGER.info("Connecting to %s", self.address)
        target = device or self.address_or_device
        if _HAS_RETRY_CONNECTOR and not isinstance(target, str):
            self._client = await establish_connection(
                BleakClient, target, name=self.address,
                disconnected_callback=lambda _c: None,
                max_attempts=3,
            )
        else:
            self._client = BleakClient(target, timeout=timeout)
            await self._client.connect()

        if not self._client.is_connected:
            raise RuntimeError(f"Failed to connect to {self.address}")

        await self._client.start_notify(NOTIFY_CHAR_UUID, self._on_notification)
        _LOGGER.info("Connected and subscribed to notifications")
        return True

    async def disconnect(self):
        if self._client and self._client.is_connected:
            try:
                await self._client.stop_notify(NOTIFY_CHAR_UUID)
            except Exception:
                pass
            await self._client.disconnect()
        self._client = None

    def _on_notification(self, sender, data: bytearray):
        """Handle incoming BLE notification chunk. Frames may span multiple chunks."""
        _LOGGER.debug("RX chunk: %s", data.hex())
        self._response_buffer.extend(data)

        # Look for complete frame terminated by CRLF
        if FRAME_TERMINATOR in self._response_buffer:
            frame_end = self._response_buffer.index(FRAME_TERMINATOR)
            raw_frame = bytes(self._response_buffer[:frame_end])
            del self._response_buffer[:frame_end + len(FRAME_TERMINATOR)]

            try:
                frame = Frame.decode(raw_frame, self.aes_key)
                _LOGGER.info("RX frame cmd=0x%02x data=%s", frame.command, frame.data.hex())
                self._last_response = frame
                self._response_event.set()
            except Exception as e:
                _LOGGER.error("Failed to parse frame %s: %s", raw_frame.hex(), e)

    async def _send_frame(self, frame_bytes: bytes) -> Frame | None:
        """Send a complete frame (with CRC) and wait for response."""
        if not self._client or not self._client.is_connected:
            raise RuntimeError("Not connected")

        # Append CRLF terminator
        payload = frame_bytes + FRAME_TERMINATOR

        # Chunk into MTU-sized writes
        for i in range(0, len(payload), MTU_CHUNK_SIZE):
            chunk = payload[i:i + MTU_CHUNK_SIZE]
            _LOGGER.debug("TX chunk: %s", chunk.hex())
            await self._client.write_gatt_char(WRITE_CHAR_UUID, chunk, response=False)

        # Wait for response
        self._response_event.clear()
        try:
            await asyncio.wait_for(self._response_event.wait(), timeout=10.0)
            return self._last_response
        except asyncio.TimeoutError:
            _LOGGER.warning("No response within 10s")
            return None

    async def _check_user_time(self) -> int | None:
        """Send checkUserTime command and parse psFromLock from response.
        Required as first auth step before unlock/lock commands.
        """
        _LOGGER.info("Auth step 1: checkUserTime")
        frame_bytes = build_check_user_time_command(
            self.aes_key,
            user_id=self.user_id,
        )
        response = await self._send_frame(frame_bytes)
        if response is None:
            _LOGGER.error("checkUserTime no response")
            return None
        if response.command not in (Cmd.RESPONSE, Cmd.CHECK_USER_TIME):
            _LOGGER.warning("checkUserTime unexpected cmd=0x%02x data=%s", response.command, response.data.hex())
        # Response data: cmd_echo(1) + status(2) + psFromLock(4)? or directly psFromLock(4)?
        # Try parsing the last 4 bytes as psFromLock first; fallback to first 4
        if len(response.data) >= 4:
            ps = parse_check_user_time_response(response.data)
            _LOGGER.info("psFromLock = %d (0x%08x) from data %s", ps, ps & 0xFFFFFFFF, response.data.hex())
            self._ps_from_lock = ps
            return ps
        return None

    async def unlock(self) -> bool:
        """Full auth + unlock sequence. Returns True on success."""
        ps = await self._check_user_time()
        if ps is None or ps == -1:
            _LOGGER.error("Could not get psFromLock")
            return False
        _LOGGER.info("Auth step 2: send unlock with sum=psFromLock(%d) + unlockKey(%d)", ps, self.unlock_key)
        frame_bytes = build_unlock_command(self.aes_key, ps, self.unlock_key)
        response = await self._send_frame(frame_bytes)
        if response is None:
            return False
        if response.command == Cmd.RESPONSE:
            success = len(response.data) >= 2 and response.data[1] == 0x01
            _LOGGER.info("Unlock response: data=%s -> %s", response.data.hex(),
                         "SUCCESS" if success else "FAIL")
            return success
        return False

    async def lock(self) -> bool:
        """Full auth + lock sequence."""
        ps = await self._check_user_time()
        if ps is None or ps == -1:
            return False
        frame_bytes = build_lock_command(self.aes_key, ps, self.unlock_key)
        response = await self._send_frame(frame_bytes)
        if response is None:
            return False
        if response.command == Cmd.RESPONSE:
            return len(response.data) >= 2 and response.data[1] == 0x01
        return False

    async def get_device_info(self) -> dict | None:
        """Read device info via standard BLE chars (no auth needed)."""
        if not self._client:
            return None
        info = {}
        for uuid, key in [
            ("00002a29-0000-1000-8000-00805f9b34fb", "manufacturer"),
            ("00002a24-0000-1000-8000-00805f9b34fb", "model"),
            ("00002a27-0000-1000-8000-00805f9b34fb", "hardware_revision"),
            ("00002a26-0000-1000-8000-00805f9b34fb", "firmware_revision"),
        ]:
            try:
                value = await self._client.read_gatt_char(uuid)
                info[key] = value.decode("utf-8", errors="replace")
            except Exception as e:
                _LOGGER.debug("Could not read %s: %s", key, e)
        return info
