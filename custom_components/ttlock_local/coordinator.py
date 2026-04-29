"""DataUpdateCoordinator for TTLock Local BLE.

Manages a single BLE connection per lock. Connects on demand (lock entities
typically don't need a persistent BLE link — auth is per-operation), and
schedules a return-to-locked transition after `auto_lock_seconds` since the
hardware auto-bolts on its own.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import timedelta

from homeassistant.components import bluetooth
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import (
    CONF_AES_KEY, CONF_AUTO_LOCK_SECONDS, CONF_MAC, CONF_UNLOCK_KEY,
    CONF_USER_ID, DEFAULT_AUTO_LOCK_SECONDS, DOMAIN,
)
from .ttlock_ble_client import TTLockBleClient
from .ttlock_protocol import parse_sciener_aeskey

_LOGGER = logging.getLogger(__name__)


class TTLockCoordinator(DataUpdateCoordinator[dict]):
    """Coordinates BLE access to a single TTLock."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name=f"{DOMAIN}_{entry.data[CONF_MAC]}",
            update_interval=None,
        )
        self.entry = entry
        self.mac: str = entry.data[CONF_MAC]
        aes_str: str = entry.data[CONF_AES_KEY]
        self.aes_key: bytes = (
            parse_sciener_aeskey(aes_str)
            if "," in aes_str
            else bytes.fromhex(aes_str)
        )
        self.user_id: int = int(entry.data[CONF_USER_ID])
        self.unlock_key: int = int(entry.data[CONF_UNLOCK_KEY])
        self.auto_lock_seconds: int = entry.options.get(
            CONF_AUTO_LOCK_SECONDS,
            entry.data.get(CONF_AUTO_LOCK_SECONDS, DEFAULT_AUTO_LOCK_SECONDS),
        )

        self._lock = asyncio.Lock()  # serialize BLE ops
        self._auto_lock_task: asyncio.Task | None = None
        self.is_unlocked: bool = False

    async def _async_update_data(self) -> dict:
        # No periodic polling — TTLock V3 BLE doesn't expose a passive state read.
        # State is inferred from our own commands + auto-lock timer.
        return {"is_unlocked": self.is_unlocked}

    def _ble_device(self):
        """Resolve a BLEDevice via HA bluetooth (supports ESPHome BT proxies)."""
        device = bluetooth.async_ble_device_from_address(
            self.hass, self.mac.upper(), connectable=True
        )
        if device is None:
            raise UpdateFailed(
                f"Lock {self.mac} not advertising. Touch keypad to wake it."
            )
        return device

    async def async_unlock(self) -> bool:
        async with self._lock:
            device = self._ble_device()
            client = TTLockBleClient(
                device, self.aes_key,
                user_id=self.user_id, unlock_key=self.unlock_key,
            )
            try:
                await client.connect(scan_first=False)
                ok = await client.unlock()
            finally:
                await client.disconnect()

        if ok:
            self.is_unlocked = True
            self._schedule_auto_lock()
            self.async_set_updated_data({"is_unlocked": True})
        return ok

    def _schedule_auto_lock(self) -> None:
        if self._auto_lock_task and not self._auto_lock_task.done():
            self._auto_lock_task.cancel()

        async def _revert() -> None:
            try:
                await asyncio.sleep(self.auto_lock_seconds)
                self.is_unlocked = False
                self.async_set_updated_data({"is_unlocked": False})
            except asyncio.CancelledError:
                pass

        self._auto_lock_task = self.hass.async_create_task(_revert())

    async def async_shutdown(self) -> None:
        if self._auto_lock_task and not self._auto_lock_task.done():
            self._auto_lock_task.cancel()
