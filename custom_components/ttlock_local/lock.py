"""Lock entity for TTLock Local BLE."""
from __future__ import annotations

import logging

from homeassistant.components.lock import LockEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import CONF_NAME, DOMAIN
from .coordinator import TTLockCoordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    coordinator: TTLockCoordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([TTLockEntity(coordinator, entry)])


class TTLockEntity(CoordinatorEntity[TTLockCoordinator], LockEntity):
    """A TTLock V3 BLE lock."""

    _attr_has_entity_name = True
    _attr_name = None  # use device name

    def __init__(self, coordinator: TTLockCoordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{coordinator.mac}_lock"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, coordinator.mac)},
            name=entry.data.get(CONF_NAME) or f"TTLock {coordinator.mac}",
            manufacturer="TTLock",
            model="V3 BLE",
            connections={("bluetooth", coordinator.mac)},
        )

    @property
    def is_locked(self) -> bool | None:
        return not self.coordinator.is_unlocked

    async def async_unlock(self, **kwargs) -> None:
        ok = await self.coordinator.async_unlock()
        if not ok:
            raise RuntimeError("TTLock unlock failed — see logs")

    async def async_lock(self, **kwargs) -> None:
        # Hardware auto-locks; manual lock cmd 0x4C returns subcode 0x1B on this
        # model. Treat as no-op so HA's lock/unlock UI still works.
        _LOGGER.debug("lock() called — relying on hardware auto-lock")
        self.coordinator.is_unlocked = False
        self.coordinator.async_set_updated_data({"is_unlocked": False})
