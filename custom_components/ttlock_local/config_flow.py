"""Config flow for TTLock Local BLE.

User provides values extracted from the rooted Sciener app DB:
- MAC address (BLE)
- aesKey (CSV hex string from `aeskeystr` column)
- user_id (uid column)
- unlockkey_b64 (raw `unlockkey` column from DB) OR unlock_key int directly

The flow runs `parse_sciener_aeskey` and `parse_sciener_unlock_key` to validate.
"""
from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import ConfigEntry, ConfigFlow, OptionsFlow
from homeassistant.core import callback
from homeassistant.data_entry_flow import FlowResult

from .const import (
    CONF_AES_KEY, CONF_AUTO_LOCK_SECONDS, CONF_MAC, CONF_NAME,
    CONF_UNLOCK_KEY, CONF_USER_ID, DEFAULT_AUTO_LOCK_SECONDS, DOMAIN,
)
from .ttlock_protocol import parse_sciener_aeskey, parse_sciener_unlock_key

_LOGGER = logging.getLogger(__name__)

CONF_UNLOCK_KEY_B64 = "unlock_key_b64"

USER_SCHEMA = vol.Schema({
    vol.Required(CONF_MAC): str,
    vol.Required(CONF_NAME, default="Front Door"): str,
    vol.Required(CONF_AES_KEY): str,
    vol.Required(CONF_USER_ID): vol.Coerce(int),
    vol.Required(CONF_UNLOCK_KEY_B64): str,
    vol.Optional(CONF_AUTO_LOCK_SECONDS, default=DEFAULT_AUTO_LOCK_SECONDS): vol.Coerce(int),
})


class TTLockConfigFlow(ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        errors: dict[str, str] = {}

        if user_input is not None:
            try:
                parse_sciener_aeskey(user_input[CONF_AES_KEY])
            except Exception as e:
                _LOGGER.warning("Bad aesKey: %s", e)
                errors[CONF_AES_KEY] = "invalid_aes_key"

            try:
                unlock_key = parse_sciener_unlock_key(user_input[CONF_UNLOCK_KEY_B64])
            except Exception as e:
                _LOGGER.warning("Bad unlockkey: %s", e)
                errors[CONF_UNLOCK_KEY_B64] = "invalid_unlock_key"
            else:
                user_input[CONF_UNLOCK_KEY] = unlock_key

            mac = user_input[CONF_MAC].upper()
            await self.async_set_unique_id(mac)
            self._abort_if_unique_id_configured()

            if not errors:
                user_input[CONF_MAC] = mac
                user_input.pop(CONF_UNLOCK_KEY_B64, None)
                return self.async_create_entry(
                    title=user_input[CONF_NAME],
                    data=user_input,
                )

        return self.async_show_form(
            step_id="user",
            data_schema=USER_SCHEMA,
            errors=errors,
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> OptionsFlow:
        return TTLockOptionsFlow(config_entry)


class TTLockOptionsFlow(OptionsFlow):
    def __init__(self, config_entry: ConfigEntry) -> None:
        self.config_entry = config_entry

    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        current = self.config_entry.options.get(
            CONF_AUTO_LOCK_SECONDS,
            self.config_entry.data.get(CONF_AUTO_LOCK_SECONDS, DEFAULT_AUTO_LOCK_SECONDS),
        )
        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema({
                vol.Required(CONF_AUTO_LOCK_SECONDS, default=current): vol.Coerce(int),
            }),
        )
