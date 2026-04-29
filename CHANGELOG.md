# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-04-29

First public release. Verified end-to-end against a real lock via Home
Assistant: HA service `lock.unlock` → BLE handshake → physical unlock in ~1.5s.

### Added
- `ttlock_protocol.py` — V3 frame encode/decode, AES-128-CBC with `key=IV`,
  CRC-8/MAXIM, helpers for `checkUserTime`, `unlock`, `lock`, `init`.
- `parse_sciener_aeskey` — read 16-byte AES key from CSV-hex string in
  Sciener DB `aeskeystr` column.
- `parse_sciener_unlock_key` — decode the obfuscated `unlockkey` byte array
  to the integer used in `setSum`. **Fixes kind3r/ttlock-sdk-js off-by-one**:
  the native `libLockCore.so` indexes the `dscrc_table` by plaintext length,
  not encoded length.
- `ttlock_ble_client.py` — async Bleak client (service `0x1910`, write
  `0xfff2`, notify `0xfff4`, 20-byte MTU chunks, `\r\n` frame terminator),
  uses `bleak-retry-connector` when available.
- HA integration: `manifest.json`, `config_flow.py` (UI for MAC, AES key,
  user_id, unlockkey base64, name, auto_lock_seconds), `coordinator.py`
  (single-lock connection + auto-lock state revert), `lock.py`
  (`LockEntity` with `unlock`, no-op `lock` for auto-bolting hardware),
  English + Lithuanian translations.
- `deploy.py` — paramiko SFTP push to `/config/custom_components/ttlock_local/`
  on a HA host, optional `--restart`.
- `tests/test_protocol.py` — 17 unit tests covering CRC, AES, frame
  encode/decode, AES key parsing, unlockKey round-trip.
- `docs/PROTOCOL.md` — protocol notes.

### Known limitations
- Manual lock command `0x4C` returns subcode `0x1B` on the model tested.
  Hardware auto-bolts on its own; `lock()` is implemented as a state-only
  no-op with an `auto_lock_seconds` revert timer.
- Initial connect can fail if the lock is asleep; touching the keypad once
  brings it back into BLE-advertise range.
- One config entry = one lock. To pair more locks, repeat the credential
  extraction for each (rooted Android + Sciener DB row).

[Unreleased]: https://github.com/rabeckas/ttlock-local-ble/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/rabeckas/ttlock-local-ble/releases/tag/v0.1.0
