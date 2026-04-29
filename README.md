# TTLock Local (BLE) — Home Assistant integration

Local Bluetooth control of TTLock V3 smart locks. No TTLock cloud, no Sciener
account, no rate limits — just your HA host (or any ESPHome BT proxy)
talking to the lock directly over BLE.

This was built for a rental-property setup where the lock owner only had
"Company manager" rights in TTRenting and could not perform `lock/unlock` via
the official cloud API (it returns `errcode -4043 The function is not supported
for this lock`). The fix: extract the AES key from the rooted Android app's
own database, decode the obfuscated unlock secret, and speak the BLE protocol
ourselves.

## Status

- ✅ V3 frame encode/decode (header `7F 5A`, AES-128-CBC, CRC-8/MAXIM)
- ✅ checkUserTime → unlock handshake against a real lock
- ✅ HA integration: config flow, lock entity, auto-lock revert
- ✅ ESPHome BT proxy support (via HA `bluetooth` component)
- ✅ `bleak-retry-connector` for reliable connections
- ⚠️ Manual lock command (`0x4C`) returns subcode `0x1B` on the model tested —
  the hardware auto-bolts on its own, so `lock()` is treated as a no-op and the
  state reverts after an `auto_lock_seconds` timer.

## Why a new project?

There are two existing options, and neither solves the problem this does:

- **`jbergler/hass-ttlock`** uses the TTLock cloud API. Works only if your
  account has admin/key rights on the lock. For rental setups, leasers, or
  Company-manager eKeys it returns `-4043` on every unlock.
- **`kind3r/ttlock-sdk-js`** is an excellent reverse engineering reference and
  the basis for this implementation. Its `CodecUtils.decodeWithEncrypt`,
  however, has an off-by-one bug (it indexes the CRC table by the encoded
  length instead of the plaintext length) that prevents it from decoding the
  `unlockkey` byte array correctly. This project ports the algorithm with the
  fix; see the comments in
  [`ttlock_protocol.py`](custom_components/ttlock_local/ttlock_protocol.py)
  near `parse_sciener_unlock_key`.

## How to extract your lock's credentials

The integration needs four values per lock, all stored in the Sciener Android
app's database (`com.tongtongsuo.app` — yes, the package name is
"tongtongsuo", which is "通通锁" in Chinese):

1. Root your Android phone (Magisk or similar).
2. Pair the lock directly into the **TTLock** app on that phone.
3. Pull the database:
   ```bash
   adb shell "su -c 'cp /data/data/com.tongtongsuo.app/databases/newsciener.db /sdcard/'"
   adb pull /sdcard/newsciener.db
   ```
4. Open it with `sqlite3` and read the `virtualkey` table. The columns you need:
   - `lockmac` — BLE MAC address
   - `aeskeystr` — AES-128 key as 16 comma-separated hex bytes
   - `uid` — user ID (integer)
   - `unlockkey` — base64-encoded, XOR-obfuscated unlock secret

If the lock has been added to TTRenting (or any other "company" app) it must
first be released or transferred, otherwise the TTLock app will refuse to pair
with it. There is no factory reset on TTRenting locks without the master code.

## Installation

1. Copy `custom_components/ttlock_local/` into `/config/custom_components/`
   on your Home Assistant host. (`deploy.py` does this over SFTP if you keep
   SSH credentials in a `.env` next to it.)
2. Restart Home Assistant.
3. Settings → Devices & Services → Add Integration → "TTLock Local".
4. Fill in the four values from `virtualkey` plus a name and the
   `auto_lock_seconds` value that matches your lock's hardware setting.

The integration runs entirely on local Bluetooth — either the HA host's own
adapter or any ESPHome BT proxy in range of the lock. No cloud account is
contacted.

## Files

- `custom_components/ttlock_local/ttlock_protocol.py` — frame encoder/decoder,
  AES, CRC, the Sciener DB parsers (including the unlockKey fix).
- `custom_components/ttlock_local/ttlock_ble_client.py` — async Bleak client
  that handles the `0x1910 / fff2 / fff4` characteristic layout, 20-byte MTU
  chunking, and the `\r\n` frame terminator.
- `custom_components/ttlock_local/coordinator.py` — single-lock coordinator,
  serializes BLE ops, drives the auto-lock state revert.
- `custom_components/ttlock_local/lock.py` — the HA `LockEntity`.
- `docs/PROTOCOL.md` — protocol notes from the reverse-engineering work.

## Contributing

Pull requests welcome, especially:

- Other lock command codes (passcode management, calibration, audio toggle).
- Decoding paths for credential formats produced by other Sciener-family apps
  (TTRenting, Roommaster, etc.).
- A graceful fallback when `0x4C` (manual lock) is supported by the hardware.

## License

MIT — see [LICENSE](LICENSE).

## Credits

- [`kind3r/ttlock-sdk-js`](https://github.com/kind3r/ttlock-sdk-js) — invaluable
  reference for the V3 frame format, AES convention, CRC table, and the
  CodecUtils encode/decode pairing.
- [`Fusseldieb/ttlock-reverse-engineering`](https://github.com/Fusseldieb/ttlock-reverse-engineering)
  — early notes on the BLE service / characteristics layout.
- [`jbergler/hass-ttlock`](https://github.com/jbergler/hass-ttlock) — the
  cloud-side reference HA integration.
