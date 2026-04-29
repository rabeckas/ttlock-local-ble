# TTLock V3 BLE Protocol Reference

Reverse-engineered from [kind3r/ttlock-sdk-js](https://github.com/kind3r/ttlock-sdk-js) (JavaScript port of TTLock Android SDK).

## Frame Format

```
+--------+--------+--------+--------+--------+----------+----------+--------+--------+--------+--------+----------+--------+
| 0x7F   | 0x5A   | proto  | subver | scene  | org (BE) | sub (BE) | cmd    | enc    | dataLen| data...| CRC      |
| header | header | type   | sion   |        | 2 bytes  | 2 bytes  | type   | flag   | byte   | (enc)  | 1 byte   |
+--------+--------+--------+--------+--------+----------+----------+--------+--------+--------+--------+----------+--------+
| 0      | 1      | 2      | 3      | 4      | 5  6     | 7  8     | 9      | 10     | 11     | 12+    | last     |
```

- **V3 Lock detection**: `protoType == 0x05 && subVersion == 0x03`
- **Header**: always `0x7F 0x5A`
- **Command type**: see [CommandType.md](./COMMANDS.md)
- **Encrypt flag**: `0x01` if data is AES encrypted, else `0x00`
- **Data**: AES-128-CBC encrypted with aesKey (IV = key)
- **CRC**: 1 byte over all preceding bytes (CRC-8/MAXIM via lookup table)

## Encryption

- **Algorithm**: AES-128-CBC
- **Key size**: 16 bytes (128-bit)
- **IV**: same as key (TTLock design choice, not standard practice)
- **Padding**: PKCS#7
- **Default unpaired key**: `defaultAESKey` from TTLock SDK (hardcoded for initial pairing)

## CRC

- **Algorithm**: CRC-8/MAXIM (Dallas/1-Wire compatible)
- **Polynomial**: 0x31 (reflected: 0x8C)
- **Initial value**: 0x00
- **Reflected**: yes (input + output)
- **XOR output**: 0x00

Lookup table approach via `dscrc_table[256]`.

## BLE Service / Characteristics

| | UUID | Purpose |
|---|---|---|
| Service | `0x1910` | TTLock proprietary service |
| Write | `0xfff2` | Send commands |
| Notify | `0xfff4` | Receive responses (subscribe) |
| MTU | 20 bytes | Chunk data into 20-byte writes |
| Frame terminator | `0x0D 0x0A` (CRLF) | Append to each frame on write |

Standard BLE GATT services (informational only):
- `0x1800` (Generic Access) → `0x2A00` Device Name
- `0x180A` (Device Information) → `0x2A29` Manufacturer, `0x2A24` Model, `0x2A26` Firmware

## Key Commands (subset for unlock/lock)

| Command | Code | Description |
|---|---|---|
| `COMM_INITIALIZATION` | 0x45 | Initial handshake |
| `COMM_GET_AES_KEY` | 0x19 | Retrieve AES key (used during pairing) |
| `COMM_RESPONSE` | 0x54 | Response from lock |
| `COMM_CHECK_ADMIN` | 0x41 | Verify admin auth |
| `COMM_UNLOCK` | 0x47 | Unlock command |
| `COMM_LOCK` | 0x4C | Lock command |
| `COMM_GET_LOCK_TIME` | 0x34 | Get lock time |
| `COMM_READ_DEVICE_INFO` | 0x90 | Read device metadata |
| `COMM_GET_VALID_KEYBOARD_PASSWORD` | 0x04 | Get passcodes |
| `COMM_RESET_LOCK` | 0x52 | Factory reset |

Full list in [COMMANDS.md](./COMMANDS.md).

## Auth Flow

1. App scans → finds lock via mfg data
2. App connects via BLE (write + notify chars)
3. App sends `COMM_INITIALIZATION` (encrypted with aesKey)
4. Lock responds with success/failure
5. App can now send unlock/lock commands

## References

- kind3r/ttlock-sdk-js: https://github.com/kind3r/ttlock-sdk-js
- Fusseldieb/ttlock-reverse-engineering: https://github.com/Fusseldieb/ttlock-reverse-engineering
- Original TTLock Android SDK (closed-source binary)

## TODO

- [x] Identify exact write/notify BLE characteristics — `0x1910/fff2/fff4`
- [x] Confirm CRC-8/MAXIM polynomial — verified with test vectors
- [x] Test against real lock with extracted aesKey — connection + decrypt verified
- [x] checkUserTime command works — returns valid psFromLock
- [x] **Decode `unlockKey` from Sciener DB byte array** — SOLVED 2026-04-29
  - Algorithm: `com.scaf.android.client.CodecUtils.decode` (JNI in libLockCore.so),
    reverse-engineered via jadx + `kind3r/ttlock-sdk-js/util/CodecUtils.ts` reference.
  - Steps:
    1. base64 decode → CSV ASCII string of bytes
    2. last byte = encryption seed; rest = XOR-encoded plaintext
    3. `plaintext[i] = seed XOR encoded[i] XOR dscrc_table[plaintext_len]`
    4. plaintext is ASCII decimal digits → parse as Long
  - **kind3r has an off-by-one bug** in `decodeWithEncrypt`: it indexes the dscrc
    table by `p0.length` (encoded length, including seed) instead of
    `p0.length - 1` (plaintext length). The native lib uses plaintext length.
  - Verified end-to-end: unlock returned `0x47 0x01` (cmd echo + status 0x01
    SUCCESS), lock physically opened. See `tests/test_protocol.py` for a
    round-trip test of the decode algorithm with synthetic data.
- [ ] Write HA custom integration (config_flow, lock entity, coordinator)
- [ ] Multi-lock support via ESPHome BT proxy

## Response Format

All responses follow:
```
[0]    command echo (matches sent command)
[1]    status: 0x01 = SUCCESS, 0x00 = FAILED
[2+]   command-specific data
```

For checkUserTime success: data starts with uint32 BE psFromLock.
For unlock failure subcodes seen so far: 0x01, 0x08, 0x1B (varies, all = FAILED).
