"""TTLock V3 BLE protocol implementation.

Frame format:
  [0]    0x7F           header byte 1
  [1]    0x5A           header byte 2
  [2]    proto type     V3 = 0x05
  [3]    sub version    V3 = 0x03
  [4]    scene          0-11 (lock category)
  [5-6]  org (BE)       organization ID
  [7-8]  suborg (BE)    sub-organization ID
  [9]    command        see CommandType
  [10]   encrypt flag   0x01 if data is AES encrypted
  [11]   data length    byte count
  [12+]  data           (AES-128-CBC encrypted with aesKey, IV=key)
  [last] CRC            CRC-8/MAXIM over all prior bytes
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


# ============================================================================
# Constants
# ============================================================================

HEADER = bytes([0x7F, 0x5A])
PROTOCOL_TYPE_V3 = 0x05
SUB_VERSION_V3 = 0x03

ENCRYPT_NO = 0x00
ENCRYPT_YES = 0x01

# Command types (subset; full list in docs/COMMANDS.md)
class Cmd:
    INIT                   = 0x45
    GET_AES_KEY            = 0x19
    RESPONSE               = 0x54
    ADD_ADMIN              = 0x56
    CHECK_ADMIN            = 0x41
    SET_LOCK_NAME          = 0x4E
    CHECK_USER_TIME        = 0x55
    OPERATE_FINISHED       = 0x57
    UNLOCK                 = 0x47
    LOCK                   = 0x4C
    TIME_CALIBRATE         = 0x43
    GET_OPERATE_LOG        = 0x25
    CHECK_RANDOM           = 0x30
    INIT_PASSWORDS         = 0x31
    GET_LOCK_TIME          = 0x34
    RESET_LOCK             = 0x52
    SEARCH_DEVICE_FEATURE  = 0x01
    READ_DEVICE_INFO       = 0x90
    AUTO_LOCK_MANAGE       = 0x36
    AUDIO_MANAGE           = 0x62


# ============================================================================
# CRC-8/MAXIM (Dallas/1-Wire)
# ============================================================================

def _build_crc8_maxim_table() -> list[int]:
    """Generate CRC-8/MAXIM lookup table.
    Polynomial: 0x31 (reflected: 0x8C). Initial: 0x00.
    """
    table = []
    for byte in range(256):
        crc = byte
        for _ in range(8):
            if crc & 0x01:
                crc = (crc >> 1) ^ 0x8C
            else:
                crc >>= 1
        table.append(crc)
    return table

_CRC_TABLE = _build_crc8_maxim_table()


def crc8_maxim(data: bytes) -> int:
    """Compute CRC-8/MAXIM over given bytes."""
    crc = 0
    for b in data:
        crc = _CRC_TABLE[crc ^ b]
    return crc


# ============================================================================
# AES-128-CBC (key = IV, PKCS#7 padding) — TTLock convention
# ============================================================================

def aes_encrypt(data: bytes, key: bytes) -> bytes:
    """AES-128-CBC encrypt with key as IV."""
    if len(key) != 16:
        raise ValueError(f"AES key must be 16 bytes, got {len(key)}")
    cipher = AES.new(key, AES.MODE_CBC, iv=key)
    return cipher.encrypt(pad(data, AES.block_size))


def aes_decrypt(data: bytes, key: bytes) -> bytes:
    """AES-128-CBC decrypt with key as IV."""
    if len(key) != 16:
        raise ValueError(f"AES key must be 16 bytes, got {len(key)}")
    if len(data) % 16 != 0:
        raise ValueError(f"Encrypted data length must be multiple of 16, got {len(data)}")
    cipher = AES.new(key, AES.MODE_CBC, iv=key)
    return unpad(cipher.decrypt(data), AES.block_size)


# ============================================================================
# Frame
# ============================================================================

@dataclass
class Frame:
    proto_type: int = PROTOCOL_TYPE_V3
    sub_version: int = SUB_VERSION_V3
    scene: int = 0
    org: int = 0
    suborg: int = 0
    command: int = 0
    encrypt: int = ENCRYPT_NO
    data: bytes = b""

    def encode(self, key: bytes | None = None) -> bytes:
        """Build TTLock V3 frame. If key provided + data non-empty, AES-encrypt."""
        payload = self.data
        encrypt = self.encrypt
        if encrypt == ENCRYPT_YES and payload and key:
            payload = aes_encrypt(payload, key)

        body = bytes([
            self.proto_type,
            self.sub_version,
            self.scene,
        ]) + struct.pack(">H", self.org) + struct.pack(">H", self.suborg) + bytes([
            self.command,
            encrypt,
            len(payload),
        ]) + payload

        frame = HEADER + body
        crc = crc8_maxim(frame)
        return frame + bytes([crc])

    @classmethod
    def decode(cls, raw: bytes, key: bytes | None = None) -> "Frame":
        """Parse a TTLock V3 frame. If encrypted + key provided, decrypts data."""
        if len(raw) < 14:
            raise ValueError(f"Frame too short: {len(raw)}")
        if raw[:2] != HEADER:
            raise ValueError(f"Bad header: {raw[:2].hex()}")

        # Verify CRC (last byte over all preceding)
        expected_crc = raw[-1]
        actual_crc = crc8_maxim(raw[:-1])
        if expected_crc != actual_crc:
            raise ValueError(
                f"CRC mismatch: expected {expected_crc:02x}, got {actual_crc:02x}"
            )

        proto_type = raw[2]
        sub_version = raw[3]
        scene = raw[4]
        org = struct.unpack(">H", raw[5:7])[0]
        suborg = struct.unpack(">H", raw[7:9])[0]
        command = raw[9]
        encrypt = raw[10]
        data_len = raw[11]
        data = raw[12:12 + data_len]

        if encrypt == ENCRYPT_YES and key:
            data = aes_decrypt(data, key)

        return cls(
            proto_type=proto_type,
            sub_version=sub_version,
            scene=scene,
            org=org,
            suborg=suborg,
            command=command,
            encrypt=encrypt,
            data=data,
        )


# ============================================================================
# Helper builders for common commands
# ============================================================================

import time


def _date_to_bytes(t: float | None = None) -> bytes:
    """Convert timestamp to 5-byte TTLock date format: YY MM DD HH MM (each byte is decimal value).

    From kind3r/ttlock-sdk-js timeUtil.dateTimeToBuffer.
    """
    if t is None:
        t = time.time()
    lt = time.localtime(t)
    return bytes([
        lt.tm_year - 2000,
        lt.tm_mon,
        lt.tm_mday,
        lt.tm_hour,
        lt.tm_min,
    ])


def build_check_user_time_command(
    aes_key: bytes,
    user_id: int,
    lock_flag_pos: int = 0,
    start_date: bytes | None = None,
    end_date: bytes | None = None,
) -> bytes:
    """Build COMM_CHECK_USER_TIME command — first step in auth flow.

    Lock responds with `psFromLock` (uint32 BE) needed for setSum.

    Payload (17 bytes):
      [0-4]    Start date (5 bytes YY MM DD HH MM, current time by default)
      [5-9]    End date (5 bytes, but byte 9 overwritten by lockFlagPos)
      [9-12]   Lock flag position (uint32 BE) — overwrites end date byte 4
      [13-16]  User ID (uint32 BE)
    """
    if start_date is None:
        start_date = _date_to_bytes()  # now
    if end_date is None:
        end_date = _date_to_bytes(time.time() + 10*365*86400)  # +10 years

    payload = bytearray(17)
    payload[0:5] = start_date
    payload[5:10] = end_date
    struct.pack_into(">I", payload, 9, lock_flag_pos)
    struct.pack_into(">I", payload, 13, user_id)

    frame = Frame(command=Cmd.CHECK_USER_TIME, encrypt=ENCRYPT_YES, data=bytes(payload))
    return frame.encode(aes_key)


def parse_check_user_time_response(decrypted_data: bytes) -> int:
    """Parse psFromLock value from CheckUserTime response.

    Response data layout (decrypted, after cmd 0x54 envelope):
      [0]    0x55 (CHECK_USER_TIME command echo)
      [1]    status byte (0x01 = ok)
      [2-5]  psFromLock (uint32 BE)
    """
    if len(decrypted_data) < 6:
        return -1
    return struct.unpack(">I", decrypted_data[2:6])[0]


def build_unlock_command(
    aes_key: bytes,
    ps_from_lock: int,
    unlock_key: int,
    timestamp: int | None = None,
) -> bytes:
    """Build encrypted unlock command frame (post-auth).

    Args:
      aes_key:       16-byte AES key from Sciener DB
      ps_from_lock:  uint32 challenge from checkUserTime response
      unlock_key:    int from extracted Sciener DB (privateData.admin.unlockKey)
      timestamp:     Unix timestamp seconds (defaults to now)

    Payload (8 bytes):
      [0-3]  sum = (psFromLock + unlockKey) & 0xFFFFFFFF (uint32 BE)
      [4-7]  timestamp (uint32 BE)
    """
    if timestamp is None:
        timestamp = int(time.time())
    sum_val = (ps_from_lock + unlock_key) & 0xFFFFFFFF
    payload = struct.pack(">II", sum_val, timestamp)
    frame = Frame(command=Cmd.UNLOCK, encrypt=ENCRYPT_YES, data=payload)
    return frame.encode(aes_key)


def build_lock_command(
    aes_key: bytes,
    ps_from_lock: int,
    unlock_key: int,
    timestamp: int | None = None,
) -> bytes:
    """Build encrypted lock command frame. Same payload structure as unlock."""
    if timestamp is None:
        timestamp = int(time.time())
    sum_val = (ps_from_lock + unlock_key) & 0xFFFFFFFF
    payload = struct.pack(">II", sum_val, timestamp)
    frame = Frame(command=Cmd.LOCK, encrypt=ENCRYPT_YES, data=payload)
    return frame.encode(aes_key)


def build_init_command(aes_key: bytes) -> bytes:
    """Build initialization handshake command."""
    frame = Frame(command=Cmd.INIT, encrypt=ENCRYPT_YES, data=b"\x01")
    return frame.encode(aes_key)


def parse_sciener_unlock_key(unlockkey_b64: str) -> int:
    """Convert Sciener DB 'unlockkey' base64-encoded byte array to integer.

    Pipeline (mirrors com.scaf.android.client.CodecUtils.decode JNI in libLockCore.so):
      1. base64 decode → CSV ASCII (e.g. "68,71,64,64,66,69,65,68,66,76,10")
      2. parse to byte array
      3. last byte is the encryption seed; the rest is XOR-encrypted plaintext
      4. plaintext[i] = seed XOR encoded[i] XOR dscrc_table[plaintext_len]
         (kind3r/ttlock-sdk-js indexes the table with encoded_len — that's an
          off-by-one bug; the native lib uses plaintext_len = encoded_len - 1)
      5. plaintext is ASCII decimal digits → int

    Worked example (synthetic):
      Encoded CSV "11,22,33,44,42" base64 → "MTEsMjIsMzMsNDQsNDI="
      seed=42, crc=dscrc_table[plaintext_len], plaintext = ASCII digits.
      See tests/test_protocol.py::TestParseScienerUnlockKey for a round-trip.
    """
    import base64
    raw = base64.b64decode(unlockkey_b64).decode().strip()
    encoded = [int(x) for x in raw.split(',')]
    if len(encoded) < 2:
        raise ValueError(f"unlockkey too short: {encoded}")
    seed = encoded[-1]
    payload = encoded[:-1]
    crc = _CRC_TABLE[len(payload) & 0xFF]
    decoded = bytes((seed ^ b ^ crc) & 0xFF for b in payload)
    return int(decoded.decode("ascii"))


# ============================================================================
# Helpers for parsing aesKey from extracted Sciener DB format
# ============================================================================

def parse_sciener_aeskey(aeskeystr: str) -> bytes:
    """Convert Sciener DB 'aeskeystr' (e.g. 'aa,bb,cc,...' — 16 hex bytes CSV) to bytes."""
    parts = aeskeystr.replace(' ', '').split(',')
    if len(parts) != 16:
        raise ValueError(f"Expected 16 hex bytes in aesKey, got {len(parts)}")
    return bytes(int(p, 16) for p in parts)
