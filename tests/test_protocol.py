"""Tests for TTLock V3 protocol implementation."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "custom_components" / "ttlock_local"))

import unittest
from ttlock_protocol import (
    HEADER, PROTOCOL_TYPE_V3, SUB_VERSION_V3, ENCRYPT_NO, ENCRYPT_YES,
    Cmd, Frame, aes_encrypt, aes_decrypt, crc8_maxim, parse_sciener_aeskey,
    build_unlock_command,
)


class TestCRC(unittest.TestCase):
    def test_crc_known_vector(self):
        # CRC-8/MAXIM("123456789") = 0xA1 (well-known test vector)
        self.assertEqual(crc8_maxim(b"123456789"), 0xA1)

    def test_crc_empty(self):
        self.assertEqual(crc8_maxim(b""), 0)

    def test_crc_single_byte(self):
        self.assertEqual(crc8_maxim(b"\x00"), 0)


class TestAES(unittest.TestCase):
    KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

    def test_round_trip(self):
        plaintext = b"Hello, TTLock!"
        encrypted = aes_encrypt(plaintext, self.KEY)
        decrypted = aes_decrypt(encrypted, self.KEY)
        self.assertEqual(decrypted, plaintext)

    def test_key_size_validation(self):
        with self.assertRaises(ValueError):
            aes_encrypt(b"data", b"short")

    def test_aligned_block(self):
        # Test exactly 16-byte block (boundary case)
        plaintext = b"X" * 16
        encrypted = aes_encrypt(plaintext, self.KEY)
        # PKCS#7 padding adds another full block
        self.assertEqual(len(encrypted), 32)
        decrypted = aes_decrypt(encrypted, self.KEY)
        self.assertEqual(decrypted, plaintext)


class TestFrame(unittest.TestCase):
    KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

    def test_encode_decode_unencrypted(self):
        frame = Frame(
            command=Cmd.READ_DEVICE_INFO,
            data=b"\x01\x02\x03",
        )
        raw = frame.encode()
        decoded = Frame.decode(raw)
        self.assertEqual(decoded.command, Cmd.READ_DEVICE_INFO)
        self.assertEqual(decoded.data, b"\x01\x02\x03")
        self.assertEqual(decoded.encrypt, ENCRYPT_NO)

    def test_encode_decode_encrypted(self):
        frame = Frame(
            command=Cmd.UNLOCK,
            encrypt=ENCRYPT_YES,
            data=b"\x00\x00\x00\x00\x68\x12\x34\x56",
        )
        raw = frame.encode(self.KEY)

        decoded = Frame.decode(raw, self.KEY)
        self.assertEqual(decoded.command, Cmd.UNLOCK)
        self.assertEqual(decoded.data, b"\x00\x00\x00\x00\x68\x12\x34\x56")

    def test_header(self):
        frame = Frame(command=Cmd.LOCK, data=b"")
        raw = frame.encode()
        self.assertEqual(raw[:2], HEADER)

    def test_v3_protocol(self):
        frame = Frame(command=Cmd.UNLOCK, data=b"\x00")
        raw = frame.encode()
        self.assertEqual(raw[2], PROTOCOL_TYPE_V3)
        self.assertEqual(raw[3], SUB_VERSION_V3)

    def test_crc_added(self):
        frame = Frame(command=Cmd.UNLOCK, data=b"\x00")
        raw = frame.encode()
        # Last byte is CRC over all preceding
        crc = raw[-1]
        expected = crc8_maxim(raw[:-1])
        self.assertEqual(crc, expected)

    def test_bad_header_rejected(self):
        bad = b"\x00\x00" + b"\x05\x03\x00\x00\x00\x00\x00\x47\x00\x00\x00"
        with self.assertRaises(ValueError):
            Frame.decode(bad)

    def test_bad_crc_rejected(self):
        frame = Frame(command=Cmd.UNLOCK, data=b"\x00")
        raw = bytearray(frame.encode())
        raw[-1] ^= 0xFF  # flip CRC bits
        with self.assertRaises(ValueError):
            Frame.decode(bytes(raw))


class TestParseScienerKey(unittest.TestCase):
    def test_csv_hex_format(self):
        s = "00,01,02,03,04,05,06,07,08,09,0a,0b,0c,0d,0e,0f"
        key = parse_sciener_aeskey(s)
        self.assertEqual(len(key), 16)
        self.assertEqual(key.hex(), "000102030405060708090a0b0c0d0e0f")

    def test_invalid_length(self):
        with self.assertRaises(ValueError):
            parse_sciener_aeskey("01,02,03")


class TestParseScienerUnlockKey(unittest.TestCase):
    def test_round_trip(self):
        # Build a synthetic encoded value and verify parse returns the original.
        from ttlock_protocol import parse_sciener_unlock_key, _CRC_TABLE
        import base64
        plain = b"1234567890"
        seed = 42
        crc = _CRC_TABLE[len(plain)]
        encoded = bytes((seed ^ b ^ crc) & 0xFF for b in plain) + bytes([seed])
        csv = ",".join(str(b) for b in encoded).encode()
        b64 = base64.b64encode(csv).decode()
        self.assertEqual(parse_sciener_unlock_key(b64), 1234567890)


class TestBuildUnlock(unittest.TestCase):
    KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

    def test_unlock_frame_structure(self):
        raw = build_unlock_command(self.KEY, ps_from_lock=12345, unlock_key=67890, timestamp=1700000000)
        self.assertEqual(raw[:2], HEADER)
        self.assertEqual(raw[2], PROTOCOL_TYPE_V3)
        self.assertEqual(raw[3], SUB_VERSION_V3)
        self.assertEqual(raw[9], Cmd.UNLOCK)
        self.assertEqual(raw[10], ENCRYPT_YES)
        self.assertEqual(raw[-1], crc8_maxim(raw[:-1]))


if __name__ == "__main__":
    unittest.main()
