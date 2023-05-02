import binascii
import random
import secrets
import unittest

from gmssl_pyx import (
    sm3_hash,
    sm3_hmac,
    sm3_kdf,
)


class SM3TestCase(unittest.TestCase):
    def test_hash(self):
        n = random.randint(1, 4096)
        message = secrets.token_bytes(n)
        hash_data = sm3_hash(message)

        expected_hash = binascii.unhexlify(
            "4ad5db882c722fc615041a22ed37568a40008b37b5fbba8937486a97983e3f64",
        )
        message = b"test_sm2_sign_and_verify"
        got_hash = sm3_hash(message=message)
        self.assertEqual(got_hash, expected_hash)

        expected_hash = binascii.unhexlify(
            "44f0061e69fa6fdfc290c494654a05dc0c053da7e5c52b84ef93a9d67d3fff88",
        )
        message = b"hello world"
        got_hash = sm3_hash(message=message)
        self.assertEqual(got_hash, expected_hash)

    def test_hmac(self):
        n = random.randint(1, 4096)
        message = secrets.token_bytes(n)
        key = secrets.token_bytes(32)
        hmac_data = sm3_hmac(key, message)

        key = binascii.unhexlify(
            "daac25c1512fe50f79b0e4526b93f5c0e1460cef40b6dd44af13caec62e8c60e0d885f3c6d6fb51e530889e6fd4ac743a6d332e68a0f2a3923f42585dceb93e9",
        )
        message = b"hello world"
        hmac_data = sm3_hmac(key, message=message)
        expected_hex = (
            "92aee474f6111e74f4745b0b10973eb2c397fa883ffa03df7b0d401a08b4a641"
        )
        self.assertEqual(hmac_data.hex(), expected_hex)

    def test_kdf(self):
        key = secrets.token_bytes(32)
        new_key = sm3_kdf(key, 64)
        self.assertEqual(len(new_key), 64)

        key = b"hello world"
        new_key = sm3_kdf(key, 32)
        expected_key = binascii.unhexlify(
            "52bd8a3dac8ccc8d9fac365005a7e210f80fe450033dd71e3ecdf120862747a6"
        )
        self.assertEqual(new_key, expected_key)
