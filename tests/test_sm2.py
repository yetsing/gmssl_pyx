import unittest
from gmssl_pyx import (
    sm2_key_generate,
    sm2_encrypt,
    sm2_decrypt,
    GmsslInnerError,
    InvalidKeyError,
)
import time

import binascii
import gmssl.sm2


class SM2TestCase(unittest.TestCase):
    def test_sm2_encrypt_and_decrypt(self):
        public_key, private_key = sm2_key_generate()
        sm2_crypto = gmssl.sm2.CryptSM2(
            binascii.hexlify(private_key).decode(),
            binascii.hexlify(public_key).decode(),
        )
        plaintext = b'hello world'
        t = time.perf_counter()
        ciphertext = sm2_crypto.encrypt(plaintext)
        decrypted = sm2_crypto.decrypt(ciphertext)
        e = time.perf_counter()
        print('gmssl used in seconds', e - t)
        self.assertEqual(plaintext, decrypted)

        ciphertext = sm2_encrypt(public_key, plaintext)
        decrypted = sm2_decrypt(private_key, ciphertext)
        self.assertEqual(plaintext, decrypted)

    def test_sm2_encrypt_and_decrypt_error(self):
        public_key, private_key = sm2_key_generate()
        with self.assertRaises(GmsslInnerError):
            sm2_encrypt(public_key, b'')
        with self.assertRaises(GmsslInnerError):
            sm2_encrypt(public_key, b'1' * 256)
        with self.assertRaises(InvalidKeyError):
            sm2_encrypt(b'abc', b'hello world')
        with self.assertRaises(TypeError):
            sm2_encrypt('abc', b'hello world')
        with self.assertRaises(TypeError):
            sm2_encrypt(public_key, 'hello world')

        with self.assertRaises(InvalidKeyError):
            sm2_decrypt(public_key, b'hello' * 10)
        with self.assertRaises(GmsslInnerError):
            sm2_decrypt(private_key, b'1' * 44)
        with self.assertRaises(GmsslInnerError):
            sm2_decrypt(private_key, b'1' * 367)
        with self.assertRaises(TypeError):
            sm2_decrypt('a' * 32, b'1' * 60)
        with self.assertRaises(TypeError):
            sm2_decrypt(private_key, '1' * 60)
