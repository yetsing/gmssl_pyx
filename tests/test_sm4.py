import random
import secrets
import unittest

from gmssl_pyx import (
    sm4_cbc_padding_encrypt,
    sm4_cbc_padding_decrypt,
    sm4_ctr_encrypt,
    sm4_ctr_decrypt,
    sm4_gcm_encrypt,
    sm4_gcm_decrypt,
    SM4_KEY_SIZE,
    SM4_BLOCK_SIZE,
    InvalidValueError,
)


class SM4TestCase(unittest.TestCase):
    def test_cbc_encrypt_and_decrypt(self):
        for i in range(3):
            n = random.randint(1, 4096)
            plaintext = secrets.token_bytes(n)
            key = secrets.token_bytes(SM4_KEY_SIZE)
            iv = secrets.token_bytes(SM4_BLOCK_SIZE)
            ciphertext = sm4_cbc_padding_encrypt(key, iv, plaintext=plaintext)
            got_plaintext = sm4_cbc_padding_decrypt(
                key=key, iv=iv, ciphertext=ciphertext
            )
            self.assertEqual(got_plaintext, plaintext)

    def test_cbc_encrypt_and_decrypt_error(self):
        key = secrets.token_bytes(SM4_KEY_SIZE + 1)
        iv = secrets.token_bytes(SM4_BLOCK_SIZE)
        plaintext = b"hello world"
        ciphertext = b"ciphertext"
        with self.assertRaises(InvalidValueError) as cm:
            sm4_cbc_padding_encrypt(key, iv, plaintext)
            self.assertEqual(str(cm.exception), "invalid sm4 key length")
        with self.assertRaises(InvalidValueError) as cm:
            sm4_cbc_padding_decrypt(key, iv, ciphertext)
            self.assertEqual(str(cm.exception), "invalid sm4 key length")
        key = secrets.token_bytes(SM4_KEY_SIZE)
        iv = secrets.token_bytes(SM4_BLOCK_SIZE + 1)
        with self.assertRaises(InvalidValueError) as cm:
            sm4_cbc_padding_encrypt(key, iv, plaintext)
            self.assertEqual(str(cm.exception), "invalid sm4 iv length")
        with self.assertRaises(InvalidValueError) as cm:
            sm4_cbc_padding_decrypt(key, iv, ciphertext)
            self.assertEqual(str(cm.exception), "invalid sm4 iv length")

    def test_ctr_encrypt_and_decrypt(self):
        for i in range(3):
            n = random.randint(1, 4096)
            plaintext = secrets.token_bytes(20)
            key = secrets.token_bytes(SM4_KEY_SIZE)
            ctr = secrets.token_bytes(SM4_BLOCK_SIZE)
            ciphertext = sm4_ctr_encrypt(key, ctr, plaintext=plaintext)
            got_plaintext = sm4_ctr_decrypt(key=key, ctr=ctr, ciphertext=ciphertext)
            self.assertEqual(got_plaintext, plaintext)

    def test_ctr_encrypt_and_decrypt_error(self):
        key = secrets.token_bytes(SM4_KEY_SIZE + 1)
        ctr = secrets.token_bytes(SM4_BLOCK_SIZE)
        plaintext = b"hello world"
        ciphertext = b"ciphertext"
        with self.assertRaises(InvalidValueError) as cm:
            sm4_ctr_encrypt(key, ctr, plaintext)
            self.assertEqual(str(cm.exception), "invalid sm4 key length")
        with self.assertRaises(InvalidValueError) as cm:
            sm4_ctr_decrypt(key, ctr, ciphertext)
            self.assertEqual(str(cm.exception), "invalid sm4 key length")
        key = secrets.token_bytes(SM4_KEY_SIZE)
        ctr = secrets.token_bytes(SM4_BLOCK_SIZE + 1)
        with self.assertRaises(InvalidValueError) as cm:
            sm4_ctr_encrypt(key, ctr, plaintext)
            self.assertEqual(str(cm.exception), "invalid sm4 iv length")
        with self.assertRaises(InvalidValueError) as cm:
            sm4_ctr_decrypt(key, ctr, ciphertext)
            self.assertEqual(str(cm.exception), "invalid sm4 iv length")

    def test_gcm_encrypt_and_decrypt(self):
        for i in range(3):
            n = random.randint(1, 4096)
            plaintext = secrets.token_bytes(n)
            key = secrets.token_bytes(SM4_KEY_SIZE)
            iv = secrets.token_bytes(SM4_BLOCK_SIZE)
            aad = secrets.token_bytes(16)
            ciphertext, tag = sm4_gcm_encrypt(key, iv, aad, plaintext=plaintext)
            got_plaintext = sm4_gcm_decrypt(
                key, iv=iv, aad=aad, ciphertext=ciphertext, tag=tag
            )
            self.assertEqual(got_plaintext, plaintext)

    def test_gcm_encrypt_and_decrypt_error(self):
        key = secrets.token_bytes(SM4_KEY_SIZE + 1)
        iv = secrets.token_bytes(SM4_BLOCK_SIZE)
        aad = secrets.token_bytes(16)
        plaintext = b"hello world"
        ciphertext = b"ciphertext"
        with self.assertRaises(InvalidValueError) as cm:
            sm4_gcm_encrypt(key, iv, aad, plaintext)
            self.assertEqual(str(cm.exception), "invalid sm4 key length")
        with self.assertRaises(InvalidValueError) as cm:
            sm4_gcm_decrypt(key, iv, aad, ciphertext, tag=secrets.token_bytes(16))
            self.assertEqual(str(cm.exception), "invalid sm4 key length")
