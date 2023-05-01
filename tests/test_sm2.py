import secrets
import unittest

from gmssl_pyx import (
    sm2_key_generate,
    sm2_encrypt,
    sm2_decrypt,
    sm2_sign_sm3_digest,
    sm2_verify_sm3_digest,
    GmsslInnerError,
    InvalidValueError,
)


class SM2TestCase(unittest.TestCase):
    def test_sm2_encrypt_and_decrypt(self):
        public_key, private_key = sm2_key_generate()
        plaintext = b"hello world"
        ciphertext = sm2_encrypt(public_key, plaintext)
        decrypted = sm2_decrypt(private_key, ciphertext)
        self.assertEqual(plaintext, decrypted)

    def test_sm2_encrypt_and_decrypt_error(self):
        public_key, private_key = sm2_key_generate()
        with self.assertRaises(GmsslInnerError):
            sm2_encrypt(public_key, b"")
        with self.assertRaises(GmsslInnerError):
            sm2_encrypt(public_key, b"1" * 256)
        with self.assertRaises(InvalidValueError):
            sm2_encrypt(b"abc", b"hello world")
        with self.assertRaises(TypeError):
            sm2_encrypt("abc", b"hello world")
        with self.assertRaises(TypeError):
            sm2_encrypt(public_key, "hello world")

        with self.assertRaises(InvalidValueError):
            sm2_decrypt(public_key, b"hello" * 10)
        with self.assertRaises(GmsslInnerError):
            sm2_decrypt(private_key, b"1" * 44)
        with self.assertRaises(GmsslInnerError):
            sm2_decrypt(private_key, b"1" * 367)
        with self.assertRaises(TypeError):
            sm2_decrypt("a" * 32, b"1" * 60)
        with self.assertRaises(TypeError):
            sm2_decrypt(private_key, "1" * 60)

    def test_sm2_sign_and_verify_sm3_digest(self):
        public_key, private_key = sm2_key_generate()
        digest = secrets.token_bytes(32)
        signature = sm2_sign_sm3_digest(private_key, digest)
        self.assertTrue(
            sm2_verify_sm3_digest(public_key, digest, signature),
        )

    def test_sm2_sign_and_verify_sm3_digest_error(self):
        public_key, private_key = sm2_key_generate()
        digest = secrets.token_bytes(32)
        with self.assertRaises(InvalidValueError):
            sm2_sign_sm3_digest(b"123", digest)
        with self.assertRaises(InvalidValueError):
            sm2_sign_sm3_digest(private_key, digest[:31])

        with self.assertRaises(InvalidValueError):
            sm2_verify_sm3_digest(b"123", digest, b"")
        with self.assertRaises(InvalidValueError):
            sm2_verify_sm3_digest(public_key, digest[:31], b"")

    def test_error_inheri(self):
        self.assertTrue(issubclass(GmsslInnerError, Exception))
        self.assertTrue(issubclass(InvalidValueError, GmsslInnerError))
