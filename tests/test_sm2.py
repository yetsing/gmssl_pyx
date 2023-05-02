import random
import secrets
import unittest

from gmssl_pyx import (
    sm2_key_generate,
    sm2_encrypt,
    sm2_decrypt,
    sm2_sign_sm3_digest,
    sm2_verify_sm3_digest,
    sm2_sign,
    sm2_verify,
    normalize_sm2_public_key,
    GmsslInnerError,
    InvalidValueError,
)


class SM2TestCase(unittest.TestCase):
    def test_sm2_encrypt_and_decrypt(self):
        public_key, private_key = sm2_key_generate()
        n = random.randint(1, 255)
        plaintext = secrets.token_bytes(n)
        # args 传参
        ciphertext = sm2_encrypt(public_key, plaintext)
        decrypted = sm2_decrypt(private_key, ciphertext)
        self.assertEqual(plaintext, decrypted)
        # kwargs 传参
        ciphertext = sm2_encrypt(
            public_key=public_key,
            plaintext=plaintext,
        )
        decrypted = sm2_decrypt(
            private_key=private_key,
            ciphertext=ciphertext,
        )
        self.assertEqual(plaintext, decrypted)
        # 混合传参
        ciphertext = sm2_encrypt(
            public_key,
            plaintext=plaintext,
        )
        decrypted = sm2_decrypt(
            private_key,
            ciphertext=ciphertext,
        )
        self.assertEqual(plaintext, decrypted)

    def test_sm2_encrypt_and_decrypt_error(self):
        public_key, private_key = sm2_key_generate()
        with self.assertRaises(InvalidValueError):
            sm2_encrypt(public_key, b"")
        with self.assertRaises(InvalidValueError):
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
        # args 传参
        signature = sm2_sign_sm3_digest(private_key, digest)
        self.assertTrue(
            sm2_verify_sm3_digest(public_key, digest, signature),
        )
        # kwargs 传参
        signature = sm2_sign_sm3_digest(
            private_key=private_key,
            digest=digest,
        )
        self.assertTrue(
            sm2_verify_sm3_digest(
                public_key=public_key,
                digest=digest,
                signature=signature,
            )
        )
        # 混合传参
        signature = sm2_sign_sm3_digest(
            private_key,
            digest=digest,
        )
        self.assertTrue(
            sm2_verify_sm3_digest(
                public_key,
                digest=digest,
                signature=signature,
            )
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

    def test_error_inherit(self):
        self.assertTrue(issubclass(GmsslInnerError, Exception))
        self.assertTrue(issubclass(InvalidValueError, GmsslInnerError))

    def test_sm2_sign_and_verify(self):
        public_key, private_key = sm2_key_generate()
        message_length = random.randint(1, 1024)
        message = secrets.token_bytes(message_length)
        # use default signer_id
        signature = sm2_sign(private_key, public_key, message)
        verify = sm2_verify(private_key, public_key, message, signature)
        self.assertTrue(verify)
        verify = sm2_verify(private_key, public_key, message, secrets.token_bytes(32))
        self.assertFalse(verify)
        # without signer_id
        signature = sm2_sign(private_key, public_key, message, signer_id=None)
        verify = sm2_verify(private_key, public_key, message, signature, signer_id=None)
        self.assertTrue(verify)
        verify = sm2_verify(
            private_key, public_key, message, secrets.token_bytes(32), signer_id=None
        )
        self.assertFalse(verify)
        # random signer_id
        signer_id = secrets.token_bytes(16)
        signature = sm2_sign(
            private_key, public_key, message=message, signer_id=signer_id
        )
        verify = sm2_verify(
            private_key,
            public_key,
            message=message,
            signature=signature,
            signer_id=signer_id,
        )
        self.assertTrue(verify)
        verify = sm2_verify(
            private_key,
            public_key,
            message=message,
            signature=secrets.token_bytes(32),
            signer_id=signer_id,
        )
        self.assertFalse(verify)

    def test_normalize_sm2_public_key(self):
        raw_public_key, _ = sm2_key_generate()
        k1 = normalize_sm2_public_key(raw_public_key)
        self.assertEqual(k1, raw_public_key)
        k1 = normalize_sm2_public_key(b"\x04" + raw_public_key)
        self.assertEqual(k1, raw_public_key)

        # 压缩版公钥
        y = int.from_bytes(raw_public_key[32:], byteorder="big")
        if y % 2 == 0:
            # y 是偶数
            compressed_public_key = b"\x02" + raw_public_key[:32]
        else:
            compressed_public_key = b"\x03" + raw_public_key[:32]
        k1 = normalize_sm2_public_key(compressed_public_key)
        self.assertEqual(k1, raw_public_key)
