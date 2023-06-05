import os
import secrets
import tempfile
import unittest

from gmssl_pyx import (
    SM9_MAX_CIPHERTEXT_SIZE,
    SM9_MAX_PLAINTEXT_SIZE,
    InvalidValueError,
    SM9MasterKey,
    SM9MasterPublicKey,
    SM9PrivateKey,
)


class SM9CipherTest(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        # 切换当前工作目录到临时目录
        self.cwd = os.getcwd()
        self.tempdir = tempfile.TemporaryDirectory()
        os.chdir(self.tempdir.name)

    def tearDown(self) -> None:
        super().tearDown()
        os.chdir(self.cwd)
        self.tempdir.cleanup()

    def test_sm9_encrypt_and_decrypt(self):
        identity = secrets.token_bytes(6)

        master = SM9MasterKey.generate()
        key = master.extract_key(identity)
        public_key = master.public_key()

        n = secrets.randbelow(SM9_MAX_PLAINTEXT_SIZE)
        plaintext = secrets.token_bytes(n)
        ciphertext = public_key.encrypt(identity, plaintext)
        got = key.decrypt(identity, ciphertext)
        self.assertEqual(got, plaintext)

    def test_sm9_encrypt_and_decrypt_error(self):
        identity = secrets.token_bytes(6)

        master = SM9MasterKey.generate()
        key = master.extract_key(identity)
        public_key = master.public_key()

        plaintext = secrets.token_bytes(SM9_MAX_PLAINTEXT_SIZE + 1)
        with self.assertRaises(InvalidValueError) as cm:
            public_key.encrypt(identity, plaintext)
        self.assertEqual(str(cm.exception), "invalid sm9 plaintext length")

        ciphertext = secrets.token_bytes(SM9_MAX_CIPHERTEXT_SIZE + 1)
        with self.assertRaises(InvalidValueError) as cm:
            key.decrypt(identity, ciphertext)
        self.assertEqual(str(cm.exception), "invalid sm9 ciphertext length")

    def test_sm9_master_key_der(self):
        identity = secrets.token_bytes(6)

        master = SM9MasterKey.generate()
        key = master.extract_key(identity)
        public_key = master.public_key()

        n = secrets.randbelow(SM9_MAX_PLAINTEXT_SIZE)
        plaintext = secrets.token_bytes(n)
        ciphertext = public_key.encrypt(identity, plaintext)
        got = key.decrypt(identity, ciphertext)
        self.assertEqual(got, plaintext)

        master_der = master.to_der()
        master2 = SM9MasterKey.from_der(master_der)
        key2 = master2.extract_key(identity)
        got = key2.decrypt(identity, ciphertext)
        self.assertEqual(got, plaintext)

        public_key2 = master2.public_key()
        ciphertext = public_key2.encrypt(identity, plaintext)
        got = key.decrypt(identity, ciphertext)
        self.assertEqual(got, plaintext)

        plaintext = secrets.token_bytes(n)
        ciphertext = public_key2.encrypt(identity, plaintext)
        got = key2.decrypt(identity, ciphertext)
        self.assertEqual(got, plaintext)

    def test_sm9_master_key_pem(self):
        identity = secrets.token_bytes(6)

        master = SM9MasterKey.generate()
        key = master.extract_key(identity)
        public_key = master.public_key()

        n = secrets.randbelow(SM9_MAX_PLAINTEXT_SIZE)
        plaintext = secrets.token_bytes(n)
        ciphertext = public_key.encrypt(identity, plaintext)
        got = key.decrypt(identity, ciphertext)
        self.assertEqual(got, plaintext)

        password = "password"
        pem_filename = "sm9_master.pem"
        master.encrypt_to_pem(password, pem_filename)
        master2 = SM9MasterKey.decrypt_from_pem(password, pem_filename)
        key2 = master2.extract_key(identity)
        got = key2.decrypt(identity, ciphertext)
        self.assertEqual(got, plaintext)

        public_key2 = master2.public_key()
        ciphertext = public_key2.encrypt(identity, plaintext)
        got = key.decrypt(identity, ciphertext)
        self.assertEqual(got, plaintext)

        plaintext = secrets.token_bytes(n)
        ciphertext = public_key2.encrypt(identity, plaintext)
        got = key2.decrypt(identity, ciphertext)
        self.assertEqual(got, plaintext)

    def test_sm9_master_key_encrypt_der(self):
        identity = secrets.token_bytes(6)

        master = SM9MasterKey.generate()
        key = master.extract_key(identity)
        public_key = master.public_key()

        n = secrets.randbelow(SM9_MAX_PLAINTEXT_SIZE)
        plaintext = secrets.token_bytes(n)
        ciphertext = public_key.encrypt(identity, plaintext)
        got = key.decrypt(identity, ciphertext)
        self.assertEqual(got, plaintext)

        password = "password"
        master_der = master.encrypt_to_der(password)
        master2 = SM9MasterKey.decrypt_from_der(password, master_der)
        key2 = master2.extract_key(identity)
        got = key2.decrypt(identity, ciphertext)
        self.assertEqual(got, plaintext)

        public_key2 = master2.public_key()
        ciphertext = public_key2.encrypt(identity, plaintext)
        got = key.decrypt(identity, ciphertext)
        self.assertEqual(got, plaintext)

        plaintext = secrets.token_bytes(n)
        ciphertext = public_key2.encrypt(identity, plaintext)
        got = key2.decrypt(identity, ciphertext)
        self.assertEqual(got, plaintext)

    def test_public_key_der(self):
        identity = secrets.token_bytes(6)

        master = SM9MasterKey.generate()
        key = master.extract_key(identity)
        public_key = master.public_key()

        n = secrets.randbelow(SM9_MAX_PLAINTEXT_SIZE)
        plaintext = secrets.token_bytes(n)
        ciphertext = public_key.encrypt(identity, plaintext)
        got = key.decrypt(identity, ciphertext)
        self.assertEqual(got, plaintext)

        pkey_der = public_key.to_der()
        public_key = SM9MasterPublicKey.from_der(pkey_der)
        ciphertext = public_key.encrypt(identity, plaintext)
        got = key.decrypt(identity, ciphertext)
        self.assertEqual(got, plaintext)

        pkey_der2 = public_key.to_der()
        self.assertEqual(pkey_der, pkey_der2)

    def test_public_key_pem(self):
        identity = secrets.token_bytes(6)

        master = SM9MasterKey.generate()
        key = master.extract_key(identity)
        public_key = master.public_key()

        n = secrets.randbelow(SM9_MAX_PLAINTEXT_SIZE)
        plaintext = secrets.token_bytes(n)
        ciphertext = public_key.encrypt(identity, plaintext)
        got = key.decrypt(identity, ciphertext)
        self.assertEqual(got, plaintext)

        pem_filename = "sm9_public.pem"
        public_key.to_pem(pem_filename)
        public_key = SM9MasterPublicKey.from_pem(pem_filename)
        ciphertext = public_key.encrypt(identity, plaintext)
        got = key.decrypt(identity, ciphertext)
        self.assertEqual(got, plaintext)

    def test_private_key_der(self):
        identity = secrets.token_bytes(6)

        master = SM9MasterKey.generate()
        key = master.extract_key(identity)
        public_key = master.public_key()

        n = secrets.randbelow(SM9_MAX_PLAINTEXT_SIZE)
        plaintext = secrets.token_bytes(n)
        ciphertext = public_key.encrypt(identity, plaintext)
        got = key.decrypt(identity, ciphertext)
        self.assertEqual(got, plaintext)

        pkey_der = key.to_der()
        key = SM9PrivateKey.from_der(pkey_der)
        got = key.decrypt(identity, ciphertext)
        self.assertEqual(got, plaintext)

        pkey_der2 = key.to_der()
        self.assertEqual(pkey_der, pkey_der2)

    def test_private_key_pem(self):
        identity = secrets.token_bytes(6)

        master = SM9MasterKey.generate()
        key = master.extract_key(identity)
        public_key = master.public_key()

        n = secrets.randbelow(SM9_MAX_PLAINTEXT_SIZE)
        plaintext = secrets.token_bytes(n)
        ciphertext = public_key.encrypt(identity, plaintext)
        got = key.decrypt(identity, ciphertext)
        self.assertEqual(got, plaintext)

        password = "password"
        pem_filename = "sm9_private.pem"
        key.encrypt_to_pem(password, pem_filename)
        key = SM9PrivateKey.decrypt_from_pem(password, pem_filename)
        got = key.decrypt(identity, ciphertext)
        self.assertEqual(got, plaintext)

    def test_private_key_encrypt_der(self):
        identity = secrets.token_bytes(6)

        master = SM9MasterKey.generate()
        key = master.extract_key(identity)
        public_key = master.public_key()

        n = secrets.randbelow(SM9_MAX_PLAINTEXT_SIZE)
        plaintext = secrets.token_bytes(n)
        ciphertext = public_key.encrypt(identity, plaintext)
        got = key.decrypt(identity, ciphertext)
        self.assertEqual(got, plaintext)

        password = "password"
        pkey_der = key.encrypt_to_der(password)
        key = SM9PrivateKey.decrypt_from_der(password, pkey_der)
        got = key.decrypt(identity, ciphertext)
        self.assertEqual(got, plaintext)
