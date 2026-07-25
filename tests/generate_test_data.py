import json
import random
import secrets
import sys
from pathlib import Path

script_dir = Path(__file__).parent.resolve()
data_dir = script_dir / "data"
data_dir.mkdir(exist_ok=True)

sys.path.insert(0, str(script_dir.parent))
from gmssl_pyx import (
    SM4_BLOCK_SIZE,
    SM4_KEY_SIZE,
    SM9_MAX_PLAINTEXT_SIZE,
    SM9MasterKey,
    SM9MasterPublicKey,
    SM9PrivateKey,
    sm2_encrypt,
    sm2_key_generate,
    sm2_sign,
    sm2_sign_sm3_digest,
    sm4_cbc_padding_encrypt,
    sm4_ctr_encrypt,
    sm4_gcm_encrypt,
)


def generate_sm2():
    d = []
    for _ in range(16):
        public_key, private_key = sm2_key_generate()
        encrypted_data = []
        signed_digests = []
        signed_data = []
        for _ in range(3):
            plaintext = secrets.token_bytes(random.randint(1, 255))
            ciphertext = sm2_encrypt(public_key, plaintext)
            encrypted_data.append(
                {
                    "plaintext": plaintext.hex(),
                    "ciphertext": ciphertext.hex(),
                }
            )
            digest = secrets.token_bytes(32)
            signature = sm2_sign_sm3_digest(private_key, digest)
            signed_digests.append(
                {
                    "digest": digest.hex(),
                    "signature": signature.hex(),
                }
            )
            message_length = random.randint(1, 1024)
            message = secrets.token_bytes(message_length)
            signature = sm2_sign(private_key, public_key, message)
            signed_data.append(
                {
                    "message": message.hex(),
                    "signature": signature.hex(),
                }
            )
            signature = sm2_sign(
                private_key,
                public_key,
                message=message,
                signer_id=None,
            )
            signed_data.append(
                {
                    "message": message.hex(),
                    "signature": signature.hex(),
                    "signer_id": None,
                }
            )
            signer_id = secrets.token_bytes(16)
            signature = sm2_sign(
                private_key, public_key, message=message, signer_id=signer_id
            )
            signed_data.append(
                {
                    "message": message.hex(),
                    "signature": signature.hex(),
                    "signer_id": signer_id.hex(),
                }
            )
        d.append(
            {
                "public_key": public_key.hex(),
                "private_key": private_key.hex(),
                "encrypted_data": encrypted_data,
                "signed_digests": signed_digests,
                "signed_data": signed_data,
            }
        )
    with open(data_dir / "sm2_generated_key.json", "w", encoding="utf-8") as f:
        json.dump(d, f, ensure_ascii=False, indent=4)


def generate_sm4():
    # cbc
    cbc_data = []
    for _ in range(16):
        n = random.randint(1, 4096)
        plaintext = secrets.token_bytes(n)
        key = secrets.token_bytes(SM4_KEY_SIZE)
        iv = secrets.token_bytes(SM4_BLOCK_SIZE)
        ciphertext = sm4_cbc_padding_encrypt(key, iv, plaintext=plaintext)
        cbc_data.append(
            {
                "key": key.hex(),
                "iv": iv.hex(),
                "plaintext": plaintext.hex(),
                "ciphertext": ciphertext.hex(),
            }
        )

    # ctr
    ctr_data = []
    for _ in range(16):
        n = random.randint(1, 4096)
        plaintext = secrets.token_bytes(n)
        key = secrets.token_bytes(SM4_KEY_SIZE)
        ctr = secrets.token_bytes(SM4_BLOCK_SIZE)
        ciphertext = sm4_ctr_encrypt(key, ctr, plaintext=plaintext)
        ctr_data.append(
            {
                "key": key.hex(),
                "ctr": ctr.hex(),
                "plaintext": plaintext.hex(),
                "ciphertext": ciphertext.hex(),
            }
        )

    # gcm
    gcm_data = []
    for _ in range(16):
        n = random.randint(1, 4096)
        plaintext = secrets.token_bytes(n)
        key = secrets.token_bytes(SM4_KEY_SIZE)
        iv = secrets.token_bytes(SM4_BLOCK_SIZE)
        aad = secrets.token_bytes(16)
        ciphertext, tag = sm4_gcm_encrypt(key, iv, plaintext=plaintext, aad=aad)
        gcm_data.append(
            {
                "key": key.hex(),
                "iv": iv.hex(),
                "aad": aad.hex(),
                "plaintext": plaintext.hex(),
                "ciphertext": ciphertext.hex(),
                "tag": tag.hex(),
            }
        )

    d = {
        "cbc": cbc_data,
        "ctr": ctr_data,
        "gcm": gcm_data,
    }
    with open(data_dir / "sm4_generated_key.json", "w", encoding="utf-8") as f:
        json.dump(d, f, ensure_ascii=False, indent=4)


def generate_sm9():
    # 生成主密钥
    master = SM9MasterKey.generate()
    # 根据主密钥生成公钥和私钥
    identity = "张三".encode()
    public_key = master.public_key()
    private_key = master.extract_key(identity)

    encrypted_data = []
    for _ in range(16):
        n = secrets.randbelow(SM9_MAX_PLAINTEXT_SIZE) + 1
        plaintext = secrets.token_bytes(n)
        ciphertext = public_key.encrypt(identity, plaintext)
        encrypted_data.append(
            {
                "plaintext": plaintext.hex(),
                "ciphertext": ciphertext.hex(),
            }
        )

    # 公私钥导出 pem
    public_pem_filename = data_dir / "sm9_public.pem"
    public_key.to_pem(str(public_pem_filename))
    password = "your password"
    private_pem_filename = data_dir / "sm9_private.pem"
    private_key.encrypt_to_pem(password, str(private_pem_filename))

    master.encrypt_to_pem(password, str(data_dir / "sm9_master.pem"))

    pub = public_key.to_der()
    priv = private_key.to_der()
    priv_encrypted = private_key.encrypt_to_der(password)
    d = {
        "identity": identity.hex(),
        "password": password,
        "public_key": pub.hex(),
        "private_key": priv.hex(),
        "private_key_encrypted": priv_encrypted.hex(),
        "encrypted_data": encrypted_data,
    }
    with open(data_dir / "sm9_generated_key.json", "w", encoding="utf-8") as f:
        json.dump(d, f, ensure_ascii=False, indent=4)


def main():
    generate_sm2()
    generate_sm4()
    generate_sm9()


if __name__ == "__main__":
    main()
