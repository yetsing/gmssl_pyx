import typing as t

def sm2_key_generate() -> t.Tuple[bytes, bytes]:
    """生成 SM2 公私密钥对，公钥 64 字节，私钥 32 字节

    Returns: public_key, private_key
    """
    ...

def sm2_encrypt(public_key: bytes, plaintext: bytes) -> bytes:
    """使用 SM2 公钥加密数据

    Args:
        public_key: 64 字节的公钥
        plaintext: 明文数据，长度范围为 [1, 255]

    Returns: 密文数据，编码格式为 ASN.1 DER ，模式为 C1C3C2
    """
    ...

def sm2_decrypt(private_key: bytes, ciphertext: bytes) -> bytes:
    """使用 SM2 私钥解密数据

    Args:
        private_key: 32 字节的私钥
        ciphertext: 密文数据，长度范围为 [45, 366]，编码格式为 ASN.1 DER ，模式为 C1C3C2

    Returns: 明文数据
    """
    ...
