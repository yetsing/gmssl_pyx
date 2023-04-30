import typing as t

class GmsslInnerError(Exception):
    """libgmssl 库内部错误"""

class InvalidKeyError(GmsslInnerError):
    """无效的密钥"""

class InvalidArgumentError(GmsslInnerError):
    """无效的参数"""

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

def sm2_sign_sm3_digest(private_key: bytes, digest: bytes) -> bytes:
    """使用 SM2 签名 SM3 摘要数据

    Args:
        private_key: 32 字节的私钥
        digest: SM3 摘要数据，长度为 32 字节

    Returns: 签名数据，编码格式为 ASN.1 DER ，模式为 rs
    """
    ...

def sm2_verify_sm3_digest(public_key: bytes, digest: bytes, signature: bytes) -> bool:
    """使用 SM2 验证 SM3 摘要和签名数据

    Args:
        public_key: 64 字节的私钥
        digest: SM3 摘要数据，长度为 32 字节
        signature: 签名数据，编码格式为 ASN.1 DER ，模式为 rs

    Returns: 验证结果
    """
    ...
