import typing as t

class GmsslInnerError(Exception):
    """libgmssl 库内部错误"""

class InvalidValueError(GmsslInnerError):
    """无效值"""

def sm2_key_generate() -> t.Tuple[bytes, bytes]:
    """生成 SM2 公私密钥对，公钥 64 字节，私钥 32 字节

    Returns: public_key, private_key

    Raises: GmsslInnerError
    """
    ...

def sm2_encrypt(public_key: bytes, plaintext: bytes) -> bytes:
    """使用 SM2 公钥加密数据

    Args:
        public_key: 64 字节的公钥
        plaintext: 明文数据，1 <= 长度 <= 255

    Returns: 密文数据，编码格式为 ASN.1 DER ，模式为 C1C3C2

    Raises: InvalidValueError, GmsslInnerError
    """
    ...

def sm2_decrypt(private_key: bytes, ciphertext: bytes) -> bytes:
    """使用 SM2 私钥解密数据

    Args:
        private_key: 32 字节的私钥
        ciphertext: 密文数据，45 <= 长度 <= 366 ，编码格式为 ASN.1 DER ，模式为 C1C3C2

    Returns: 明文数据

    Raises: InvalidValueError, GmsslInnerError
    """
    ...

def sm2_sign_sm3_digest(private_key: bytes, digest: bytes) -> bytes:
    """使用 SM2 签名 SM3 摘要数据

    Args:
        private_key: 32 字节的私钥
        digest: SM3 摘要数据，长度为 32 字节

    Returns: 签名数据，编码格式为 ASN.1 DER ，模式为 rs

    Raises: InvalidValueError, GmsslInnerError
    """
    ...

def sm2_verify_sm3_digest(public_key: bytes, digest: bytes, signature: bytes) -> bool:
    """使用 SM2 验证 SM3 摘要和签名数据

    Args:
        public_key: 64 字节的私钥
        digest: SM3 摘要数据，长度为 32 字节
        signature: 签名数据，编码格式为 ASN.1 DER ，模式为 rs

    Returns: 验证结果

    Raises: InvalidValueError, GmsslInnerError
    """
    ...

def sm2_sign(
    private_key: bytes,
    public_key: bytes,
    message: bytes,
    signer_id: t.Optional[bytes] = b"1234567812345678",
) -> bytes:
    """使用 SM2 签名消息数据

    Args:
        private_key: 32 字节的私钥
        public_key: 64 字节的公钥
        message: 消息数据
        signer_id: 签名者标识（一般情况下用默认值即可）；
            如果传 None ，签名不包括 SM3 杂凑值 z ，否则包括 SM3 杂凑值 z

    Returns: 签名数据，编码格式为 ASN.1 DER ，模式为 rs

    Raises: InvalidValueError, GmsslInnerError
    """
    ...

def sm2_verify(
    private_key: bytes,
    public_key: bytes,
    message: bytes,
    signature: bytes,
    signer_id: t.Optional[bytes] = b"1234567812345678",
) -> bool:
    """使用 SM2 验证消息数据的签名，包含 SM3 杂凑值 z

    Args:
        private_key: 32 字节的私钥
        public_key: 64 字节的公钥
        message: 消息数据
        signature: 签名数据，编码格式为 ASN.1 DER ，模式为 rs
        signer_id: 签名者标识（一般情况下用默认值即可），签名的时候传了啥，这里就传啥；
            如果传 None ，签名不包括 SM3 杂凑值 z ，否则包括 SM3 杂凑值 z

    Returns: 验证结果

    Raises: InvalidValueError, GmsslInnerError
    """
    ...

def sm3_hash(message: bytes) -> bytes:
    """SM3 hash 运算

    Args:
        message: 消息数据

    Returns: hash 数据
    """
    ...

def sm3_hmac(key: bytes, message: bytes) -> bytes:
    """SM3 hmac 运算

    Args:
        key: 密钥
        message: 消息数据

    Returns: hmac 运算后的数据
    """
    ...

def sm3_kdf(key: bytes, outlen: int) -> bytes:
    """SM3 kdf 密钥派生

    Args:
        key: 密钥
        outlen: 输出数据大小

    Returns: 输出数据
    """
    ...

def sm4_cbc_padding_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """使用 SM4 加密数据，模式为 CBC ， padding 采用 PKCS#7

    Args:
        key: 16 字节密钥
        iv: 16 字节初始向量
        plaintext: 明文数据

    Returns: 密文数据

    Raises: InvalidValueError
    """
    ...

def sm4_cbc_padding_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """使用 SM4 解密数据，模式为 CBC ， padding 采用 PKCS#7

    Args:
        key: 16 字节密钥
        iv: 16 字节初始向量
        ciphertext: 密文数据

    Returns: 明文数据

    Raises: InvalidValueError
    """
    ...

def sm4_ctr_encrypt(key: bytes, ctr: bytes, plaintext: bytes) -> bytes:
    """使用 SM4 加密数据，模式为 CTR

    Args:
        key: 16 字节密钥
        ctr: 16 字节初始计数器
        plaintext: 明文数据

    Returns: 密文数据

    Raises: InvalidValueError
    """
    ...

def sm4_ctr_decrypt(key: bytes, ctr: bytes, ciphertext: bytes) -> bytes:
    """使用 SM4 解密数据，模式为 CTR

    Args:
        key: 16 字节密钥
        ctr: 16 字节初始计数器
        ciphertext: 密文数据

    Returns: 明文数据

    Raises: InvalidValueError
    """
    ...

def sm4_gcm_encrypt(
    key: bytes, iv: bytes, aad: bytes, plaintext: bytes
) -> t.Tuple[bytes, bytes]:
    """使用 SM4 加密数据，模式为 GCM

    Args:
        key: 密钥
        iv: 初始化向量，也被叫做 nonce ，1 <= 长度 <= 64
        aad: 附加数据，也被叫做 associated_data
        plaintext: 明文数据

    Returns: 密文数据和标签
    """
    ...

def sm4_gcm_decrypt(
    key: bytes, iv: bytes, aad: bytes, ciphertext: bytes, tag: bytes
) -> bytes:
    """使用 SM4 解密数据，模式为 GCM

    Args:
        key: 密钥
        iv: 初始化向量，也被叫做 nonce ，1 <= 长度 <= 64
        aad: 附加数据，也被叫做 associated_data
        ciphertext: 密文数据
        tag: 标签

    Returns: 明文数据
    """
    ...

def rand_bytes(n: int) -> bytes:
    """生成 n 字节的随机字节数据

    Args:
        n: 字节数，范围为 [1, 256] ，包含 1 和 256

    Returns: 随机字节数据
    """
    ...

class SM9PrivateKey:
    """SM9 私钥"""

    @classmethod
    def from_der(cls, data: bytes) -> "SM9PrivateKey":
        """从 ASN.1 DER 编码的字节数据生成私钥"""
        ...
    def to_der(self) -> bytes:
        """将私钥转化为 ASN.1 DER 编码字节数据"""
        ...
    @classmethod
    def decrypt_from_der(cls, password: str, data: bytes) -> "SM9PrivateKey":
        """从加密的 ASN.1 DER 编码的字节数据生成私钥

        Args:
            password: 密码
            data: 加密的 ASN.1 DER 编码数据

        Return: 私钥
        """
        ...
    def encrypt_to_der(self, password: str) -> bytes:
        """将私钥转化为加密的 ASN.1 DER 编码字节数据"""
        ...
    @classmethod
    def decrypt_from_pem(cls, password: str, filepath: str) -> "SM9PrivateKey":
        """根据 pem 文件生成私钥"""
        ...
    def encrypt_to_pem(cls, password: str, filepath: str) -> None:
        """将私钥数据写入指定文件"""
        ...
    def decrypt(self, identity: bytes, ciphertext: bytes) -> bytes:
        """解密数据

        Args:
            identity: 用户标志
            ciphertext: 密文数据， ASN.1 DER 编码，长度 < 368

        Returns: 明文数据
        """
        ...

class SM9MasterPublicKey:
    """SM9 主公钥"""

    @classmethod
    def from_der(cls, data: bytes) -> "SM9MasterPublicKey":
        """从 ASN.1 DER 编码的字节数据生成公钥"""
        ...
    def to_der(self) -> bytes:
        """将公钥转化为 ASN.1 DER 编码字节数据"""
        ...
    @classmethod
    def from_pem(cls, filepath: str) -> "SM9MasterPublicKey":
        """根据 pem 文件生成主公钥"""
        ...
    def to_pem(self, filepath: str) -> None:
        """将公钥数据写入文件"""
        ...
    def encrypt(self, identity: bytes, plaintext: bytes) -> bytes:
        """加密数据

        Args:
            identity: 用户标志
            plaintext: 明文数据，长度 < 256

        Returns: 密文数据， ASN.1 DER 编码
        """
        ...

class SM9MasterKey:
    """SM9 主密钥"""

    @classmethod
    def generate(cls) -> "SM9MasterKey":
        """生成随机的主密钥。

        Returns: 主密钥
        """
        ...
    @classmethod
    def from_der(cls, data: bytes) -> "SM9MasterKey":
        """从 ASN.1 DER 编码的字节数据生成主密钥"""
        ...
    def to_der(self) -> bytes:
        """将主密钥转化为 ASN.1 DER 编码字节数据"""
        ...
    @classmethod
    def decrypt_from_der(cls, password: str, data: bytes) -> "SM9MasterKey":
        """从加密的 ASN.1 DER 编码的字节数据生成主密钥

        Args:
            password: 密码
            data: 加密的 ASN.1 DER 编码数据

        Return: 主密钥
        """
        ...
    def encrypt_to_der(self, password: str) -> bytes:
        """将主密钥转化为加密的 ASN.1 DER 编码字节数据"""
        ...
    @classmethod
    def decrypt_from_pem(cls, password: str, filepath: str) -> "SM9MasterKey":
        """根据加密的 pem 文件生成主密钥

        Args:
            password: 密码
            filepath: 文件路径

        Return: 主密钥
        """
    def encrypt_to_pem(self, password: str, filepath: str) -> None:
        """将主密钥转化为加密 pem 数据，并写入指定文件

        Args:
            password: 密码
            filepath: 文件路径

        """
    def extract_key(self, identity: bytes) -> "SM9PrivateKey":
        """根据用户标志生成私钥。

        Args:
            identity: 用户标志

        Returns: 私钥
        """
        ...
    def public_key(self) -> "SM9MasterPublicKey":
        """返回主公钥。

        Returns: 主公钥
        """
        ...
