import binascii
import typing as t
from gmssl_pyx.gmsslext import InvalidValueError

g_default_ecc_table = {
    "n": "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
    "p": "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
    "g": "32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7"
    "bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0",
    "a": "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",
    "b": "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",
}
ga = int(g_default_ecc_table["a"], 16)
gb = int(g_default_ecc_table["b"], 16)
gp = int(g_default_ecc_table["p"], 16)


HexStr = str


def decompress_sm2_public_key(key: bytes, a: int, b: int, p: int) -> bytes:
    prefix = key[0]
    x = int.from_bytes(key[1:], "big")
    # y^2 = (x^3 + ax + b) % p
    y_sq = (x**3 + a * x + b) % p
    y = pow(y_sq, (p + 1) // 4, p)
    # y 是偶数，前缀为 '\x02' ；奇数则是 '\x03'
    if (prefix - 2) != (y % 2):
        # y 的奇偶与前缀表示不同
        y = p - y
    return x.to_bytes(32, byteorder="big") + y.to_bytes(32, byteorder="big")


def normalize_sm2_public_key(public_key: t.Union[HexStr, bytes]) -> bytes:
    """返回本库可直接使用的公钥格式

    Args:
        public_key: 16 进制字符串或者字节串

    Returns: 64 字节的字节串
    """
    pk: bytes = public_key
    if not isinstance(public_key, bytes):
        pk = binascii.unhexlify(public_key)

    if len(pk) == 65:
        if pk[0] != 4:
            raise InvalidValueError("invalid public key")
        return pk[1:]
    elif len(pk) == 64:
        return pk
    elif len(pk) == 33:
        return decompress_sm2_public_key(pk, ga, gb, gp)
    else:
        raise InvalidValueError("invalid public key")
