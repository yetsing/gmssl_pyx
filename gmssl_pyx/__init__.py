from gmssl_pyx.gmsslext import (
    # SM2
    sm2_key_generate,
    sm2_encrypt,
    sm2_decrypt,
    sm2_sign_sm3_digest,
    sm2_verify_sm3_digest,
    sm2_sign,
    sm2_verify,
    # SM3
    sm3_hash,
    sm3_hmac,
    sm3_kdf,
    # SM4
    sm4_cbc_padding_encrypt,
    sm4_cbc_padding_decrypt,
    sm4_ctr_encrypt,
    sm4_ctr_decrypt,
    sm4_gcm_encrypt,
    sm4_gcm_decrypt,
    # exception
    GmsslInnerError,
    InvalidValueError,
)
from gmssl_pyx.sm2_utils import normalize_sm2_public_key
from gmssl_pyx._version import (
    version_info,
    version,
    __version__,
)

SM2_DEFAULT_SIGNER_ID: bytes = b"1234567812345678"

SM4_KEY_SIZE: int = 16
SM4_BLOCK_SIZE:int = 16
SM4_NUM_ROUNDS: int = 32
