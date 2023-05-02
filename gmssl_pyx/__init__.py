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

SM2_DEFAULT_SIGNER_ID = b"1234567812345678"
