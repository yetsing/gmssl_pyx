from gmssl_pyx._version import __version__, version, version_info
from gmssl_pyx.gmsslext import (  # SM2; SM3; SM4; SM9; exception
    GmsslInnerError,
    InvalidValueError,
    SM9MasterKey,
    SM9MasterPublicKey,
    SM9PrivateKey,
    rand_bytes,
    sm2_decrypt,
    sm2_encrypt,
    sm2_key_generate,
    sm2_sign,
    sm2_sign_sm3_digest,
    sm2_verify,
    sm2_verify_sm3_digest,
    sm3_hash,
    sm3_hmac,
    sm3_kdf,
    sm4_cbc_padding_decrypt,
    sm4_cbc_padding_encrypt,
    sm4_ctr_decrypt,
    sm4_ctr_encrypt,
    sm4_gcm_decrypt,
    sm4_gcm_encrypt,
)
from gmssl_pyx.sm2_utils import normalize_sm2_public_key

SM2_DEFAULT_SIGNER_ID: bytes = b"1234567812345678"

SM4_KEY_SIZE: int = 16
SM4_BLOCK_SIZE: int = 16
SM4_NUM_ROUNDS: int = 32

SM9_MAX_PLAINTEXT_SIZE: int = 255
SM9_MAX_CIPHERTEXT_SIZE: int = 367
