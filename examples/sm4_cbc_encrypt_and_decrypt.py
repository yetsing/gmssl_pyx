import secrets
from gmssl_pyx import (
    sm4_cbc_padding_encrypt,
    sm4_cbc_padding_decrypt,
    SM4_KEY_SIZE,
    SM4_BLOCK_SIZE,
)


key = secrets.token_bytes(SM4_KEY_SIZE)
iv = secrets.token_bytes(SM4_BLOCK_SIZE)
plaintext = b"hello world"
# 加密
ciphertext = sm4_cbc_padding_encrypt(key, iv, plaintext)
print("ciphertext", ciphertext.hex())

# 解密
decrypted = sm4_cbc_padding_decrypt(key, iv, ciphertext)
print("decrypted", decrypted)
