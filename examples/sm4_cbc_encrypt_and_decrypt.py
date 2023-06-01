import secrets

from gmssl_pyx import (
    SM4_BLOCK_SIZE,
    SM4_KEY_SIZE,
    sm4_cbc_padding_decrypt,
    sm4_cbc_padding_encrypt,
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
