import secrets
from gmssl_pyx import sm4_gcm_encrypt, sm4_gcm_decrypt, SM4_KEY_SIZE, SM4_BLOCK_SIZE


plaintext = b"hello world"
key = secrets.token_bytes(SM4_KEY_SIZE)
iv = secrets.token_bytes(SM4_BLOCK_SIZE)
aad = secrets.token_bytes(16)
# 加密
ciphertext, tag = sm4_gcm_encrypt(key, iv, aad, plaintext=plaintext)
print("ciphertext", ciphertext)

# 解密
plaintext = sm4_gcm_decrypt(key, iv=iv, aad=aad, ciphertext=ciphertext, tag=tag)
print("plaintext", plaintext)
