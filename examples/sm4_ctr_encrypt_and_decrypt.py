import secrets

from gmssl_pyx import SM4_BLOCK_SIZE, SM4_KEY_SIZE, sm4_ctr_decrypt, sm4_ctr_encrypt

key = secrets.token_bytes(SM4_KEY_SIZE)
ctr = secrets.token_bytes(SM4_BLOCK_SIZE)
plaintext = b"hello world"
# 加密
ciphertext = sm4_ctr_encrypt(key, ctr, plaintext)
print("ciphertext", ciphertext.hex())

# 解密
decrypted = sm4_ctr_decrypt(key, ctr, ciphertext)
print("decrypted", decrypted)
