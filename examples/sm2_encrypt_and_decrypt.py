from gmssl_pyx import sm2_decrypt, sm2_encrypt, sm2_key_generate

# 生成 SM2 公私钥
public_key, private_key = sm2_key_generate()
# 加密
plaintext = b"hello world"
ciphertext = sm2_encrypt(public_key, plaintext)
print("ciphertext", ciphertext)
# 解密
plaintext = sm2_decrypt(private_key, ciphertext)
print("plaintext", plaintext)
