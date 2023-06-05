from gmssl_pyx import SM9MasterKey, SM9MasterPublicKey, SM9PrivateKey

# 生成主密钥
master = SM9MasterKey.generate()
# 根据主密钥生成公钥和私钥
identity = "张三".encode()
public_key = master.public_key()
private_key = master.extract_key(identity)
# 公私钥导出 pem
public_pem_filename = "sm9_public.pem"
public_key.to_pem(public_pem_filename)
password = "your password"
private_pem_filename = "sm9_private.pem"
private_key.encrypt_to_pem(password, private_pem_filename)

# 导入公私钥
public_key = SM9MasterPublicKey.from_pem(public_pem_filename)
private_key = SM9PrivateKey.decrypt_from_pem(password, private_pem_filename)
# 加密
plaintext = b"hello world"
ciphertext = public_key.encrypt(identity, plaintext)
print("ciphertext", ciphertext)
# 解密
plaintext = private_key.decrypt(identity, ciphertext)
print("plaintext", plaintext)
