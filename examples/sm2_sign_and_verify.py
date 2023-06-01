from gmssl_pyx import sm2_key_generate, sm2_sign, sm2_verify

# 生成 SM2 公私钥
public_key, private_key = sm2_key_generate()

# 没有 signer_id 和 SM3 杂凑值 z
# 签名
message = b"hello world"
signature = sm2_sign(private_key, public_key, message, signer_id=None)
print("signature", signature)
# 验证签名
verify = sm2_verify(private_key, public_key, message, signature, signer_id=None)
print("verify", verify)

# 默认 signer_id 和 SM3 杂凑值 z
signature = sm2_sign(private_key, public_key, message)
print("signature", signature)
# 验证签名
verify = sm2_verify(private_key, public_key, message, signature)
print("verify", verify)

# 自定义 signer_id 和 SM3 杂凑值 z
signer_id = b"signer_id"
signature = sm2_sign(private_key, public_key, message, signer_id=signer_id)
print("signature", signature)
# 验证签名
verify = sm2_verify(private_key, public_key, message, signature, signer_id=signer_id)
print("verify", verify)
