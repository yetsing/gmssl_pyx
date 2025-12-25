from Cryptodome.Util.asn1 import DerInteger, DerOctetString, DerSequence

from gmssl_pyx import sm2_decrypt, sm2_encrypt, sm2_key_generate, sm2_sign, sm2_verify

# 生成 SM2 公私钥
public_key, private_key = sm2_key_generate()
# 加密
plaintext = b"hello world"
ciphertext = sm2_encrypt(public_key, plaintext)
print("ciphertext", ciphertext)
seq_der = DerSequence()
decoded_ciphertext = seq_der.decode(ciphertext)
# ASN.1 DER 解码
# c1: point(x, y) 64bytes
# c2: ciphertext len(data)
# c3: hash 32bytes
# der order: c1x c1y hash ciphertext
c1x = decoded_ciphertext[0]
c1y = decoded_ciphertext[1]
c3 = DerOctetString().decode(decoded_ciphertext[2]).payload
c2 = DerOctetString().decode(decoded_ciphertext[3]).payload
# 模式为 C1C3C2
raw_ciphertext = c1x.to_bytes(32, "big") + c1y.to_bytes(32, "big") + c3 + c2

# 如果需要解密原始密文，需要先进行 ASN.1 DER 编码
seq_der = DerSequence()
c1x = raw_ciphertext[:32]
x = DerInteger(int.from_bytes(c1x, byteorder="big"))
seq_der.append(x)
c1y = raw_ciphertext[32:64]
y = DerInteger(int.from_bytes(c1y, byteorder="big"))
seq_der.append(y)
c3 = raw_ciphertext[64 : 64 + 32]
seq_der.append(DerOctetString(c3))
c2 = raw_ciphertext[64 + 32 :]
seq_der.append(DerOctetString(c2))
ciphertext = seq_der.encode()
plaintext = sm2_decrypt(private_key, ciphertext)
print("plaintext", plaintext)


message = b"hello world"
# 签名
signature = sm2_sign(private_key, public_key, message)
seq_der = DerSequence()
decoded_sign = seq_der.decode(signature)
# ASN.1 DER 解码，两个 32 字节的整数
r = decoded_sign[0]
s = decoded_sign[1]
print("r", r)
print("s", s)
raw_signature = "%064x%064x" % (r, s)

# 验证原始签名同样需要先进行 ASN.1 DER 编码
r = int(raw_signature[:64], base=16)
s = int(raw_signature[64:], base=16)
seq_der = DerSequence()
seq_der.append(DerInteger(r))
seq_der.append(DerInteger(s))
signature = seq_der.encode()
verify = sm2_verify(public_key, message, signature)
print("verify", verify)
