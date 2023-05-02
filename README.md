# gmssl_pyx

python wrapper of [GmSSL](https://github.com/guanzhi/GmSSL)

使用的版本是 [GmSSL-3.1.0](https://github.com/guanzhi/GmSSL/releases/tag/v3.1.0)

支持 Python 3.7, 3.8, 3.9, 3.10

## 安装

```shell
pip install gmssl_pyx
```

## SM2

### 加密和解密

```python
from gmssl_pyx import sm2_key_generate, sm2_encrypt, sm2_decrypt


# 生成 SM2 公私钥
public_key, private_key = sm2_key_generate()
# 加密
plaintext = b"hello world"
ciphertext = sm2_encrypt(public_key, plaintext)
print("ciphertext", ciphertext)
# 解密
plaintext = sm2_decrypt(private_key, ciphertext)
print("plaintext", plaintext)

```

### 签名和验签

```python
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
```

### ASN.1 DER 编码

加密和签名的结果都是 ASN.1 DER 编码，如果要得到原始的密文和签名，可以参考下面的例子

需要安装 pycryptodomex 库

```shell
pip install pycryptodomex
```

```python
from Cryptodome.Util.asn1 import DerSequence, DerOctetString, DerInteger
from gmssl_pyx import sm2_key_generate, sm2_encrypt, sm2_decrypt


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
x = DerInteger(int.from_bytes(c1x, byteorder='big'))
seq_der.append(x)
c1y = raw_ciphertext[32:64]
y = DerInteger(int.from_bytes(c1y, byteorder='big'))
seq_der.append(y)
c3 = raw_ciphertext[64:64 + 32]
seq_der.append(DerOctetString(c3))
c2 = raw_ciphertext[64 +32:]
seq_der.append(DerOctetString(c2))
ciphertext = seq_der.encode()
plaintext = sm2_decrypt(private_key, ciphertext)
print("plaintext", plaintext)

# 签名
signature = sm2_sign(private_key, public_key, message)
seq_der = DerSequence()
decoded_sign = seq_der.decode(signature)
# ASN.1 DER 解码，两个 32 字节的整数
r = decoded_sign[0]
s = decoded_sign[1]
print('r', r)
print('s', s)
raw_signature = '%064x%064x' % (r, s)

# 验证原始签名同样需要先进行 ASN.1 DER 编码
r = int(raw_signature[:64], base=16)
s = int(raw_signature[64:], base=16)
seq_der = DerSequence()
seq_der.append(DerInteger(r))
seq_der.append(DerInteger(s))
signature = seq_der.encode()
verify = sm2_verify(private_key, public_key, message, signature)
print('verify', verify)
```

### 公私钥的一些补充说明

公钥长度为 64 字节，是两个 32 字节的整数 x y 拼接而成。

如果公钥长度为 65 字节，那么第一个字节为 '\x04' ，表示后面的 64 字节就是公钥。

如果公钥长度为 33 字节，那么第一个字节为 '\x02' 或者 '\x03' ， 
这是一种压缩格式，后面的 32 字节为整数 x ， y 可以根据 x 计算出来。

私钥长度为 32 字节，没有其他变化。

```python
from gmssl_pyx import sm2_key_generate, normalize_sm2_public_key


raw_public_key, _ = sm2_key_generate()
k1 = normalize_sm2_public_key(raw_public_key)
assert k1 == raw_public_key
k1 = normalize_sm2_public_key(b'\x04' + raw_public_key)
assert k1 == raw_public_key

# 压缩版公钥
y = int.from_bytes(raw_public_key[32:], byteorder='big')
if y % 2 == 0:
    # y 是偶数
    compressed_public_key = b'\x02' +raw_public_key[:32]
else:
    compressed_public_key = b'\x03' + raw_public_key[:32]
k1 = normalize_sm2_public_key(compressed_public_key)
assert k1 == raw_public_key
```

## SM3

### hash 计算

```python
from gmssl_pyx import sm3_hash


message = b'hello world'
signature = sm3_hash(message)
print('message', message)
print('signature', signature.hex())
```

### hmac 计算

```python
import secrets
from gmssl_pyx import sm3_hmac


key = secrets.token_bytes(32)
message = b"sm3_hmac"
hmac_data = sm3_hmac(key, message)
print("message", message)
print("hmac_data", hmac_data)
```

### kdf 计算

```python
import secrets
from gmssl_pyx import sm3_kdf


key = secrets.token_bytes(32)
new_key = sm3_kdf(key, 32)
print('kdf new_key', new_key)
```

## SM4

### CBC 模式加密和解密

```python
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

```

### CTR 模式加密和解密

```python
import secrets
from gmssl_pyx import (
    sm4_ctr_encrypt,
    sm4_ctr_decrypt,
    SM4_KEY_SIZE,
    SM4_BLOCK_SIZE,
)


key = secrets.token_bytes(SM4_KEY_SIZE)
ctr = secrets.token_bytes(SM4_BLOCK_SIZE)
plaintext = b"hello world"
# 加密
ciphertext = sm4_ctr_encrypt(key, ctr, plaintext)
print("ciphertext", ciphertext.hex())

# 解密
decrypted = sm4_ctr_decrypt(key, ctr, ciphertext)
print("decrypted", decrypted)

```

### GCM 模式加密和解密

```python
import secrets
from gmssl_pyx import sm4_gcm_encrypt, sm4_gcm_decrypt, SM4_KEY_SIZE, SM4_BLOCK_SIZE


plaintext = b'hello world'
key = secrets.token_bytes(SM4_KEY_SIZE)
iv = secrets.token_bytes(SM4_BLOCK_SIZE)
aad = secrets.token_bytes(16)
# 加密
ciphertext, tag = sm4_gcm_encrypt(key, iv, aad, plaintext=plaintext)
print('ciphertext', ciphertext)

# 解密
plaintext = sm4_gcm_decrypt(key, iv=iv, aad=aad, ciphertext=ciphertext, tag=tag)
print('plaintext', plaintext)

```
