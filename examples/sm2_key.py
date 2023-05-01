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
