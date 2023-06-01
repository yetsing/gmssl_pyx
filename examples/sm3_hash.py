from gmssl_pyx import sm3_hash

message = b"hello world"
signature = sm3_hash(message)
print("message", message)
print("signature", signature.hex())
