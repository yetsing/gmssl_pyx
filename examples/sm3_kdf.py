import secrets

from gmssl_pyx import sm3_kdf

key = secrets.token_bytes(32)
new_key = sm3_kdf(key, 32)
print("kdf new_key", new_key)
