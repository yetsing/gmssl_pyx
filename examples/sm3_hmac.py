import secrets

from gmssl_pyx import sm3_hmac

key = secrets.token_bytes(32)
message = b"sm3_hmac"
hmac_data = sm3_hmac(key, message)
print("message", message)
print("hmac_data", hmac_data)
