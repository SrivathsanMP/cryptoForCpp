""" from Crypto.Cipher import AES
import hashlib

# 🚨 Weak AES key (only 5 bytes)
key = b'12345'

# 🚨 ECB Mode usage
cipher = AES.new(key, AES.MODE_ECB)
ciphertext = cipher.encrypt(b'1234567890123456')

# 🚨 Insecure hash function
hash_object = hashlib.md5(b"hello world")
digest = hash_object.hexdigest() """

from cryptography.fernet import Fernet

key = Fernet.generate_key()
cipher = Fernet(key)

message = b"Hello"
token = cipher.encrypt(message)
print(token)
