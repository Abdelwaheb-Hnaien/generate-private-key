import base64
import os
from crypto_lab import key_from_password
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

password_provided = 'MyVeryComplicatedPassword'
salt = b'\xae\x1aim\xfd\xd87\xcae\x0b\x08\x94%\x86k('

#Output file
keyfile = 'mykey.key'

key_from_password(password_provided, salt, keyfile)
