import os
from argon2 import PasswordHasher

def hash_password(password):
    pepper_hex = os.environ.get('PEPPER_KEY', 'pepper-not-set')
    pepper_bytes = bytes.fromhex(pepper_hex)

    hasher = PasswordHasher()
    return hasher.hash(password.encode() + pepper_bytes)