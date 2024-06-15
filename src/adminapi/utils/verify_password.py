import os
from argon2 import PasswordHasher, exceptions

def verify_password(hashed_password, password):
    try:
        pepper_hex = os.environ.get('PEPPER_KEY', 'pepper-not-set')
        pepper_bytes = bytes.fromhex(pepper_hex)

        hasher = PasswordHasher()
        hasher.verify(hashed_password, password.encode() + pepper_bytes)
        return True
    except exceptions.VerifyMismatchError:
        return False