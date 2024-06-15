import os
import hashlib

def hash_email(email):
    pepper_hex = os.environ.get('PEPPER_KEY', 'pepper-not-set')
    pepper_bytes = bytes.fromhex(pepper_hex)

    hasher = hashlib.sha256()
    hasher.update(email.encode() + pepper_bytes)
    return hasher.hexdigest()