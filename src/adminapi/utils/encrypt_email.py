import os
import warnings

from cryptography.fernet import Fernet

def encrypt_email(email):
    warnings.warn(
        "encrypt_email is deprecated, and you should use `request_encrypt` instead.",
        DeprecationWarning,
        stacklevel=2
    )
    cipher_suite = Fernet(os.environ.get('AES_SECRET', 'key-not-set').encode())
    return cipher_suite.encrypt(email.encode()).decode()