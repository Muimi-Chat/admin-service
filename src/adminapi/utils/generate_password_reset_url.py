
import os

def generate_password_reset_url(tokenID, token):
    clientHostAddress = os.environ.get('CLIENT_HOST_ADDRESS', 'localhost')
    
    sslEnabled = os.environ.get('CLIENT_SSL_ENABLED', 'FALSE') == 'TRUE'
    baseHttp = f"http{'s' if sslEnabled else ''}"
    return f"{baseHttp}://{clientHostAddress}/confirm-password-reset#id={tokenID}&code={token}"