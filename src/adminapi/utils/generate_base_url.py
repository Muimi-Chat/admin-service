import os

def generate_base_url():
    clientHostAddress = os.environ.get('CLIENT_HOST_ADDRESS', 'localhost')
    
    sslEnabled = os.environ.get('CLIENT_SSL_ENABLED', 'FALSE') == 'TRUE'
    baseHttp = f"http{'s' if sslEnabled else ''}"
    return f"{baseHttp}://{clientHostAddress}"