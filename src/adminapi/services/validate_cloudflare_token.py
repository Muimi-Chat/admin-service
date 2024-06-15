
import os
import requests

def validate_cloudflare_token(token, ip_address):
    url = 'https://challenges.cloudflare.com/turnstile/v0/siteverify'
    secret_key = os.environ.get('CLOUDFLARE_SECRET_KEY', 'secret key not set')
    response_value = token

    if ip_address == "localhost":
        ip_address = "127.0.0.1"
    
    data = {
        'secret': secret_key,
        'response': response_value,
    }

    response = requests.post(url, data=data)
    result = response.json()
    return result['success']