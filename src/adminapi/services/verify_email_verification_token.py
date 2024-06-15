import os
import requests

def verify_email_verification_token(tokenID, token):
    hostAddress = os.environ.get('AUTH_HOST_ADDRESS', 'email-api-url-not-set')
    hostPort = os.environ.get('AUTH_HOST_PORT', 'email-api-port-not-set')

    url = f"http://{hostAddress}:{hostPort}/email/verify-token"
    headers = {
        'Authorization': os.environ.get('AUTH_API_KEY', 'email-api-key-not-set'),
    }

    data = {
        'tokenID': int(tokenID),
        'token': token
    }

    response =  requests.post(url, headers=headers, data=data)
    result = response.json()
    return result