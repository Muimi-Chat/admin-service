import os
import requests

def generate_email_verification_token(userID):
    hostAddress = os.environ.get('AUTH_HOST_ADDRESS', 'email-api-url-not-set')
    hostPort = os.environ.get('AUTH_HOST_PORT', 'email-api-port-not-set')

    url = f"http://{hostAddress}:{hostPort}/email/create-token"
    headers = {
        'Authorization': os.environ.get('AUTH_API_KEY', 'email-api-key-not-set'),
    }

    data = {
        'userID': userID
    }

    response = requests.post(url, headers=headers, data=data)
    result = response.json()
    return result