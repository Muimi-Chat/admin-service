import os
import requests

def generate_totp_token(userID, username):
    hostAddress = os.environ.get('AUTH_HOST_ADDRESS', 'email-api-url-not-set')
    hostPort = os.environ.get('AUTH_HOST_PORT', 'email-api-port-not-set')

    url = f"http://{hostAddress}:{hostPort}/totp/generate-token"
    headers = {
        'Authorization': os.environ.get('AUTH_API_KEY', 'email-api-key-not-set'),
    }

    data = {
        'accountID': userID,
        'username': username
    }

    response = requests.post(url, headers=headers, data=data)
    print(response, flush=True)
    result = response.json()
    return result