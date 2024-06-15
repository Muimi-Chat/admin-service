import os
import requests

def generate_recovery_codes(userID):
    hostAddress = os.environ.get('AUTH_HOST_ADDRESS', 'email-api-url-not-set')
    hostPort = os.environ.get('AUTH_HOST_PORT', 'email-api-port-not-set')

    url = f"http://{hostAddress}:{hostPort}/totp/generate-recovery-code"
    headers = {
        'Authorization': os.environ.get('AUTH_API_KEY', 'email-api-key-not-set'),
    }

    data = {
        'accountID': userID
    }

    response = requests.post(url, headers=headers, data=data)
    result = response.json()
    return result