import os
import requests

def verify_totp_code(userID, code):
    hostAddress = os.environ.get('AUTH_HOST_ADDRESS', 'email-api-url-not-set')
    hostPort = os.environ.get('AUTH_HOST_PORT', 'email-api-port-not-set')

    url = f"http://{hostAddress}:{hostPort}/totp/verify-code"
    headers = {
        'Authorization': os.environ.get('AUTH_API_KEY', 'email-api-key-not-set'),
    }

    data = {
        'accountID': userID,
        'code': code
    }

    response = requests.post(url, headers=headers, data=data)
    result = response.json()
    return result