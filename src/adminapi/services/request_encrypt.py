
import os
import requests

def request_encrypt(id: str, content: str, metadata: str = ""):
    authorization_key = os.environ.get('CAPPU_CRYPT_API_KEY', 'key-not-set')
    target_host = os.environ.get('CAPPU_CRYPT_HOST', 'key-not-set')
    target_port = os.environ.get('CAPPU_CRYPT_PORT', 'key-not-set')
    
    url = f'http://{target_host}:{target_port}/crypt/encrypt'
    headers = {
        'Authorization': authorization_key
    }
    data = {
        'id': id,
        'content': content,
        'metadata': metadata
    }

    response = requests.post(url, headers=headers, data=data)
    data = response.json()
    return data['encryptedContent']