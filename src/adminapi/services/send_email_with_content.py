import os
import requests

def send_email_with_content(email, subject, content):
    url = os.environ.get('MAILING_SERVICE_SERVER', 'email-api-url-not-set') + "/send"
    headers = {
        'Authorization': os.environ.get('MAILING_API_KEY', 'email-api-key-not-set'),
    }

    data = {
        'content': content,
        'subject': subject,
        'target': email
    }

    response = requests.post(url, headers=headers, data=data)
    result = response.json()
    return result