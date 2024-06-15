import os
import traceback
from django.conf import settings

import requests

def get_country_from_ip(ip_address):
    try:
        response = requests.get(f'https://ipapi.co/{ip_address}/json/').json()

        if response.get('error') and response.get('reserved'):
            # Likely debug due to internal IP Address, default to singapore...
            return "Singapore"
        country = response.get("country_name")
        return country
    except Exception as e:
        log_message = f"Tried to get a geo-location from IP address but failed due to :: {e}\n\n{traceback.format_exc()}"
        print(log_message, flush=True)
        return None