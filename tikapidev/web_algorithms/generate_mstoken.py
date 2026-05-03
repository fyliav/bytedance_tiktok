import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests
from config import BASE_URL, API_KEY


def generate_mstoken() -> dict:
    """
    Generate a valid MsToken for TikTok browser / www.tiktok.com.

    Returns:
        API response as a dict, e.g. {"msToken": "...", "userAgent": "..."}.
    """
    url = f"{BASE_URL}/mstoken"
    headers = {"x-api-key": API_KEY}

    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json()


if __name__ == "__main__":
    result = generate_mstoken()
    print(result)
