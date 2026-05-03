import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests
from config import BASE_URL, API_KEY


def generate_fpverify() -> dict:
    """
    Generate an FpVerify value for TikTok.com.

    Returns:
        API response as a dict.
    """
    url = f"{BASE_URL}/fpverify"
    headers = {"x-api-key": API_KEY}

    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json()


if __name__ == "__main__":
    result = generate_fpverify()
    print(result)
