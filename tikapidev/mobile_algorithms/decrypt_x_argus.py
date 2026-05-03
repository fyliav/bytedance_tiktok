import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests
from config import BASE_URL, API_KEY


def decrypt_x_argus(platform: str, input: str) -> dict:
    """
    Decrypt an X-Argus header value.

    Args:
        platform: Platform string (e.g. "android").
        input:    Base64-encoded X-Argus value.

    Returns:
        API response as a dict.
    """
    url = f"{BASE_URL}/mobile/algo/decx-a"
    headers = {"x-api-key": API_KEY}
    payload = {
        "platform": platform,
        "input": input,
    }

    response = requests.post(url, json=payload, headers=headers)
    response.raise_for_status()
    return response.json()


if __name__ == "__main__":
    result = decrypt_x_argus(platform="android", input="base64 here")
    print(result)
