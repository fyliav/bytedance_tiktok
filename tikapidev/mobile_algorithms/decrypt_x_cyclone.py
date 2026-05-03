import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests
from config import BASE_URL, API_KEY


def decrypt_x_cyclone(input: str) -> dict:
    """
    Decrypt an X-Cyclone header value.

    Args:
        input: Base64-encoded X-Cyclone header value.

    Returns:
        API response as a dict.
    """
    url = f"{BASE_URL}/mobile/algo/decx-c"
    headers = {"x-api-key": API_KEY}
    payload = {"input": input}

    response = requests.post(url, json=payload, headers=headers)
    response.raise_for_status()
    return response.json()


if __name__ == "__main__":
    result = decrypt_x_cyclone(input="base64, cyclone header here")
    print(result)
