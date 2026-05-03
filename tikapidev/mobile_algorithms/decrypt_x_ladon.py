import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests
from config import BASE_URL, API_KEY


def decrypt_x_ladon(input: str, aid: str = "") -> dict:
    """
    Decrypt an X-Ladon header value.

    Args:
        input: Raw X-Ladon header value.
        aid:   App ID (e.g. "1233").

    Returns:
        API response as a dict.
    """
    url = f"{BASE_URL}/mobile/algo/decx-l"
    headers = {"x-api-key": API_KEY}
    payload = {
        "input": input,
        "aid": aid,
    }

    response = requests.post(url, json=payload, headers=headers)
    response.raise_for_status()
    return response.json()


if __name__ == "__main__":
    result = decrypt_x_ladon(input="ladon header here", aid="1233")
    print(result)
