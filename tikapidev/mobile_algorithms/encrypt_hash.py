import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests
from config import BASE_URL, API_KEY


def encrypt_hash(query: str, body: str = "", which: str = "all") -> dict:
    """
    Get every 20xx signatures (Encrypt Hash).

    Args:
        query: URL query string (e.g. "aid=1233&device_id=7123456789012345678").
        body:  Request body string.
        which: Which signatures to return (e.g. "all").

    Returns:
        API response as a dict.
    """
    url = f"{BASE_URL}/mobile/algo/enchash"
    headers = {"x-api-key": API_KEY}
    payload = {
        "query": query,
        "body": body,
        "which": which,
    }

    response = requests.post(url, json=payload, headers=headers)
    response.raise_for_status()
    return response.json()


if __name__ == "__main__":
    result = encrypt_hash(
        query="aid=1233&device_id=7123456789012345678",
        body="",
        which="all",
    )
    print(result)
