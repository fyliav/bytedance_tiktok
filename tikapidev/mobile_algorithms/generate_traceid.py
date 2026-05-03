import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests
from config import BASE_URL, API_KEY


def generate_traceid(device_id: str) -> dict:
    """
    Generate a TikTok TraceID for a given device.

    Args:
        device_id: TikTok device ID.

    Returns:
        API response as a dict.
    """
    url = f"{BASE_URL}/mobile/algo/gentraceid"
    headers = {"x-api-key": API_KEY}
    payload = {"device_id": device_id}

    response = requests.post(url, json=payload, headers=headers)
    response.raise_for_status()
    return response.json()


if __name__ == "__main__":
    result = generate_traceid(device_id="7123456789012345678")
    print(result)
