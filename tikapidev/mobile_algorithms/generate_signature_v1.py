import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests
from config import BASE_URL, API_KEY


def generate_signature_v1(
    device_id: str,
    url: str,
    method: str = "POST",
    body: str = "",
) -> dict:
    """
    Generate a TikTok mobile signature (V1 / legacy).

    Args:
        device_id: TikTok device ID.
        url:       Full request URL.
        method:    HTTP method (default "POST").
        body:      Request body string.

    Returns:
        API response as a dict.
    """
    endpoint = f"{BASE_URL}/mobile/algo/old/gensign"
    headers = {"x-api-key": API_KEY}
    payload = {
        "device_id": device_id,
        "url": url,
        "method": method,
        "body": body,
    }

    response = requests.post(endpoint, json=payload, headers=headers)
    response.raise_for_status()
    return response.json()


if __name__ == "__main__":
    result = generate_signature_v1(
        device_id="7123456789012345678",
        url="https://api16-normal-c-alisg.ttapis.com/aweme/v1/feed/?aid=1233",
        method="POST",
        body="",
    )
    print(result)
