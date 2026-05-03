import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests
from config import BASE_URL, API_KEY


def encrypt_x_medusa(
    url: str,
    device_id: str,
    token: str = "",
    seed: str = "",
) -> dict:
    """
    Encrypt an X-Medusa header value.

    Args:
        url:       Target request URL.
        device_id: TikTok device ID.
        token:     Optional token.
        seed:      Optional seed value.

    Returns:
        API response as a dict.
    """
    endpoint = f"{BASE_URL}/mobile/algo/encx-m"
    headers = {"x-api-key": API_KEY}
    payload = {
        "url": url,
        "device_id": device_id,
        "token": token,
        "seed": seed,
    }

    response = requests.post(endpoint, json=payload, headers=headers)
    response.raise_for_status()
    return response.json()


if __name__ == "__main__":
    result = encrypt_x_medusa(
        url="https://api16-normal-c-alisg.ttapis.com/aweme/v1/feed/",
        device_id="7123456789012345678",
        token="",
        seed="",
    )
    print(result)
