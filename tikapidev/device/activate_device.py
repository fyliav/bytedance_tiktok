import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests
from config import BASE_URL, API_KEY


def activate_device(device: dict, region: str = "US", proxy: str = None) -> dict:
    """
    Activate a TikTok mobile device.

    Args:
        device: Device object containing device_id, install_id, and header.
        region: Target region code (e.g. "US").
        proxy:  Optional proxy in user:pass@host:port format.

    Returns:
        API response as a dict.
    """
    url = f"{BASE_URL}/mobile/device/activation"
    headers = {"x-api-key": API_KEY}
    payload = {
        "device": device,
        "region": region,
    }
    if proxy:
        payload["proxy"] = proxy

    response = requests.post(url, json=payload, headers=headers)
    response.raise_for_status()
    return response.json()


if __name__ == "__main__":
    result = activate_device(
        device={
            "device_id": "7378012345678901234",
            "install_id": "7378012345678901235",
            "header": {},
        },
        region="US",
        proxy="user:pass@1.2.3.4:4439",
    )
    print(result)
