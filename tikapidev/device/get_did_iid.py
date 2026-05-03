import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests
from config import BASE_URL, API_KEY


def get_did_iid(region: str = "US", proxy: str = None) -> dict:
    """
    Get a Device ID (DID) and Install ID (IID).

    Args:
        region: Target region code (e.g. "US").
        proxy:  Optional proxy in user:pass@host:port format.

    Returns:
        API response as a dict.
    """
    url = f"{BASE_URL}/mobile/device/getdevice"
    headers = {"x-api-key": API_KEY}
    payload = {"region": region}
    if proxy:
        payload["proxy"] = proxy

    response = requests.post(url, json=payload, headers=headers)
    response.raise_for_status()
    return response.json()


if __name__ == "__main__":
    result = get_did_iid(region="US", proxy="user:pass@1.2.3.4:4439")
    print(result)
