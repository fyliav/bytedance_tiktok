import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests
from config import BASE_URL, API_KEY


def ztca_dpop_encryption(method: str, url: str) -> dict:
    """
    Generate a ZTCA-DPOP token.

    Args:
        method: HTTP method for the DPoP proof (e.g. "POST").
        url:    Target URL for the DPoP proof (e.g. "https://webcast.tiktok.com/webcast/room/chat/").

    Returns:
        API response as a dict containing ztca-dpop and ztca-version.
    """
    endpoint = f"{BASE_URL}/web/ztcadpop/enc"
    headers = {"x-api-key": API_KEY}
    payload = {
        "method": method,
        "url": url,
    }

    response = requests.post(endpoint, json=payload, headers=headers)
    response.raise_for_status()
    return response.json()


if __name__ == "__main__":
    result = ztca_dpop_encryption(
        method="POST",
        url="https://webcast.tiktok.com/webcast/room/chat/",
    )
    print(result)
