import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests
from config import BASE_URL, API_KEY


def follow_user(
    sessionid: str,
    user_id: str = "",
    sec_user_id: str = "",
    proxy: str = None,
) -> dict:
    """
    Follow a TikTok user.

    Args:
        sessionid:   Account session ID (ALISG).
        user_id:     Target user ID.
        sec_user_id: Target secure user ID.
        proxy:       Optional proxy in user:pass@host:port format.

    Returns:
        API response as a dict.
    """
    url = f"{BASE_URL}/mobile/actions/follow"
    headers = {"x-api-key": API_KEY}
    payload = {
        "sessionid": sessionid,
        "user_id": user_id,
        "sec_user_id": sec_user_id,
    }
    if proxy:
        payload["proxy"] = proxy

    response = requests.post(url, json=payload, headers=headers)
    response.raise_for_status()
    return response.json()


if __name__ == "__main__":
    result = follow_user(
        sessionid="ACCOUNT SESSION ID (ALISG)",
        user_id="123456789",
        sec_user_id="",
        proxy="user:pass@1.2.3.4:4439",
    )
    print(result)
