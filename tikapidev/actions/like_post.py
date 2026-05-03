import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests
from config import BASE_URL, API_KEY


def like_post(sessionid: str, aweme_id: str, proxy: str = None) -> dict:
    """
    Like a TikTok post.

    Args:
        sessionid: Account session ID (ALISG).
        aweme_id:  ID of the post to like.
        proxy:     Optional proxy in user:pass@host:port format.

    Returns:
        API response as a dict.
    """
    url = f"{BASE_URL}/mobile/actions/like"
    headers = {"x-api-key": API_KEY}
    payload = {
        "sessionid": sessionid,
        "aweme_id": aweme_id,
    }
    if proxy:
        payload["proxy"] = proxy

    response = requests.post(url, json=payload, headers=headers)
    response.raise_for_status()
    return response.json()


if __name__ == "__main__":
    result = like_post(
        sessionid="YOUR SESSIONID HERE (ALISG)",
        aweme_id="7234567890123456789",
        proxy="user:pass@1.2.3.4:4439",
    )
    print(result)
