import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests
from config import BASE_URL, API_KEY


def get_web_signatures_v2(
    query: str,
    user_agent: str,
    body: str = "",
) -> dict:
    """
    Generate web signatures X-Gnarly and X-Bogus (V2).

    Args:
        query:      URL query string (e.g. "aid=1988&device_platform=webapp&channel=tiktok_web").
        user_agent: Browser User-Agent string.
        body:       Optional request body string.

    Returns:
        API response as a dict containing x_bogus, x_gnarly, signed_query, and headers.
    """
    url = f"{BASE_URL}/web-sign"
    headers = {"x-api-key": API_KEY}
    payload = {
        "query": query,
        "body": body,
        "user_agent": user_agent,
    }

    response = requests.post(url, json=payload, headers=headers)
    response.raise_for_status()
    return response.json()


if __name__ == "__main__":
    result = get_web_signatures_v2(
        query="aid=1988&device_platform=webapp&channel=tiktok_web",
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/142.0.0.0 Safari/537.36"
        ),
        body="",
    )
    print(result)
