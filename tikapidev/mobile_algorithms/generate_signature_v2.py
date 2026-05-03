import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests
from config import BASE_URL, API_KEY


def generate_signature_v2(
    device_id: str,
    url: str,
    method: str = "POST",
    body: str = "",
    platform: str = "android",
    license_id: str = "1611921764",
    sdk_version_str: str = "v04.04.05-ov-android",
    sdk_version: int = 167904322,
    device_type: str = "SM925",
    channel: str = "googleplay",
    app_version: str = "38.3.0",
    os_version: str = "17.4.1",
    token: str = "",
    seed: str = "",
    aid: str = "1233",
    cookies: str = "",
) -> dict:
    """
    Generate a TikTok mobile signature (V2).

    Args:
        device_id:        TikTok device ID.
        url:              Full request URL.
        method:           HTTP method (default "POST").
        body:             Request body string.
        platform:         Platform string (default "android").
        license_id:       License ID string.
        sdk_version_str:  SDK version string.
        sdk_version:      SDK version integer.
        device_type:      Device model string.
        channel:          Distribution channel (e.g. "googleplay").
        app_version:      TikTok app version.
        os_version:       OS version string.
        token:            Optional token.
        seed:             Optional seed value.
        aid:              App ID (default "1233").
        cookies:          Optional cookies string.

    Returns:
        API response as a dict.
    """
    endpoint = f"{BASE_URL}/mobile/algo/gensign"
    headers = {"x-api-key": API_KEY}
    payload = {
        "device_id": device_id,
        "url": url,
        "method": method,
        "body": body,
        "platform": platform,
        "license_id": license_id,
        "sdk_version_str": sdk_version_str,
        "sdk_version": sdk_version,
        "device_type": device_type,
        "channel": channel,
        "app_version": app_version,
        "os_version": os_version,
        "token": token,
        "seed": seed,
        "aid": aid,
        "cookies": cookies,
    }

    response = requests.post(endpoint, json=payload, headers=headers)
    response.raise_for_status()
    return response.json()


if __name__ == "__main__":
    result = generate_signature_v2(
        device_id="7123456789012345678",
        url="https://api16-normal-c-alisg.ttapis.com/aweme/v1/feed/?aid=1233&device_id=7123456789012345678",
    )
    print(result)
