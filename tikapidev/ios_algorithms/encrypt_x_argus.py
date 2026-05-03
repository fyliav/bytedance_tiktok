"""
iOS Algorithms — Deprecated.
This endpoint is deprecated and may be removed in a future API version.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests
from config import BASE_URL, API_KEY


def encrypt_x_argus(
    url: str,
    device_id: str,
    platform: str = "ios",
    body: str = "",
    license_id: str = "1611921764",
    sdk_version_str: str = "v04.04.05-ov-android",
    sdk_version: int = 167904322,
    device_type: str = "iPhone13,2",
    channel: str = "App Store",
    app_version: str = "38.3.0",
    os_version: str = "17.4.1",
    token: str = "",
    id28: int = 1006,
    id29: int = 4,
    id30: int = 8,
) -> dict:
    """
    Encrypt an X-Argus header value for iOS. (Deprecated)

    Args:
        url:              Full request URL.
        device_id:        TikTok device ID.
        platform:         Platform string (default "ios").
        body:             Request body as a JSON string.
        license_id:       License ID string.
        sdk_version_str:  SDK version string.
        sdk_version:      SDK version integer.
        device_type:      Device model string (e.g. "iPhone13,2").
        channel:          Distribution channel (e.g. "App Store").
        app_version:      TikTok app version.
        os_version:       iOS version string.
        token:            Optional token.
        id28:             Optional id28 value.
        id29:             Optional id29 value.
        id30:             Optional id30 value.

    Returns:
        API response as a dict.
    """
    endpoint = f"{BASE_URL}/mobile/algo/ios/encx-a"
    headers = {"x-api-key": API_KEY}
    payload = {
        "platform": platform,
        "url": url,
        "device_id": device_id,
        "body": body,
        "license_id": license_id,
        "sdk_version_str": sdk_version_str,
        "sdk_version": sdk_version,
        "device_type": device_type,
        "channel": channel,
        "app_version": app_version,
        "os_version": os_version,
        "token": token,
        "id28": id28,
        "id29": id29,
        "id30": id30,
    }

    response = requests.post(endpoint, json=payload, headers=headers)
    response.raise_for_status()
    return response.json()


if __name__ == "__main__":
    result = encrypt_x_argus(
        url="https://api16-normal-c-useast1a.tiktokv.com/aweme/v1/feed/?aid=1233&device_id=7123456789012345678",
        device_id="7123456789012345678",
        body='{"foo":"bar"}',
    )
    print(result)
