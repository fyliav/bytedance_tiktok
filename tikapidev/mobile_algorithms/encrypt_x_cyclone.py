import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests
from config import BASE_URL, API_KEY


def encrypt_x_cyclone(
    url: str,
    x_bd_lanusk: str = "",
    type: str = "0",
    head_hex: str = "0000",
    pb_data_hex: str = "0801",
) -> dict:
    """
    Encrypt an X-Cyclone header value.

    Args:
        url:          Target WebSocket or HTTPS URL.
        x_bd_lanusk:  X-BD-LANUSK value.
        type:         Cyclone type string (default "0").
        head_hex:     Head hex string (default "0000").
        pb_data_hex:  Protobuf data hex string (default "0801").

    Returns:
        API response as a dict.
    """
    endpoint = f"{BASE_URL}/mobile/algo/encx-c"
    headers = {"x-api-key": API_KEY}
    payload = {
        "url": url,
        "x_bd_lanusk": x_bd_lanusk,
        "type": type,
        "head_hex": head_hex,
        "pb_data_hex": pb_data_hex,
    }

    response = requests.post(endpoint, json=payload, headers=headers)
    response.raise_for_status()
    return response.json()


if __name__ == "__main__":
    result = encrypt_x_cyclone(
        url="wss://webcast16-normal-c-useast1a.tiktokv.com/webcast/im/push/v2/?aid=1233&device_id=7123456789012345678",
        x_bd_lanusk="",
        type="0",
        head_hex="0000",
        pb_data_hex="0801",
    )
    print(result)
