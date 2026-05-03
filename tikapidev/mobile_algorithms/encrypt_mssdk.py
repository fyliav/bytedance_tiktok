import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests
from config import BASE_URL, API_KEY


def encrypt_mssdk(
    payload: str,
    payload_encoding: str = "raw",
    output_encoding: str = "hex",
    sdk_ver: str = "",
    include_keys: bool = True,
) -> dict:
    """
    Encrypt data using MSSDK.

    Args:
        payload:          Hex string or raw data to encrypt.
        payload_encoding: Encoding of the input payload (e.g. "raw", "hex").
        output_encoding:  Encoding of the output (e.g. "hex", "base64").
        sdk_ver:          SDK version string.
        include_keys:     Whether to include keys in the response.

    Returns:
        API response as a dict.
    """
    url = f"{BASE_URL}/mobile/algo/encmssdk"
    headers = {"x-api-key": API_KEY}
    body = {
        "payload": payload,
        "payload_encoding": payload_encoding,
        "output_encoding": output_encoding,
        "sdk_ver": sdk_ver,
        "include_keys": include_keys,
    }

    response = requests.post(url, json=body, headers=headers)
    response.raise_for_status()
    return response.json()


if __name__ == "__main__":
    result = encrypt_mssdk(
        payload="676767677767676767",
        payload_encoding="raw",
        output_encoding="hex",
        sdk_ver="",
        include_keys=True,
    )
    print(result)
