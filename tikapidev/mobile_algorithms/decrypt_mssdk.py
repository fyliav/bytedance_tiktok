import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests
from config import BASE_URL, API_KEY


def decrypt_mssdk(
    encrypted: str,
    input_encoding: str = "hex",
    output_encoding: str = "raw",
) -> dict:
    """
    Decrypt an MSSDK-encrypted value.

    Args:
        encrypted:       The encrypted string.
        input_encoding:  Encoding of the input (e.g. "hex", "base64").
        output_encoding: Encoding of the output (e.g. "raw", "hex").

    Returns:
        API response as a dict.
    """
    url = f"{BASE_URL}/mobile/algo/decmssdk"
    headers = {"x-api-key": API_KEY}
    payload = {
        "encrypted": encrypted,
        "input_encoding": input_encoding,
        "output_encoding": output_encoding,
    }

    response = requests.post(url, json=payload, headers=headers)
    response.raise_for_status()
    return response.json()


if __name__ == "__main__":
    result = decrypt_mssdk(encrypted="", input_encoding="hex", output_encoding="raw")
    print(result)
