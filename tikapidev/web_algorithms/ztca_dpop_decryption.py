import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests
from config import BASE_URL, API_KEY


def ztca_dpop_decryption(token: str) -> dict:
    """
    Decrypt a ZTCA-DPOP token.

    Args:
        token: The ZTCA-DPOP JWT token to decrypt.

    Returns:
        API response as a dict containing header, payload, signature_hex, and signing_input.
    """
    url = f"{BASE_URL}/web/ztcadpop/dec"
    headers = {"x-api-key": API_KEY}
    payload = {"token": token}

    response = requests.post(url, json=payload, headers=headers)
    response.raise_for_status()
    return response.json()


if __name__ == "__main__":
    result = ztca_dpop_decryption(
        token=(
            "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0IiwiandrIjp7ImNydiI6IlAtMjU2Iiwia3R5IjoiRUMiLCJ4IjoiQU5PdFhtak5XYnppSnNuWkFDZ2pldnJJSkptTTZhOGFjbndrWFI4bXI2QSIsInkiOiJZRmt1SmI3bGFnblpFcFlxUVVhZ1lOUHdWMkVNOXRueFdrODFfTm1wYjUwIn19"
            ".eyJqdGkiOiJRcWNsTDlRTlNjMjh4dV9FM3RlOEhIa3p1WWx3dzFnRi14a0k2NFJ3dDlFIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vd2ViY2FzdC50aWt0b2suY29tL3dlYmNhc3Qvcm9vbS9jaGF0LyIsImlhdCI6MTc3NjExNDc0NX0"
            ".JxaaQGu5myddOzhewlafC4CMeJ5-FPb6lHWj_jUNl-LVmVDAiyNgQneJvzXoR5cmbHRlHAxo4BszUDRlftnTng"
        )
    )
    print(result)
