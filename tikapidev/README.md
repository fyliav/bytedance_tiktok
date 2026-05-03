# TikAPI.dev Python SDK

Official Python wrapper for the [TikAPI.dev](https://tikapi.dev) API.

## Installation

```bash
pip install -r requirements.txt
```

## Configuration

Open `config.py` and replace the placeholder with your API key:

```python
API_KEY = "YOUR_API_KEY_HERE"
```

## Project Structure

```
tikapidev/
├── config.py
├── requirements.txt
│
├── actions/                  # Interact with users, videos, and more
│   ├── comment_post.py
│   ├── follow_user.py
│   └── like_post.py
│
├── device/                   # Mobile device management
│   ├── activate_device.py
│   ├── generate_full_device.py
│   └── get_did_iid.py
│
├── mobile_algorithms/        # Mobile encryption / signature generation
│   ├── decrypt_mssdk.py
│   ├── decrypt_x_argus.py
│   ├── decrypt_x_cyclone.py
│   ├── decrypt_x_ladon.py
│   ├── encrypt_hash.py
│   ├── encrypt_mssdk.py
│   ├── encrypt_x_cyclone.py
│   ├── encrypt_x_medusa.py
│   ├── generate_signature_v1.py
│   ├── generate_signature_v2.py
│   └── generate_traceid.py
│
├── web_algorithms/           # Web (tiktok.com) encryption / token generation
│   ├── generate_fpverify.py
│   ├── generate_mstoken.py
│   ├── get_mssdk_info.py
│   ├── get_web_signatures_v2.py
│   ├── ztca_dpop_decryption.py
│   └── ztca_dpop_encryption.py
│
└── ios_algorithms/           # iOS algorithms (Deprecated)
    └── encrypt_x_argus.py
```

## Usage

Every module can be imported or run directly.

### Import example

```python
from actions.comment_post import comment_post
from actions.like_post import like_post
from web_algorithms.generate_mstoken import generate_mstoken
from mobile_algorithms.generate_signature_v2 import generate_signature_v2

# Like a post
result = like_post(
    sessionid="YOUR_SESSIONID",
    aweme_id="7234567890123456789",
    proxy="user:pass@1.2.3.4:4439",
)
print(result)

# Generate a web MsToken
token = generate_mstoken()
print(token)
```

### Run a script directly

```bash
python actions/like_post.py
python web_algorithms/generate_mstoken.py
python mobile_algorithms/generate_signature_v2.py
```

## Endpoints

| Category | File | Method | Path |
|---|---|---|---|
| Actions | `comment_post.py` | POST | `mobile/actions/comment` |
| Actions | `follow_user.py` | POST | `mobile/actions/follow` |
| Actions | `like_post.py` | POST | `mobile/actions/like` |
| Device | `activate_device.py` | POST | `mobile/device/activation` |
| Device | `generate_full_device.py` | POST | `mobile/device/fullgen` |
| Device | `get_did_iid.py` | POST | `mobile/device/getdevice` |
| Mobile Algorithms | `decrypt_mssdk.py` | POST | `mobile/algo/decmssdk` |
| Mobile Algorithms | `decrypt_x_argus.py` | POST | `mobile/algo/decx-a` |
| Mobile Algorithms | `decrypt_x_cyclone.py` | POST | `mobile/algo/decx-c` |
| Mobile Algorithms | `decrypt_x_ladon.py` | POST | `mobile/algo/decx-l` |
| Mobile Algorithms | `encrypt_hash.py` | POST | `mobile/algo/enchash` |
| Mobile Algorithms | `encrypt_mssdk.py` | POST | `mobile/algo/encmssdk` |
| Mobile Algorithms | `encrypt_x_cyclone.py` | POST | `mobile/algo/encx-c` |
| Mobile Algorithms | `encrypt_x_medusa.py` | POST | `mobile/algo/encx-m` |
| Mobile Algorithms | `generate_signature_v1.py` | POST | `mobile/algo/old/gensign` |
| Mobile Algorithms | `generate_signature_v2.py` | POST | `mobile/algo/gensign` |
| Mobile Algorithms | `generate_traceid.py` | POST | `mobile/algo/gentraceid` |
| Web Algorithms | `generate_fpverify.py` | GET | `fpverify` |
| Web Algorithms | `generate_mstoken.py` | GET | `mstoken` |
| Web Algorithms | `get_mssdk_info.py` | GET | `mssdkinfo` |
| Web Algorithms | `get_web_signatures_v2.py` | POST | `web-sign` |
| Web Algorithms | `ztca_dpop_decryption.py` | POST | `web/ztcadpop/dec` |
| Web Algorithms | `ztca_dpop_encryption.py` | POST | `web/ztcadpop/enc` |
| iOS Algorithms *(Deprecated)* | `encrypt_x_argus.py` | POST | `mobile/algo/ios/encx-a` |

## Base URL

```
https://tikapi.dev/api/v1
```
