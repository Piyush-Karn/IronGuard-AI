# 🔗 IronGuard Client Integration Guide

> This guide explains how to integrate your backend application with the IronGuard AI security gateway after registering it on the Admin Dashboard.

---

## 📋 Table of Contents

- [Authentication Protocol](#-authentication-protocol-hmac-sha256)
- [API Endpoints](#-api-endpoints)
- [Code Examples](#-code-examples)
- [Error Handling](#-error-handling)

---

## 🔐 Authentication Protocol (HMAC-SHA256)

IronGuard uses a **stateless HMAC-SHA256 signing protocol** to verify your application's identity and prevent request tampering.

### Required Headers

Every request to the gateway must include:

| Header | Description |
|--------|-------------|
| `X-IG-Client-Id` | Your unique Client ID (from the Client Registry) |
| `X-IG-Timestamp` | Current UTC Unix timestamp (seconds). Requests older than **30 seconds** are rejected |
| `X-IG-Signature` | The computed HMAC-SHA256 hex signature |

### How to Compute the Signature

**Step 1 — Prepare the canonical message**

Concatenate the timestamp, client ID, and the SHA-256 hash of the JSON body, separated by newlines:

```
message = timestamp + "\n" + client_id + "\n" + sha256_hex(request_body_bytes)
```

**Step 2 — Sign the message**

Compute the HMAC-SHA256 hex digest using your **Signing Secret** as the key:

```
signature = hmac_sha256_hex(signing_secret, message)
```

---

## 📡 API Endpoints

### `POST /gateway/v1/prompt` — Full Proxy

Use this for **full security scanning + automatic LLM forwarding**. IronGuard handles all AI provider keys via its Secure Vault.

**Request Body**

```json
{
  "prompt": "User input text here",
  "user_id": "app-user-123",
  "session_id": "optional-session-uuid",
  "external_content": "optional retrieval context"
}
```

**Response `200 OK`**

```json
{
  "response": "The AI generated text (or a blocked/sanitized message)",
  "action_taken": "Passed | Sanitized | Blocked",
  "risk_score": 12,
  "attack_types": [],
  "request_id": "uuid-for-tracking"
}
```

---

### `POST /gateway/v1/scan` — Security Scan Only

Use this if you want IronGuard to analyze the prompt for threats but **handle the LLM call yourself**.

**Response `200 OK`**

```json
{
  "risk_score": 85,
  "classification": "Malicious",
  "action": "Blocked",
  "reasons": ["Prompt injection detected via transformer model"],
  "attack_types": ["injection"]
}
```

---

## 💻 Code Examples

### Python

```python
import time
import hmac
import hashlib
import requests

CLIENT_ID = "your_client_id"
CLIENT_SECRET = "your_signing_secret"
BASE_URL = "http://localhost:8000/gateway/v1"

def send_prompt(prompt_text: str) -> dict:
    url = f"{BASE_URL}/prompt"
    body = {"prompt": prompt_text, "user_id": "example-user"}
    body_bytes = str(body).replace("'", '"').encode("utf-8")

    timestamp = str(int(time.time()))
    body_hash = hashlib.sha256(body_bytes).hexdigest()

    # Construct canonical message
    message = f"{timestamp}\n{CLIENT_ID}\n{body_hash}"

    # Sign
    signature = hmac.new(
        CLIENT_SECRET.encode(),
        message.encode(),
        hashlib.sha256,
    ).hexdigest()

    headers = {
        "X-IG-Client-Id": CLIENT_ID,
        "X-IG-Timestamp": timestamp,
        "X-IG-Signature": signature,
        "Content-Type": "application/json",
    }

    response = requests.post(url, json=body, headers=headers)
    return response.json()

# Usage
result = send_prompt("Hello, help me write some code.")
print(result["response"])
```

### Node.js

```javascript
const axios = require('axios');
const crypto = require('crypto');

const CLIENT_ID = 'your_client_id';
const SECRET    = 'your_signing_secret';

async function callIronGuard(prompt) {
    const timestamp  = Math.floor(Date.now() / 1000).toString();
    const body       = { prompt, user_id: 'node-client' };
    const bodyString = JSON.stringify(body);

    const bodyHash = crypto.createHash('sha256').update(bodyString).digest('hex');
    const message  = `${timestamp}\n${CLIENT_ID}\n${bodyHash}`;

    const signature = crypto
        .createHmac('sha256', SECRET)
        .update(message)
        .digest('hex');

    const response = await axios.post(
        'http://localhost:8000/gateway/v1/prompt',
        body,
        {
            headers: {
                'X-IG-Client-Id':  CLIENT_ID,
                'X-IG-Timestamp':  timestamp,
                'X-IG-Signature':  signature,
            },
        }
    );

    return response.data;
}
```

---

## ⚠️ Error Handling

| Status Code | Meaning | Recommended Action |
|:-----------:|---------|-------------------|
| `401` | Signature or Timestamp mismatch | Check your clock sync and secret key |
| `403` | Unknown Client ID or revoked access | Verify Client ID in Admin Registry |
| `429` | Client rate limit exceeded (RPM) | Slow down request frequency |
| `500` | LLM provider or database error | Retry with exponential backoff |

---

<div align="right"><a href="../README.md">← Back to README</a></div>