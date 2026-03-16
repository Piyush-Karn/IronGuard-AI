# IronGuard API Reference

IronGuard provides a RESTful API built with FastAPI. All endpoints are prefixed with `/api/v1`.

## Security Scanning API

### `POST /api/v1/scan_prompt`
Evaluates a prompt's risk level using the hybrid detection pipeline without sending it to an LLM.

- **Request Body**:
  ```json
  {
    "user_id": "string",
    "prompt": "string"
  }
  ```
- **Response**:
  ```json
  {
    "risk_explanation": {
      "risk_score": 75,
      "classification": "Malicious",
      "reasons": ["Matched known malicious pattern for Jailbreak"],
      "attack_types": ["Jailbreak Attempt"]
    },
    "action": "Blocked",
    "classifier_output": {
      "label": "PROMPT_INJECTION",
      "confidence": 0.98,
      "is_malicious": true,
      "latency_ms": 12.5
    }
  }
  ```

### `POST /api/v1/process_prompt`
The full "production" endpoint. It scans the prompt, sanitizes it if suspicious, and forwards it to the configured LLM proxies.

---

## Authentication & Profile API

### `GET /api/v1/auth/me`
Retrieves the authenticated user's role and synchronizes profile data.

- **Headers**:
  - `X-User-Id`: The user's unique identifier.
- **Query Parameters**:
  - `email` (optional): User's primary email address.
  - `full_name` (optional): User's display name.
- **Response**:
  ```json
  {
    "user_id": "user_123",
    "role": "admin"
  }
  ```

---

## Analytics & User Management API

All analytics endpoints require **Admin** privileges and MUST include the `X-User-Id` header.

### `GET /api/v1/analytics/users`
Retrieves a list of all users with aggregated security statistics.

- **Response**:
  ```json
  {
    "users": [
      {
        "user_id": "user_123",
        "role": "employee",
        "trust_score": 85,
        "total_checked": 10,
        "sanitized": 8,
        "blocked": 2,
        "email": "piyush@example.com",
        "full_name": "Piyush Karn"
      }
    ]
  }
  ```

### `POST /api/v1/analytics/assign-role`
Updates a user's role (Admin vs Employee).

- **Request Body**:
  ```json
  {
    "user_id": "string",
    "role": "admin"
  }
  ```

### `GET /api/v1/analytics/attack-frequency`
Returns temporal data on how many attacks were blocked over time.

### `GET /api/v1/analytics/top-threats`
Returns a breakdown of which threat categories are most active.

### `GET /api/v1/analytics/user-behavior`
Returns analytics on high-risk users and overall trust trends.

---

## Interactive Docs
The server provides interactive API documentation via Swagger UI at:
**[http://localhost:8000/docs](http://localhost:8000/docs)**
