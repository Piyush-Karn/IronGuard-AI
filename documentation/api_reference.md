# IronGuard API Reference

IronGuard provides a RESTful API built with FastAPI. All endpoints are prefixed with `/api/v1`.

## Security Scanning API

### `POST /api/v1/scan_prompt`
Evaluates a prompt's risk level using the hybrid detection pipeline (v2) without sending it to an LLM.

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
    },
    "fingerprint_match": true,
    "fingerprint_method": "simhash"
  }
  ```

### `POST /api/v1/process_prompt`
The full "production" endpoint. It scans the prompt, sanitizes it if suspicious, forwards it to the LLM Proxy (MOD-1), and scans the response (MOD-2).

- **Response**:
  ```json
  {
    "risk_explanation": { "risk_score": 0, "classification": "Safe", "reasons": [], "attack_types": [] },
    "action": "Passed",
    "classifier_output": { ... },
    "llm_response": "The capital of France is Paris.",
    "violation_notes": null,
    "sanitized_prompt": null,
    "fingerprint_match": false
  }
  ```

---

## Authentication & Profile API

### `GET /api/v1/auth/me`
Retrieves the authenticated user's role and synchronizes profile data.

- **Headers**:
  - `X-User-Id`: The user's unique identifier.
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
Retrieves a list of all users with aggregated security statistics (checks, sanitized, blocked) and trust scores.

### `GET /api/v1/analytics/metrics/latency-breakdown`
Returns system performance metrics: `avg_latency`, `max_latency`, and `p95_latency` (calculated live).

### `GET /api/v1/analytics/metrics/blocking-efficiency`
Returns a breakdown of actions taken (Passed, Blocked, Sanitized) across all logs.

### `GET /api/v1/analytics/metrics/sanitization-ratio`
Returns the percentage of prompts that were successfully sanitized vs total prompts.

### `GET /api/v1/analytics/metrics/top-policy-violations`
Returns the top 5 reasons for security interventions (e.g., "Prompt Injection", "PII Leak").

### `GET /api/v1/analytics/logs`
Fetches a chronological list of recent `threat_logs`.
- **Parameters**: `limit` (default: 50).

---

## Interactive Docs
The server provides interactive API documentation via Swagger UI at:
**[http://localhost:8000/docs](http://localhost:8000/docs)**
