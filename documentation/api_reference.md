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

## Administrative API

### `POST /api/v1/unblock`
Restores a user's trust score and resets their malicious attempt count.

- **Request Body**:
  ```json
  {
    "user_id": "string"
  }
  ```
- **Response**:
  ```json
  {
    "status": "success",
    "message": "Trust score restored for user_id_123",
    "current_state": {
      "trust_score": 100,
      "malicious_attempts": 0
    }
  }
  ```

## Analytics API

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
