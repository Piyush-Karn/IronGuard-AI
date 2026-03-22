import pytest
import time
import json
import sys
from unittest.mock import AsyncMock, patch, MagicMock

# Mock missing optional dependencies so tests can run without full ML environment
_mock_mods = [
    "motor", "motor.motor_asyncio", "pymongo", "chromadb",
    "sentence_transformers", "guardrails", "lmql", "datasets",
    "transformers", "torch",
]
for _m in _mock_mods:
    if _m not in sys.modules:
        sys.modules[_m] = MagicMock()

from app.gateway.signing import build_signing_message, compute_signature

def test_gateway_scan_success(client, mock_services):
    """Test successful gateway scan with valid signature."""
    mock_cr = mock_services["mock_cr"]
    client_id = "test_client_id"
    raw_secret = "test_raw_secret_32_bytes_long_123456"
    timestamp = str(int(time.time()))
    payload = {"user_id": "user_123", "prompt": "Is this safe?"}
    body_bytes = json.dumps(payload).encode()
    
    msg = build_signing_message(timestamp, client_id, body_bytes)
    sig = compute_signature(raw_secret, msg)
    
    headers = {
        "X-IG-Client-Id": client_id,
        "X-IG-Timestamp": timestamp,
        "X-IG-Signature": sig,
        "Content-Type": "application/json",
    }
    
    mock_cr.get_decrypted_secret.return_value = raw_secret
    
    from app.security_engine.decision import decision_engine
    from app.threat_detection.intent_classifier import ClassifierResult
    from app.fingerprinting.fingerprint_engine import FingerprintResult
    from app.models.schemas import RiskExplanation

    with patch.object(decision_engine, "evaluate_request", new_callable=AsyncMock) as mock_eval:
        mock_eval.return_value = (
            "Is this safe?",
            RiskExplanation(risk_score=10, base_risk_score=10,
                classification="Safe", reasons=[], attack_types=[]),
            "Passed",
            ClassifierResult(label="SAFE", confidence=0.99, is_malicious=False, latency_ms=10.0),
            FingerprintResult(is_match=False, score_bonus=0, similarity_score=0.0, method_used="none", matched_canonical=None),
            None,
        )
        
        # Use content= (raw bytes) so the body matches exactly what the signature was computed over
        response = client.post("/gateway/v1/scan", content=body_bytes, headers=headers)
        
        assert response.status_code == 200
        assert response.json()["action"] == "Passed"

def test_gateway_invalid_signature(client, mock_services):
    """Test gateway rejection of invalid signature."""
    mock_cr = mock_services["mock_cr"]
    headers = {
        "X-IG-Client-Id": "test_client",
        "X-IG-Timestamp": str(int(time.time())),
        "X-IG-Signature": "invalid_sig"
    }
    
    mock_cr.get_decrypted_secret.return_value = "secret"
    
    response = client.post("/gateway/v1/scan", json={"prompt": "test"}, headers=headers)
    
    assert response.status_code == 401
    assert "Signature verification failed" in response.json()["detail"]

def test_gateway_expired_timestamp(client):
    """Test gateway rejection of stale requests."""
    headers = {
        "X-IG-Client-Id": "test_client",
        "X-IG-Timestamp": str(int(time.time()) - 300), # 5 mins ago
        "X-IG-Signature": "any_sig"
    }
    
    response = client.post("/gateway/v1/scan", json={"prompt": "test"}, headers=headers)
    assert response.status_code == 401
    assert "Timestamp expired" in response.json()["detail"]
