import pytest
import time
import json
from unittest.mock import AsyncMock, patch, MagicMock
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
        "X-IG-Signature": sig
    }
    
    mock_cr.get_decrypted_secret.return_value = raw_secret
    
    # Patch the DecisionEngine.decide method directly on the class
    with patch("app.security_engine.decision.DecisionEngine.decide", new_callable=AsyncMock) as mock_decide:
        mock_decide.return_value = MagicMock(
            action="Passed", 
            risk_explanation={"risk_score": 10, "classification": "Safe", "reasons": [], "attack_types": []}
        )
        
        response = client.post("/gateway/v1/scan", json=payload, headers=headers)
        
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
