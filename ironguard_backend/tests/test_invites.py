import pytest

def test_verify_secret_success(client, mock_services):
    """Test successful secret verification."""
    mock_um = mock_services["mock_um"]
    mock_user_id = "user_123"
    payload = {"secret": "valid_secret_123"}
    
    # Ensure it's an AsyncMock and set the return value
    mock_um.verify_invite.return_value = True
    
    response = client.post(
        "/api/v1/auth/verify-secret",
        json=payload,
        headers={"X-User-Id": mock_user_id}
    )
    
    assert response.status_code == 200
    assert response.json()["status"] == "success"

def test_verify_secret_failure(client, mock_services):
    """Test failed secret verification."""
    mock_um = mock_services["mock_um"]
    mock_user_id = "user_123"
    payload = {"secret": "wrong_secret"}
    
    mock_um.verify_invite.return_value = False
    
    response = client.post(
        "/api/v1/auth/verify-secret",
        json=payload,
        headers={"X-User-Id": mock_user_id}
    )
    
    assert response.status_code == 401
    assert "Invalid or expired" in response.json()["detail"]
