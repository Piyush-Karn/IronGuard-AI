import pytest

def test_get_me_success(client, mock_services):
    """Test the /auth/me endpoint returns correct profile data."""
    mock_um = mock_services["mock_um"]
    mock_user_id = "user_123"
    
    mock_um.get_user_role.return_value = "employee"
    mock_um.is_user_verified.return_value = True
    
    response = client.get(
        "/api/v1/auth/me",
        headers={"X-User-Id": mock_user_id}
    )
    
    assert response.status_code == 200
    data = response.json()
    assert data["user_id"] == mock_user_id
    assert data["role"] == "employee"
    assert data["is_verified"] is True

def test_get_me_not_verified(client, mock_services):
    """Test /auth/me reflects unverified status."""
    mock_um = mock_services["mock_um"]
    mock_user_id = "user_456"
    
    mock_um.is_user_verified.return_value = False
    
    response = client.get(
        "/api/v1/auth/me",
        headers={"X-User-Id": mock_user_id}
    )
    
    assert response.status_code == 200
    assert response.json()["is_verified"] is False
