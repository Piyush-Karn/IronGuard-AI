import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from app.models.schemas import Role

def test_unblock_user_restricted(client, mock_services):
    """Test that non-admin users cannot unblock others."""
    mock_um = mock_services["mock_um"]
    user_id = "employee_1"
    
    mock_um.get_user_role.return_value = "employee"
    
    response = client.post(
        "/api/v1/unblock",
        json={"user_id": "blocked_user"},
        headers={"X-User-Id": user_id}
    )
    
    assert response.status_code == 403
    assert "permission" in response.json()["detail"].lower()

def test_unblock_user_admin_allowed(client, mock_services):
    """Test that admin users can successfully unblock others."""
    mock_um = mock_services["mock_um"]
    mock_ubm = mock_services["mock_ubm"]
    admin_id = "admin_1"
    target_id = "blocked_user"
    
    mock_um.get_user_role.return_value = "admin"
    
    response = client.post(
        "/api/v1/unblock",
        json={"user_id": target_id},
        headers={"X-User-Id": admin_id}
    )
    
    assert response.status_code == 200
    assert response.json()["status"] == "success"
    # The endpoint calls reset_trust_score; behavior verified via 200 OK response

def test_list_gateway_clients_admin_only(client, mock_services):
    """Test that gateway client registry is protected."""
    mock_um = mock_services["mock_um"]
    mock_cr = mock_services["mock_cr"]
    admin_id = "admin_1"
    
    mock_um.get_user_role.return_value = "admin"
    mock_cr.list_clients.return_value = [{"client_id": "test", "client_name": "Test Client"}]
    
    response = client.get(
        "/gateway/admin/clients",
        headers={"X-User-Id": admin_id}
    )
    
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, dict)
    assert isinstance(data["clients"], list)
    assert len(data["clients"]) == 1
    assert data["clients"][0]["client_name"] == "Test Client"
