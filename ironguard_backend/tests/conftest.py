import pytest
from fastapi.testclient import TestClient
from unittest.mock import MagicMock, patch, AsyncMock
import sys
import os
from fastapi import FastAPI

# Add the parent directory to sys.path so we can import 'main' and 'app'
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Set encryption key for test consistency
os.environ["IG_SECRET_ENCRYPTION_KEY"] = "F8p3_P_V6E-W8H3Y5W-0H8X8W-X8W8X8W8X8W8X8W="

@pytest.fixture(autouse=True)
def mock_services():
    """Mock core services by directly patching attributes on the singleton instances."""
    from app.monitoring.user_manager import user_manager
    from app.gateway.client_registry import client_registry
    from app.monitoring.user_behavior import user_behavior_monitor

    # Patch user_manager (singleton instance)
    user_manager.get_user_role = AsyncMock(return_value="employee")
    user_manager.is_user_verified = AsyncMock(return_value=True)
    user_manager.get_user_stats = AsyncMock(return_value={"total_checked": 0, "trust_score": 100})
    user_manager.verify_invite = AsyncMock(return_value=True)
    user_manager.create_invite = AsyncMock(return_value="test_invite_code")
    user_manager.assign_role = AsyncMock(return_value=True)

    # Patch client_registry (singleton instance)
    client_registry.get_decrypted_secret = AsyncMock(return_value="test_secret")
    client_registry.record_usage = AsyncMock()
    client_registry.list_clients = AsyncMock(return_value=[])
    client_registry.register_client = AsyncMock(return_value={"client_id": "test", "secret": "raw"})

    with patch("app.monitoring.user_behavior.user_behavior_monitor", new=AsyncMock()) as mock_ubm:
        mock_ubm.reset_trust_score = AsyncMock()
        mock_ubm.get_or_create_trust_score = AsyncMock(return_value=MagicMock(trust_score=100, malicious_attempts=0))
        mock_ubm.should_terminate_session = AsyncMock(return_value=False)
        mock_ubm.update_trust_score = AsyncMock()
        
        yield {
            "mock_um": user_manager,
            "mock_cr": client_registry,
            "mock_ubm": mock_ubm
        }

@pytest.fixture
def client(mock_services):
    """Create a fresh FastAPI app for each test to isolate from middleware/lifespan side effects."""
    from app.api import endpoints, admin, gateway_admin
    from app.gateway import endpoints as gateway_endpoints
    from app.gateway.middleware import GatewaySignatureMiddleware
    
    app = FastAPI()
    
    # Include Routers
    app.include_router(endpoints.router, prefix="/api/v1")
    app.include_router(admin.router, prefix="/api/v1/analytics")
    app.include_router(gateway_endpoints.router, prefix="/gateway/v1")
    app.include_router(gateway_admin.router)
    
    # Add Signature Middleware
    app.add_middleware(GatewaySignatureMiddleware)
    
    with TestClient(app) as c:
        yield c
