"""
app/api/gateway_admin.py
=========================
Admin endpoints to manage gateway clients.
Uses existing X-User-Id + admin role auth — no HMAC required here.
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from app.api.auth import RoleChecker, get_current_user_id
from app.models.schemas import Role
from app.gateway.client_registry import client_registry

router = APIRouter(prefix="/gateway/admin", tags=["gateway-admin"])
admin_only = Depends(RoleChecker([Role.ADMIN]))


class RegisterClientRequest(BaseModel):
    client_name: str
    allowed_rpm: int = 60


class RevokeClientRequest(BaseModel):
    reason: str


@router.post("/clients", dependencies=[admin_only])
async def register_client(
    body: RegisterClientRequest,
    admin_user_id: str = Depends(get_current_user_id)
):
    """Register a new backend client. Returns secret ONCE — store it securely."""
    result = await client_registry.register_client(
        client_name=body.client_name,
        created_by=admin_user_id,
        allowed_rpm=body.allowed_rpm,
    )
    return result


@router.get("/clients", dependencies=[admin_only])
async def list_clients():
    """List all gateway clients (hashed secrets never returned)."""
    clients = await client_registry.list_clients()
    return {"clients": clients}


@router.post("/clients/{client_id}/rotate", dependencies=[admin_only])
async def rotate_secret(client_id: str):
    """Rotate signing secret. Old secret is immediately invalidated."""
    result = await client_registry.rotate_secret(client_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.delete("/clients/{client_id}", dependencies=[admin_only])
async def revoke_client(
    client_id: str,
    body: RevokeClientRequest,
    admin_user_id: str = Depends(get_current_user_id)
):
    """Revoke a client. All future requests from this client will be rejected."""
    success = await client_registry.revoke_client(
        client_id, body.reason, admin_user_id
    )
    if not success:
        raise HTTPException(status_code=404, detail="Client not found")
    return {"message": f"Client {client_id} revoked"}
