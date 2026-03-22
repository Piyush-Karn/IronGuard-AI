from fastapi import HTTPException, Header, Depends, status
from app.models.schemas import Role
from app.monitoring.user_manager import user_manager
import logging

logger = logging.getLogger(__name__)

async def get_current_user_id(x_user_id: str = Header(..., alias="X-User-Id")):
    """
    Extracts the user_id from the X-User-Id header. 
    In production, this would be validated against a JWT/Clerk session.
    """
    if not x_user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing user identification header"
        )
    return x_user_id.strip()

class RoleChecker:
    def __init__(self, allowed_roles: list[Role]):
        self.allowed_roles = allowed_roles

    async def __call__(self, user_id: str = Depends(get_current_user_id)):
        role_info = await user_manager.get_user_role(user_id)
        # Handle both Enum objects and raw strings if necessary
        user_role = role_info.value if hasattr(role_info, "value") else role_info
        
        if user_role not in [r.value for r in self.allowed_roles]:
            logger.warning(f"Unauthorized access attempt by user {user_id} with role {user_role}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to access this resource"
            )
        return user_id

admin_only = RoleChecker([Role.ADMIN])
