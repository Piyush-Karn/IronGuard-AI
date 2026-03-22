import asyncio
from unittest.mock import MagicMock, AsyncMock, patch

async def debug_async():
    with patch("app.api.auth.user_manager") as mock_um:
        print(f"Mock UM type: {type(mock_um)}")
        mock_um.get_user_role = AsyncMock(return_value="admin")
        
        result = await mock_um.get_user_role("test")
        print(f"Result: {result}")
        
        # Test if another reference is updated
        from app.api.auth import user_manager as auth_um
        print(f"Auth UM type: {type(auth_um)}")
        res2 = await auth_um.get_user_role("test")
        print(f"Res2: {res2}")

if __name__ == "__main__":
    import sys
    import os
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    asyncio.run(debug_async())
