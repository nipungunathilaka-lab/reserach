from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session
from app.database.db import get_db
from app.database.models import User
from app.services.auth_service import AuthService
from app.core.redis_client import get_redis
import json

security = HTTPBearer()


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)) -> User:
    payload = AuthService.decode_token(credentials.credentials)
    user_id = int(payload.get("sub"))
    
    redis = await get_redis()
    cache_key = f"user_session:{user_id}"
    try:
        cached_data = await redis.get(cache_key)
        if cached_data:
            user_dict = json.loads(cached_data)
            return User(**user_dict)
    except Exception:
        pass # Fallback to DB if redis fails
        
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User no longer exists")
        
    try:
        user_dict = {
            "id": user.id,
            "email": user.email,
            "role": user.role,
            "full_name": user.full_name,
            "mfa_enabled": user.mfa_enabled,
            "failed_login_attempts": user.failed_login_attempts
        }
        await redis.setex(cache_key, 300, json.dumps(user_dict)) # Cache for 5 mins
    except Exception:
        pass
        
    return user


def require_admin(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return current_user
