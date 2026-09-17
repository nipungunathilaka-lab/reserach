import os
import jwt
import redis
from fastapi import HTTPException, Security, Request
from fastapi.security.api_key import APIKeyHeader
import logging

logger = logging.getLogger(__name__)

INTERNAL_API_SECRET = os.getenv("INTERNAL_API_SECRET", "default-insecure-internal-secret")
API_KEY_HEADER = APIKeyHeader(name="Authorization", auto_error=False)

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")

_redis_client = None

def get_redis():
    global _redis_client
    if _redis_client is None:
        try:
            _redis_client = redis.from_url(REDIS_URL, socket_timeout=1)
        except Exception:
            pass
    return _redis_client

def verify_internal_token(request: Request, authorization: str = Security(API_KEY_HEADER)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid internal service token")
    
    token = authorization.split(" ")[1]
    
    try:
        payload = jwt.decode(
            token, 
            INTERNAL_API_SECRET, 
            algorithms=["HS256"], 
            audience="fastapi-engine",
            issuer="node-api"
        )
        
        jti = payload.get("jti")
        if not jti:
            raise HTTPException(status_code=401, detail="Missing JTI in service token")
            
        r = get_redis()
        if r is None:
            logger.error("Redis connection unavailable for JTI replay protection.")
            raise HTTPException(status_code=500, detail="Internal security store unavailable")
            
        try:
            is_new = r.set(f"internal-auth:jti:{jti}", "1", ex=60, nx=True)
            if not is_new:
                raise HTTPException(status_code=401, detail="SERVICE_AUTH_FAILURE: Replayed JTI detected")
        except redis.RedisError as e:
            logger.error(f"Redis error checking JTI: {e}")
            raise HTTPException(status_code=500, detail="Internal security store unavailable")
        
        if payload.get("service") != "node-api":
            raise HTTPException(status_code=403, detail="SERVICE_AUTH_FAILURE: Invalid service identity")
            
        req_method = payload.get("req_method", "*")
        req_path = payload.get("req_path", "*")
        
        if req_method != "*" and req_method != request.method:
            raise HTTPException(status_code=403, detail="SERVICE_AUTH_FAILURE: HTTP Method context mismatch")
            
        if req_path != "*" and req_path != request.url.path:
            raise HTTPException(status_code=403, detail="SERVICE_AUTH_FAILURE: HTTP Path context mismatch")
            
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="SERVICE_AUTH_FAILURE: Internal service token expired")
    except jwt.InvalidIssuerError:
        raise HTTPException(status_code=401, detail="SERVICE_AUTH_FAILURE: Invalid token issuer")
    except jwt.InvalidAudienceError:
        raise HTTPException(status_code=401, detail="SERVICE_AUTH_FAILURE: Invalid token audience")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="SERVICE_AUTH_FAILURE: Invalid internal service token")
    
    return True
