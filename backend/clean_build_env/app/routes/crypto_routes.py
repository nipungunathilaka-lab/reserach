from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
import base64
from app.database.db import get_db
from app.database.models import User
from app.routes.dependencies import get_current_user
from app.services.crypto_service import CryptoService
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

router = APIRouter(prefix="/crypto", tags=["Cryptography"])

class KeyExchangeResponse(BaseModel):
    server_public_key_pem: str

@router.get("/ecdh/public-key", response_model=KeyExchangeResponse)
def get_public_key(current_user: User = Depends(get_current_user)):
    """Return the server's ECDH public key for the current user to establish a shared secret."""
    CryptoService.ensure_user_keypair(current_user.id)
    pem_path = CryptoService.key_paths(current_user.id)["ecdh_public"]
    return KeyExchangeResponse(server_public_key_pem=pem_path.read_text("utf-8"))

class KeyExchangeRequest(BaseModel):
    client_public_key_pem: str

class SharedSecretResponse(BaseModel):
    message: str

@router.post("/ecdh/exchange", response_model=SharedSecretResponse)
def exchange_keys(payload: KeyExchangeRequest, current_user: User = Depends(get_current_user)):
    """
    Receive the client's public key. In a full implementation, the backend would 
    derive the shared secret here and store it in a session store (like Redis) 
    to decrypt incoming payloads.
    """
    try:
        # Verify the client public key is valid
        client_pub = serialization.load_pem_public_key(payload.client_public_key_pem.encode("utf-8"))
        
        # Derive shared secret (just to verify it works, we don't strictly persist it in this prototype without a session store)
        server_priv = CryptoService._load_ecdh_private(current_user.id)
        shared_secret = server_priv.exchange(
            ec.ECDH(),
            client_pub
        )
        return SharedSecretResponse(message="Key exchange successful. Shared secret derived.")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid public key or exchange failed: {e}")
