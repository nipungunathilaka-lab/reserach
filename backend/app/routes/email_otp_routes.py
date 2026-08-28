from fastapi import APIRouter, HTTPException, status
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, EmailStr
import random
import string
from app.services.email_service import EmailService
from app.core.redis_client import get_redis

router = APIRouter(prefix="/email-otp", tags=["Email OTP"])

class SendOtpRequest(BaseModel):
    email: EmailStr

class VerifyOtpRequest(BaseModel):
    email: EmailStr
    otp: str

def generate_otp(length=6) -> str:
    return "".join(random.choices(string.digits, k=length))

@router.post("/send-otp")
async def send_otp(payload: SendOtpRequest):
    redis = await get_redis()
    otp = generate_otp()
    
    # Store OTP with 5 minute expiration (300 seconds)
    redis_key = f"email_otp:{payload.email}"
    await redis.setex(redis_key, 300, otp)
    
    # Run the synchronous email sending in a threadpool to avoid blocking the event loop
    await run_in_threadpool(EmailService.send_otp_email, payload.email, otp)
    return {"message": "OTP sent successfully"}

@router.post("/verify-otp")
async def verify_otp(payload: VerifyOtpRequest):
    redis = await get_redis()
    redis_key = f"email_otp:{payload.email}"
    
    stored_otp = await redis.get(redis_key)
    
    if not stored_otp:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="OTP Expired or Invalid")
        
    if stored_otp != payload.otp:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid OTP")
        
    # Delete OTP to prevent reuse
    await redis.delete(redis_key)
    
    return {"message": "OTP verified successfully"}
