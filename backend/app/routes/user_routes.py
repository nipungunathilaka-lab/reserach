from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database.db import get_db
from app.database.models import User
from app.routes.dependencies import get_current_user, require_admin
from app.schemas.user_schema import ReceiverItem, UserCreateRequest, UserListItem, UserUpdateRequest
from app.services.auth_service import AuthService
from app.services.crypto_service import CryptoService

router = APIRouter(prefix="/users", tags=["Users"])


@router.get("", response_model=list[UserListItem])
def list_users(_: User = Depends(require_admin), db: Session = Depends(get_db)):
    return db.query(User).order_by(User.created_at.desc()).all()


@router.post("", response_model=UserListItem, status_code=status.HTTP_201_CREATED)
def create_user(payload: UserCreateRequest, _: User = Depends(require_admin), db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == payload.email.lower()).first()
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="A user with this email already exists")
    user = AuthService.create_user(db, payload.full_name, payload.email, payload.password, payload.role)
    CryptoService.ensure_user_keypair(user.id)
    return user


@router.patch("/{user_id}", response_model=UserListItem)
def update_user(user_id: int, payload: UserUpdateRequest, current_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if payload.full_name is not None:
        user.full_name = payload.full_name.strip()
    if payload.role is not None:
        # Prevent the currently logged-in admin from accidentally removing their own admin access.
        if user.id == current_user.id and payload.role != "admin":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="You cannot remove your own admin role")
        user.role = payload.role
    db.commit()
    db.refresh(user)
    return user


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(user_id: int, current_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    if user_id == current_user.id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="You cannot delete your own account")
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    sent_count = len(user.sent_transfers)
    received_count = len(user.received_transfers)
    if sent_count or received_count:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Cannot delete a user with existing transfer history. Disable or change role instead.")
    db.delete(user)
    db.commit()
    return None


@router.get("/receivers", response_model=list[ReceiverItem])
def list_receivers(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    # Robustly ensure the current user is filtered out, even if id is missing in Redis cache
    return db.query(User).filter(
        User.email != current_user.email
    ).order_by(User.full_name.asc()).all()
