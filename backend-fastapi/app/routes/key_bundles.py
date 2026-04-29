from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import DeviceKeys, User
from ..schemas import KeyBundleCreate, KeyBundleOut, UserCreate, UserOut

router = APIRouter(prefix="/api/users", tags=["users", "key-bundles"])


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(payload: UserCreate, db: Session = Depends(get_db)) -> User:
    existing = db.query(User).filter(User.id == payload.id).first()
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User already exists")

    user = User(id=payload.id, email=payload.email, display_name=payload.display_name)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.post("/{user_id}/key-bundle", response_model=KeyBundleOut, status_code=status.HTTP_201_CREATED)
def upsert_key_bundle(user_id: str, payload: KeyBundleCreate, db: Session = Depends(get_db)) -> DeviceKeys:
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    bundle = (
        db.query(DeviceKeys)
        .filter(DeviceKeys.user_id == user_id, DeviceKeys.device_id == payload.device_id)
        .first()
    )
    if bundle:
        bundle.device_id = payload.device_id
        bundle.identity_key_public = payload.identity_key_public
        bundle.signed_pre_key_public = payload.signed_pre_key_public
        bundle.signed_pre_key_signature = payload.signed_pre_key_signature
        bundle.one_time_pre_keys = [key.model_dump() for key in payload.one_time_pre_keys]
    else:
        bundle = DeviceKeys(
            user_id=user_id,
            **payload.model_dump(mode="json"),
        )
        db.add(bundle)

    db.commit()
    db.refresh(bundle)
    return bundle


@router.get("/{user_id}/key-bundle", response_model=KeyBundleOut)
def get_key_bundle(user_id: str, device_id: str = "primary", db: Session = Depends(get_db)) -> DeviceKeys:
    bundle = (
        db.query(DeviceKeys)
        .filter(DeviceKeys.user_id == user_id, DeviceKeys.device_id == device_id)
        .first()
    )
    if not bundle:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Key bundle not found")
    return bundle
