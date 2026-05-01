from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class OneTimePreKey(BaseModel):
    key_id: str = Field(min_length=1, max_length=128)
    public_key: str = Field(min_length=32, max_length=2048)


class UserCreate(BaseModel):
    id: str = Field(min_length=3, max_length=64)
    email: EmailStr
    display_name: str = Field(min_length=2, max_length=120)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    email: EmailStr
    display_name: str
    created_at: datetime


class KeyBundleCreate(BaseModel):
    device_id: str = Field(default="primary", min_length=1, max_length=64)
    identity_key_public: str = Field(min_length=32, max_length=2048)
    signed_pre_key_id: int = Field(default=1, ge=1)
    signed_pre_key_public: str = Field(min_length=32, max_length=2048)
    signed_pre_key_signature: str = Field(min_length=32, max_length=2048)
    one_time_pre_keys: list[OneTimePreKey] = Field(default_factory=list)


class KeyBundleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    user_id: str
    device_id: str
    identity_key_public: str
    signed_pre_key_id: int
    signed_pre_key_public: str
    signed_pre_key_signature: str
    one_time_pre_key: Optional[OneTimePreKey] = None
