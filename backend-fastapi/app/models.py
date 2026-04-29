from sqlalchemy import JSON, DateTime, ForeignKey, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    display_name: Mapped[str] = mapped_column(String(120), nullable=False)
    created_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    device_keys: Mapped[list["DeviceKeys"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
    )


class DeviceKeys(Base):
    __tablename__ = "device_keys"
    __table_args__ = (UniqueConstraint("user_id", "device_id", name="uq_device_keys_user_device"),)

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    device_id: Mapped[str] = mapped_column(String(64), nullable=False, default="primary")
    identity_key_public: Mapped[str] = mapped_column(String(2048), nullable=False)
    signed_pre_key_public: Mapped[str] = mapped_column(String(2048), nullable=False)
    signed_pre_key_signature: Mapped[str] = mapped_column(String(2048), nullable=False)
    one_time_pre_keys: Mapped[list[dict]] = mapped_column(JSON, default=list, nullable=False)
    created_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    user: Mapped["User"] = relationship(back_populates="device_keys")
