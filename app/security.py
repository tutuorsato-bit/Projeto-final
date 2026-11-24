from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.models import User, UserSession

password_hasher = PasswordHasher()
SESSION_TTL = timedelta(days=14)


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return password_hasher.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def digest_token(token: str) -> str:
    key = settings.secret_key.encode("utf-8") or b"development-only-token-key"
    return hmac.new(key, token.encode("utf-8"), hashlib.sha256).hexdigest()


def create_session(db: Session, user: User) -> tuple[str, str]:
    session_token = secrets.token_urlsafe(48)
    csrf_token = secrets.token_urlsafe(32)
    db.add(
        UserSession(
            user_id=user.id,
            token_hash=digest_token(session_token),
            csrf_hash=digest_token(csrf_token),
            expires_at=datetime.now(timezone.utc) + SESSION_TTL,
        )
    )
    db.commit()
    return session_token, csrf_token


def get_session(db: Session, token: str | None) -> tuple[User | None, UserSession | None]:
    if not token:
        return None, None
    record = db.scalar(
        select(UserSession).where(UserSession.token_hash == digest_token(token))
    )
    if record is None:
        return None, None
    expires_at = record.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at <= datetime.now(timezone.utc):
        db.delete(record)
        db.commit()
        return None, None
    user = db.get(User, record.user_id)
    if user is None or not user.active:
        return None, None
    return user, record


def validate_csrf(record: UserSession, supplied: str | None) -> bool:
    return bool(supplied) and secrets.compare_digest(
        record.csrf_hash, digest_token(supplied or "")
    )


def validate_secret_configuration() -> None:
    if settings.production and (
        len(settings.secret_key) < 32
        or settings.secret_key.startswith("replace-")
        or settings.secret_key.lower() in {"changeme", "change-me", "secret", "development"}
    ):
        raise RuntimeError("SECRET_KEY must be configured with at least 32 characters in production")
    if settings.production and not settings.require_email_verification:
        raise RuntimeError("REQUIRE_EMAIL_VERIFICATION must be enabled in production")
    if settings.production and settings.require_email_verification and not settings.smtp_host:
        raise RuntimeError("SMTP_HOST is required when email verification is enforced")


def validate_request_origin(request) -> bool:
    origin = request.headers.get("origin")
    referer = request.headers.get("referer")
    if not origin and not referer:
        return True
    candidate = origin or referer
    candidate_origin = urlparse(candidate).scheme + "://" + urlparse(candidate).netloc
    if settings.allowed_origins:
        return candidate_origin.rstrip("/") in {
            allowed.rstrip("/") for allowed in settings.allowed_origins
        }
    if settings.production:
        return False
    return True
