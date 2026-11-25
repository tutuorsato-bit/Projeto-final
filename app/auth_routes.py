from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.dependencies import current_user, csrf_protected, optional_user
from app.mailer import send_account_email
from app.models import AuditLog, DeveloperProfile, OneTimeToken, User, UserSession
from app.schemas import (
    DeveloperInput,
    EmailInput,
    LoginInput,
    PasswordChangeInput,
    PasswordResetInput,
    ProfileInput,
    RegisterInput,
    TokenInput,
)
from app.security import (
    create_session,
    digest_token,
    get_session,
    hash_password,
    validate_request_origin,
    verify_password,
)

router = APIRouter(prefix="/api/auth", tags=["authentication"])


def _set_session_cookies(response: Response, session_token: str, csrf_token: str) -> None:
    response.set_cookie(
        "modstation_session",
        session_token,
        httponly=True,
        secure=settings.cookie_secure or settings.production,
        samesite=settings.cookie_same_site,
        max_age=14 * 24 * 60 * 60,
        path="/",
    )
    response.set_cookie(
        "modstation_csrf",
        csrf_token,
        httponly=False,
        secure=settings.cookie_secure or settings.production,
        samesite=settings.cookie_same_site,
        max_age=14 * 24 * 60 * 60,
        path="/",
    )


def _issue_one_time_token(db: Session, user: User, purpose: str) -> str:
    raw_token = secrets.token_urlsafe(40)
    db.add(
        OneTimeToken(
            user_id=user.id,
            token_hash=digest_token(raw_token),
            purpose=purpose,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
    )
    return raw_token


def _consume_one_time_token(db: Session, raw_token: str, purpose: str) -> tuple[OneTimeToken, User]:
    record = db.scalar(
        select(OneTimeToken).where(
            OneTimeToken.token_hash == digest_token(raw_token),
            OneTimeToken.purpose == purpose,
        )
    )
    if record is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid or expired token")
    expiry = record.expires_at
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    if expiry <= datetime.now(timezone.utc):
        db.delete(record)
        db.commit()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid or expired token")
    user = db.get(User, record.user_id)
    if user is None:
        db.delete(record)
        db.commit()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid or expired token")
    return record, user


@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(payload: RegisterInput, db: Session = Depends(get_db)):
    email = str(payload.email).lower()
    if db.scalar(
        select(User.id).where(
            (func.lower(User.email) == email) | (func.lower(User.username) == payload.username.lower())
        )
    ):
        raise HTTPException(status.HTTP_409_CONFLICT, "Email or username is already registered")
    if settings.require_email_verification and not settings.smtp_host:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "Email verification is required but SMTP is not configured",
        )
    user = User(
        email=email,
        username=payload.username,
        password_hash=hash_password(payload.password),
    )
    db.add(user)
    db.flush()
    if settings.smtp_host:
        raw_token = _issue_one_time_token(db, user, "verify_email")
        try:
            send_account_email(
                user.email,
                "Verifique seu e-mail no ModStation",
                f"Use este token na tela de verificacao da conta: {raw_token}\nValidade: 1 hora.",
            )
        except (OSError, RuntimeError) as exc:
            db.rollback()
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE, "Could not deliver verification email"
            ) from exc
    db.add(
        AuditLog(
            actor_id=user.id,
            action="account.register",
            target_type="user",
            target_id=str(user.id),
        )
    )
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Email or username is already registered"
        ) from exc
    return {
        "id": user.id,
        "username": user.username,
        "email_verified": user.email_verified,
        "verification_email_sent": bool(settings.smtp_host),
    }


@router.post("/login")
def login(payload: LoginInput, response: Response, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(func.lower(User.email) == str(payload.email).lower()))
    if user is None or not user.active or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password")
    session_token, csrf_token = create_session(db, user)
    db.add(
        AuditLog(
            actor_id=user.id,
            action="account.login",
            target_type="user",
            target_id=str(user.id),
        )
    )
    db.commit()
    _set_session_cookies(response, session_token, csrf_token)
    return {
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "email_verified": user.email_verified,
        "csrf_token": csrf_token,
    }


@router.post("/logout")
def logout(
    response: Response,
    request: Request,
    user: User = Depends(csrf_protected),
    db: Session = Depends(get_db),
):
    token = request.cookies.get("modstation_session")
    if token:
        record = db.scalar(select(UserSession).where(UserSession.token_hash == digest_token(token)))
        if record:
            db.delete(record)
            db.commit()
    response.delete_cookie(
        "modstation_session",
        path="/",
        secure=settings.cookie_secure or settings.production,
        samesite=settings.cookie_same_site,
    )
    response.delete_cookie(
        "modstation_csrf",
        path="/",
        secure=settings.cookie_secure or settings.production,
        samesite=settings.cookie_same_site,
    )
    return {"ok": True}


@router.get("/me")
def me(user: User = Depends(current_user)):
    profile = user.profile
    return {
        "id": user.id,
        "email": user.email,
        "username": user.username,
        "role": user.role,
        "email_verified": user.email_verified,
        "created_at": user.created_at,
        "developer_profile": (
            {
                "display_name": profile.display_name,
                "bio": profile.bio,
                "website": profile.website,
                "identity_verified": profile.identity_verified,
            }
            if profile
            else None
        ),
    }


@router.post("/csrf")
def refresh_csrf_token(
    request: Request,
    identity: tuple[User | None, UserSession | None] = Depends(optional_user),
    db: Session = Depends(get_db),
):
    user, session = identity
    if user is None or session is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentication required")
    if not validate_request_origin(request):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Request origin is not allowed")
    csrf_token = secrets.token_urlsafe(32)
    session.csrf_hash = digest_token(csrf_token)
    db.commit()
    return {"csrf_token": csrf_token}


@router.post("/verify-email")
def verify_email(payload: TokenInput, db: Session = Depends(get_db)):
    record, user = _consume_one_time_token(db, payload.token, "verify_email")
    user.email_verified = True
    db.delete(record)
    db.add(
        AuditLog(
            actor_id=user.id,
            action="account.email_verified",
            target_type="user",
            target_id=str(user.id),
        )
    )
    db.commit()
    return {"email_verified": True}


@router.post("/verification-email")
def resend_verification(payload: EmailInput, db: Session = Depends(get_db)):
    if not settings.smtp_host:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Email delivery is not configured")
    user = db.scalar(select(User).where(func.lower(User.email) == str(payload.email).lower()))
    if user and not user.email_verified:
        raw_token = _issue_one_time_token(db, user, "verify_email")
        try:
            send_account_email(
                user.email,
                "Verifique seu e-mail no ModStation",
                f"Token de verificacao: {raw_token}\nValidade: 1 hora.",
            )
        except (OSError, RuntimeError) as exc:
            db.rollback()
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Email delivery failed") from exc
        db.commit()
    return {"message": "If the account can be verified, instructions have been sent"}


@router.post("/password-reset/request")
def request_password_reset(payload: EmailInput, db: Session = Depends(get_db)):
    if not settings.smtp_host:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Password recovery email is not configured")
    user = db.scalar(select(User).where(func.lower(User.email) == str(payload.email).lower()))
    if user and user.active:
        raw_token = _issue_one_time_token(db, user, "password_reset")
        try:
            send_account_email(
                user.email,
                "Redefinicao de senha do ModStation",
                f"Token de redefinicao: {raw_token}\nValidade: 1 hora.",
            )
        except (OSError, RuntimeError) as exc:
            db.rollback()
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Email delivery failed") from exc
        db.commit()
    return {"message": "If the account exists, password reset instructions have been sent"}


@router.post("/password-reset/confirm")
def confirm_password_reset(payload: PasswordResetInput, db: Session = Depends(get_db)):
    record, user = _consume_one_time_token(db, payload.token, "password_reset")
    user.password_hash = hash_password(payload.password)
    db.delete(record)
    db.query(UserSession).filter(UserSession.user_id == user.id).delete()
    db.add(
        AuditLog(
            actor_id=user.id,
            action="account.password_reset",
            target_type="user",
            target_id=str(user.id),
        )
    )
    db.commit()
    return {"password_reset": True}


@router.patch("/password")
def change_password(
    payload: PasswordChangeInput,
    request: Request,
    user: User = Depends(csrf_protected),
    db: Session = Depends(get_db),
):
    if not verify_password(payload.current_password, user.password_hash):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Current password is incorrect")
    session_token = request.cookies.get("modstation_session")
    active_session = db.scalar(
        select(UserSession).where(
            UserSession.token_hash == digest_token(session_token or ""),
            UserSession.user_id == user.id,
        )
    )
    if active_session is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session is no longer valid")
    user.password_hash = hash_password(payload.new_password)
    db.query(UserSession).filter(
        UserSession.user_id == user.id,
        UserSession.id != active_session.id,
    ).delete()
    db.add(
        AuditLog(
            actor_id=user.id,
            action="account.password_changed",
            target_type="user",
            target_id=str(user.id),
        )
    )
    db.commit()
    return {"password_changed": True, "other_sessions_revoked": True}


@router.post("/developer")
def apply_as_developer(
    payload: DeveloperInput,
    user: User = Depends(csrf_protected),
    db: Session = Depends(get_db),
):
    if settings.require_email_verification and not user.email_verified:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Verify your email before applying")
    if user.role not in {"user", "developer"}:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "This account cannot apply for developer access")
    existing = db.scalar(select(DeveloperProfile).where(DeveloperProfile.user_id == user.id))
    if existing is None:
        existing = DeveloperProfile(
            user_id=user.id,
            display_name=payload.display_name,
            bio=payload.bio,
            website=str(payload.website or ""),
        )
        db.add(existing)
    else:
        existing.display_name = payload.display_name
        existing.bio = payload.bio
        existing.website = str(payload.website or "")
    user.role = "developer"
    db.add(
        AuditLog(
            actor_id=user.id,
            action="developer.profile_updated",
            target_type="user",
            target_id=str(user.id),
        )
    )
    db.commit()
    return {"role": user.role, "display_name": existing.display_name}


@router.patch("/profile")
def update_profile(
    payload: ProfileInput,
    user: User = Depends(csrf_protected),
    db: Session = Depends(get_db),
):
    if user.profile is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Developer profile not found")
    user.profile.display_name = payload.display_name
    user.profile.bio = payload.bio
    user.profile.website = str(payload.website or "")
    db.commit()
    return {"display_name": user.profile.display_name, "bio": user.profile.bio}
