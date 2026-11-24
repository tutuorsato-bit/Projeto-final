from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User, UserSession
from app.security import get_session, validate_csrf, validate_request_origin


def optional_user(
    request: Request, db: Session = Depends(get_db)
) -> tuple[User | None, UserSession | None]:
    return get_session(db, request.cookies.get("modstation_session"))


def current_user(
    identity: tuple[User | None, UserSession | None] = Depends(optional_user),
) -> User:
    user, _ = identity
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentication required")
    return user


def csrf_protected(
    request: Request,
    identity: tuple[User | None, UserSession | None] = Depends(optional_user),
) -> User:
    user, record = identity
    if user is None or record is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentication required")
    if not validate_csrf(record, request.headers.get("x-csrf-token")):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "CSRF token is missing or invalid")
    if not validate_request_origin(request):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Request origin is not allowed")
    return user


def require_roles(*roles: str):
    def dependency(
        request: Request,
        identity: tuple[User | None, UserSession | None] = Depends(optional_user),
    ) -> User:
        user, record = identity
        if user is None or record is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentication required")
        if request.method not in {"GET", "HEAD", "OPTIONS"} and not validate_csrf(
            record, request.headers.get("x-csrf-token")
        ):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "CSRF token is missing or invalid")
        if request.method not in {"GET", "HEAD", "OPTIONS"} and not validate_request_origin(request):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Request origin is not allowed")
        if user.role not in roles:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient permissions")
        return user
    return dependency
