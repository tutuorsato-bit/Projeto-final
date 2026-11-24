from __future__ import annotations

import os
import re
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from app.admin_routes import router as admin_router
from app.auth_routes import router as auth_router
from app.config import settings
from app.content_routes import router as content_router
from app.database import engine
from app.security import validate_secret_configuration

WEB_ROOT = Path(__file__).resolve().parent.parent / "web"
RATE_LIMITS: dict[str, deque[float]] = defaultdict(deque)
UPLOAD_BODY_OVERHEAD = 1024 * 1024
_api_origin = settings.api_url or ""
_connect_sources = "'self'" + (
    f" {_api_origin}" if _api_origin else ""
)
_image_sources = "'self' data:" + (
    f" {_api_origin}" if _api_origin else ""
)
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        f"img-src {_image_sources}; connect-src {_connect_sources}; object-src 'none'; "
        "base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
    ),
}


class UploadBodyTooLarge(Exception):
    pass


class UploadLimitMiddleware:
    def __init__(self, application):
        self.application = application

    async def __call__(self, scope, receive, send):
        if (
            scope["type"] != "http"
            or scope.get("method") != "POST"
            or not re.fullmatch(r"/api/contents/\d+/(?:files|images)", scope.get("path", ""))
        ):
            await self.application(scope, receive, send)
            return
        is_image = scope["path"].endswith("/images")
        body_limit = min(settings.max_upload_bytes, 5 * 1024 * 1024) if is_image else settings.max_upload_bytes
        limit = body_limit + UPLOAD_BODY_OVERHEAD
        content_length = next(
            (value for name, value in scope.get("headers", []) if name.lower() == b"content-length"),
            None,
        )
        if content_length:
            try:
                if int(content_length) > limit:
                    response = JSONResponse(
                        {"detail": "Upload request exceeds the configured size limit"},
                        status_code=413,
                        headers=SECURITY_HEADERS,
                    )
                    await response(scope, receive, send)
                    return
            except ValueError:
                response = JSONResponse(
                    {"detail": "Invalid Content-Length"},
                    status_code=400,
                    headers=SECURITY_HEADERS,
                )
                await response(scope, receive, send)
                return
        received = 0

        async def limited_receive():
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise UploadBodyTooLarge
            return message

        try:
            await self.application(scope, limited_receive, send)
        except UploadBodyTooLarge:
            response = JSONResponse(
                {"detail": "Upload request exceeds the configured size limit"},
                status_code=413,
                headers=SECURITY_HEADERS,
            )
            await response(scope, receive, send)


@asynccontextmanager
async def lifespan(_: FastAPI):
    validate_secret_configuration()
    if settings.production and not settings.allowed_origins:
        raise RuntimeError("ALLOWED_ORIGINS must contain the public frontend origin in production")
    if settings.cookie_same_site not in {"lax", "strict", "none"}:
        raise RuntimeError("COOKIE_SAME_SITE must be lax, strict, or none")
    if settings.production and settings.cookie_same_site == "none" and not settings.cookie_secure:
        raise RuntimeError("Secure cookies are required when COOKIE_SAME_SITE=none")
    storage = settings.storage_root.resolve()
    quarantine = settings.quarantine_root.resolve()
    web_root = WEB_ROOT.resolve()
    if (
        storage == quarantine
        or storage == web_root
        or quarantine == web_root
        or storage in quarantine.parents
        or quarantine in storage.parents
        or web_root in storage.parents
        or web_root in quarantine.parents
        or storage in web_root.parents
        or quarantine in web_root.parents
    ):
        raise RuntimeError("Private file directories must be separate and outside the web root")
    if settings.max_upload_bytes < 1:
        raise RuntimeError("MAX_UPLOAD_BYTES must be positive")
    for directory in (settings.storage_root, settings.quarantine_root):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(directory, 0o700)
    yield
    engine.dispose()


app = FastAPI(
    title="ModStation API",
    version="1.0.0",
    description="Minecraft Java and Bedrock content discovery, publishing, and secure distribution.",
    docs_url=None if settings.production else "/docs",
    redoc_url=None,
    lifespan=lifespan,
)

app.include_router(auth_router)
app.include_router(content_router)
app.include_router(admin_router)
app.mount("/assets", StaticFiles(directory=WEB_ROOT / "assets"), name="assets")

if settings.allowed_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.allowed_origins),
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-CSRF-Token"],
    )


@app.middleware("http")
async def security_and_rate_limit(request: Request, call_next):
    path = request.url.path
    if path.startswith("/api/"):
        address = request.client.host if request.client else "unknown"
        parts = path.split("/")
        route_class = parts[2] if len(parts) > 2 else "api"
        if path in {"/api/auth/password-reset/request", "/api/auth/verification-email"}:
            route_class = path
        elif path in {
            "/api/auth/verify-email",
            "/api/auth/password-reset/confirm",
        }:
            route_class = path
        elif re.fullmatch(r"/api/contents/\d+/(?:files|images)", path):
            route_class = "uploads"
        elif path == "/api/reports" or re.fullmatch(
            r"/api/contents/\d+/(?:comments|rating|favorite)", path
        ):
            route_class = "community"
        key = f"{address}:{route_class}"
        now = time.monotonic()
        if key not in RATE_LIMITS and len(RATE_LIMITS) >= 4096:
            for stale_key in list(RATE_LIMITS):
                if not RATE_LIMITS[stale_key] or RATE_LIMITS[stale_key][-1] <= now - 60:
                    del RATE_LIMITS[stale_key]
            if len(RATE_LIMITS) >= 4096:
                response = JSONResponse(
                    {"detail": "Rate limit capacity reached"},
                    status_code=429,
                    headers={**SECURITY_HEADERS, "Retry-After": "60"},
                )
                return response
        events = RATE_LIMITS[key]
        while events and events[0] <= now - 60:
            events.popleft()
        maximum = (
            5
            if path in {"/api/auth/password-reset/request", "/api/auth/verification-email"}
            else 10
            if path in {
                "/api/auth/login",
                "/api/auth/register",
                "/api/auth/verify-email",
                "/api/auth/password-reset/confirm",
            }
            else 6
            if route_class == "uploads"
            else 30
            if route_class == "community"
            else 180
        )
        if len(events) >= maximum:
            return JSONResponse(
                {"detail": "Rate limit exceeded; retry shortly"},
                status_code=429,
                headers={**SECURITY_HEADERS, "Retry-After": "60"},
            )
        events.append(now)
    response = await call_next(request)
    for name, value in SECURITY_HEADERS.items():
        response.headers[name] = value
    if settings.production:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


app.add_middleware(UploadLimitMiddleware)


@app.get("/api/health")
def health():
    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))
    return {"status": "ok"}


@app.get("/", include_in_schema=False)
def home():
    return FileResponse(WEB_ROOT / "index.html")


@app.get("/{spa_path:path}", include_in_schema=False)
def spa_fallback(spa_path: str):
    if spa_path.startswith("api/") or "." in spa_path:
        return JSONResponse({"detail": "Not found"}, status_code=404)
    return FileResponse(WEB_ROOT / "index.html")
