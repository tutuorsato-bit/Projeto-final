from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    database_url: str = os.getenv("DATABASE_URL", "sqlite:///./data/modstation.db")
    secret_key: str = os.getenv("SECRET_KEY", "")
    app_env: str = os.getenv("APP_ENV", "development")
    cookie_secure: bool = os.getenv("COOKIE_SECURE", "false").lower() == "true"
    max_upload_bytes: int = int(os.getenv("MAX_UPLOAD_BYTES", str(20 * 1024 * 1024)))
    storage_root: Path = Path(os.getenv("STORAGE_ROOT", "./storage"))
    quarantine_root: Path = Path(os.getenv("QUARANTINE_ROOT", "./quarantine"))
    clamd_host: str = os.getenv("CLAMD_HOST", "127.0.0.1")
    clamd_port: int = int(os.getenv("CLAMD_PORT", "3310"))
    yara_rules_path: Path = Path(os.getenv("YARA_RULES_PATH", "./security/rules.yar"))
    virustotal_api_key: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    smtp_host: str = os.getenv("SMTP_HOST", "")
    smtp_port: int = int(os.getenv("SMTP_PORT", "587"))
    smtp_username: str = os.getenv("SMTP_USERNAME", "")
    smtp_password: str = os.getenv("SMTP_PASSWORD", "")
    smtp_from: str = os.getenv("SMTP_FROM", "ModStation <noreply@example.invalid>")
    allowed_origins: tuple[str, ...] = tuple(
        origin.strip().rstrip("/")
        for origin in (
            os.getenv("ALLOWED_ORIGINS", "").split(",")
            + (
                [
                    f"https://{os.getenv('CODESPACE_NAME')}-8000."
                    f"{os.getenv('GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN')}"
                ]
                if os.getenv("CODESPACE_NAME")
                and os.getenv("GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN")
                else []
            )
        )
        if origin.strip()
    )
    api_url: str = os.getenv("API_URL", "").rstrip("/")
    cookie_same_site: str = os.getenv("COOKIE_SAME_SITE", "lax").lower()
    object_storage_bucket: str = os.getenv("OBJECT_STORAGE_BUCKET", "")
    object_storage_endpoint: str = os.getenv("OBJECT_STORAGE_ENDPOINT", "")
    object_storage_region: str = os.getenv("OBJECT_STORAGE_REGION", "auto")
    object_storage_access_key: str = os.getenv("OBJECT_STORAGE_ACCESS_KEY", "")
    object_storage_secret_key: str = os.getenv("OBJECT_STORAGE_SECRET_KEY", "")
    require_email_verification: bool = (
        os.getenv("REQUIRE_EMAIL_VERIFICATION", "false").lower() == "true"
    )

    @property
    def production(self) -> bool:
        return self.app_env.lower() == "production"


settings = Settings()
