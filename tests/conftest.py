import os
import tempfile
from pathlib import Path

TEST_ROOT = Path(tempfile.mkdtemp(prefix="modstation-tests-"))
os.environ["DATABASE_URL"] = "sqlite://"
os.environ["SECRET_KEY"] = "test-only-secret-key-that-is-at-least-32-chars"
os.environ["APP_ENV"] = "test"
os.environ["COOKIE_SECURE"] = "false"
os.environ["STORAGE_ROOT"] = str(TEST_ROOT / "storage")
os.environ["QUARANTINE_ROOT"] = str(TEST_ROOT / "quarantine")
os.environ["CLAMD_HOST"] = "127.0.0.1"
os.environ["CLAMD_PORT"] = "1"
os.environ["REQUIRE_EMAIL_VERIFICATION"] = "false"
os.environ["MAX_UPLOAD_BYTES"] = "1048576"
