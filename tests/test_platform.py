from io import BytesIO
import asyncio
from dataclasses import replace
import struct
import zlib
from zipfile import ZIP_DEFLATED, ZipFile

import pytest
from fastapi.testclient import TestClient

from app.database import Base, SessionLocal, engine
from app.main import RATE_LIMITS, app
from app.models import DeveloperProfile, User
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
    archive = BytesIO()
    with ZipFile(archive, "w", ZIP_DEFLATED) as zipped:
        zipped.writestr("pack.mcmeta", '{"pack":{"pack_format":1,"description":"test"}}')
    uploaded = client.post(
        f"/api/contents/{created.json()['id']}/files?version=1.0.0",
        files={"upload": ("starter.zip", archive.getvalue(), "application/zip")},
        headers={"X-CSRF-Token": token},
    )
    assert uploaded.status_code == 202
    file_id = uploaded.json()["id"]
    uploaded_image = client.post(
        f"/api/contents/{created.json()['id']}/images",
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
