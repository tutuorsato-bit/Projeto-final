from __future__ import annotations

import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from app.config import settings


class ObjectStorageError(RuntimeError):
    pass


class PrivateStorage:
    def __init__(self) -> None:
        self.bucket = settings.object_storage_bucket
        self._client = None
        if self.bucket:
            if not all(
                (
                    settings.object_storage_endpoint,
                    settings.object_storage_access_key,
                    settings.object_storage_secret_key,
                )
            ):
                raise ObjectStorageError(
                    "OBJECT_STORAGE_ENDPOINT, OBJECT_STORAGE_ACCESS_KEY and "
                    "OBJECT_STORAGE_SECRET_KEY are required when OBJECT_STORAGE_BUCKET is set"
                )
            try:
                import boto3
                from botocore.config import Config
            except ImportError as exc:
                raise ObjectStorageError(
                    "boto3 and botocore are required for S3-compatible object storage"
                ) from exc
            self._client = boto3.client(
                "s3",
                endpoint_url=settings.object_storage_endpoint,
                region_name=settings.object_storage_region,
                aws_access_key_id=settings.object_storage_access_key,
                aws_secret_access_key=settings.object_storage_secret_key,
                config=Config(signature_version="s3v4"),
            )

    def quarantine_key(self, storage_key: str) -> str:
        return f"quarantine/{storage_key}.blob"

    def approved_key(self, storage_key: str) -> str:
        return f"approved/{storage_key}.blob"

    def put_quarantine(self, storage_key: str, data: bytes) -> None:
        if self._client:
            self._client.put_object(
                Bucket=self.bucket,
                Key=self.quarantine_key(storage_key),
                Body=data,
                ContentType="application/octet-stream",
                ServerSideEncryption="AES256",
            )
            return
        path = settings.quarantine_root / f"{storage_key}.blob"
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with path.open("xb") as target:
            target.write(data)
        os.chmod(path, 0o600)

    def put_quarantine_file(self, storage_key: str, path: Path) -> None:
        self.put_quarantine(storage_key, path.read_bytes())

    def read_approved(self, storage_key: str) -> bytes | None:
        if self._client:
            try:
                response = self._client.get_object(
                    Bucket=self.bucket,
                    Key=self.approved_key(storage_key),
                )
                return response["Body"].read()
            except Exception as exc:
                if getattr(exc, "response", {}).get("Error", {}).get("Code") in {
                    "NoSuchKey",
                    "404",
                    "NotFound",
                }:
                    return None
                raise ObjectStorageError("Could not read approved private file") from exc
        path = settings.storage_root / f"{storage_key}.blob"
        if not path.is_file() or path.is_symlink():
            return None
        return path.read_bytes()

    def approved_exists(self, storage_key: str) -> bool:
        return self.read_approved(storage_key) is not None

    @contextmanager
    def scan_quarantine(self, storage_key: str) -> Iterator[Path | None]:
        if self._client:
            try:
                response = self._client.get_object(
                    Bucket=self.bucket,
                    Key=self.quarantine_key(storage_key),
                )
                data = response["Body"].read()
            except Exception as exc:
                if getattr(exc, "response", {}).get("Error", {}).get("Code") in {
                    "NoSuchKey",
                    "404",
                    "NotFound",
                }:
                    yield None
                    return
                raise ObjectStorageError("Could not read quarantined file") from exc
            with tempfile.NamedTemporaryFile(prefix="modstation-scan-", suffix=".blob", delete=False) as temp:
                temp.write(data)
                temp_path = Path(temp.name)
            try:
                yield temp_path
            finally:
                temp_path.unlink(missing_ok=True)
            return
        path = settings.quarantine_root / f"{storage_key}.blob"
        if not path.is_file() or path.is_symlink():
            yield None
            return
        yield path

    def approve(self, storage_key: str) -> bool:
        if self._client:
            try:
                response = self._client.get_object(
                    Bucket=self.bucket,
                    Key=self.quarantine_key(storage_key),
                )
                self._client.put_object(
                    Bucket=self.bucket,
                    Key=self.approved_key(storage_key),
                    Body=response["Body"].read(),
                    ContentType="application/octet-stream",
                    ServerSideEncryption="AES256",
                )
                self._client.delete_object(
                    Bucket=self.bucket,
                    Key=self.quarantine_key(storage_key),
                )
                return True
            except Exception as exc:
                raise ObjectStorageError("Could not move quarantined file to approved storage") from exc
        source = settings.quarantine_root / f"{storage_key}.blob"
        destination = settings.storage_root / f"{storage_key}.blob"
        if not source.is_file() or source.is_symlink():
            return False
        settings.storage_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            os.replace(source, destination)
            os.chmod(destination, 0o600)
            return True
        except OSError:
            return False

    def quarantine(self, storage_key: str) -> bool:
        if self._client:
            try:
                response = self._client.get_object(
                    Bucket=self.bucket,
                    Key=self.approved_key(storage_key),
                )
                self._client.put_object(
                    Bucket=self.bucket,
                    Key=self.quarantine_key(storage_key),
                    Body=response["Body"].read(),
                    ContentType="application/octet-stream",
                    ServerSideEncryption="AES256",
                )
                self._client.delete_object(
                    Bucket=self.bucket,
                    Key=self.approved_key(storage_key),
                )
                return True
            except Exception as exc:
                raise ObjectStorageError("Could not move approved file to quarantine") from exc
        source = settings.storage_root / f"{storage_key}.blob"
        destination = settings.quarantine_root / f"{storage_key}.blob"
        if not source.is_file() or source.is_symlink():
            return False
        settings.quarantine_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            os.replace(source, destination)
            os.chmod(destination, 0o600)
            return True
        except OSError:
            return False


private_storage = PrivateStorage()
