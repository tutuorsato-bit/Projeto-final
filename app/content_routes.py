from __future__ import annotations

import hashlib
import io
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, Query, UploadFile, status
from fastapi.responses import StreamingResponse
from sqlalchemy import func, or_, select, update
from sqlalchemy.orm import Session

from app.config import settings
from app.database import SessionLocal, get_db
from app.dependencies import current_user, csrf_protected, optional_user
from app.mse import MAX_IMAGE_BYTES, sanitize_png, scan_file
from app.models import (
    AuditLog,
    Comment,
    Content,
    DeveloperProfile,
    DownloadEvent,
    Favorite,
    Notification,
    Rating,
    ReleaseFile,
    Report,
    SecurityScan,
    User,
    utcnow,
)
from app.models import UserSession
from app.schemas import CommentInput, ContentInput, RatingInput, ReportInput
from app.storage import private_storage

router = APIRouter(prefix="/api", tags=["catalog and publishing"])
ALLOWED_ARCHIVES = {".jar", ".zip", ".mcpack", ".mcaddon", ".mctemplate"}
ARCHIVE_MIME_TYPES = {
    "application/java-archive",
    "application/zip",
    "application/x-java-archive",
    "application/x-zip-compressed",
}


def _validate_declared_mime(content_type: str | None, *, image: bool) -> None:
    if not content_type:
        return
    mime_type = content_type.partition(";")[0].strip().lower()
    accepted = {"application/octet-stream", "binary/octet-stream"}
    accepted.update({"image/png"} if image else ARCHIVE_MIME_TYPES)
    if mime_type not in accepted:
        expected = "PNG" if image else "ZIP-compatible archive"
        raise HTTPException(
            status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            f"Unsupported declared MIME type; expected {expected}",
        )


def _slugify(value: str) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")[:100]
    return base or "content"


def _content_data(content: Content, db: Session, include_private: bool = False) -> dict:
    rating = db.query(func.avg(Rating.score), func.count(Rating.id)).filter(
        Rating.content_id == content.id
    ).one()
    files = db.scalars(
        select(ReleaseFile)
        .where(
            ReleaseFile.content_id == content.id,
            *(
                []
                if include_private
                else [
                    ReleaseFile.file_type == "archive",
                    ReleaseFile.scan_status == "approved",
                    ReleaseFile.review_status == "approved",
                ]
            ),
        )
        .order_by(ReleaseFile.created_at.desc())
    ).all()
    images = db.scalars(
        select(ReleaseFile)
        .where(
            ReleaseFile.content_id == content.id,
            ReleaseFile.file_type == "image",
            *(
                []
                if include_private
                else [
                    ReleaseFile.scan_status == "approved",
                    ReleaseFile.review_status == "approved",
                ]
            ),
        )
        .order_by(ReleaseFile.created_at.desc())
    ).all()
    return {
        "id": content.id,
        "slug": content.slug,
        "name": content.name,
        "description": content.description,
        "category": content.category,
        "edition": content.edition,
        "minecraft_version": content.minecraft_version,
        "license": content.license,
        "dependencies": content.dependencies or [],
        "credits": content.credits,
        "changelog": content.changelog,
        "status": content.status if include_private else "published",
        "developer": {
            "username": content.owner.username,
            "display_name": (
                content.owner.profile.display_name
                if content.owner.profile
                else content.owner.username
            ),
            "identity_verified": bool(
                content.owner.profile and content.owner.profile.identity_verified
            ),
        },
        "trust": trust_score(content.owner, db),
        "average_rating": round(float(rating[0] or 0), 2),
        "rating_count": int(rating[1]),
        "download_count": db.scalar(
            select(func.count(DownloadEvent.id)).join(
                ReleaseFile, ReleaseFile.id == DownloadEvent.file_id
            ).where(ReleaseFile.content_id == content.id)
        )
        or 0,
        "files": [
            {
                "id": file.id,
                "version": file.version,
                "name": file.original_name,
                "size_bytes": file.size_bytes,
                "sha256": file.sha256,
                "scan_status": file.scan_status,
                "review_status": file.review_status,
                "file_type": file.file_type,
                "download_url": f"/api/files/{file.id}/download",
            }
            for file in files
        ],
        "images": [
            {
                "id": image.id,
                "scan_status": image.scan_status,
                "review_status": image.review_status,
                "url": f"/api/images/{image.id}",
            }
            for image in images
        ],
        "created_at": content.created_at,
        "updated_at": content.updated_at,
    }


def trust_score(user: User, db: Session) -> dict:
    approved = db.scalar(
        select(func.count(Content.id)).where(
            Content.owner_id == user.id,
            Content.status == "published",
        )
    ) or 0
    confirmed_reports = db.scalar(
        select(func.count(Report.id))
        .outerjoin(Content, Content.id == Report.content_id)
        .outerjoin(Comment, Comment.id == Report.comment_id)
        .where(
            or_(Content.owner_id == user.id, Comment.user_id == user.id),
            Report.status == "resolved",
            Report.confirmed_violation.is_(True),
        )
    ) or 0
    resolved_violations = confirmed_reports
    account_age_days = max(
        0, (datetime.now(timezone.utc) - user.created_at.replace(tzinfo=timezone.utc)).days
    )
    score = min(100, 10 + min(account_age_days, 365) * 0.05 + min(approved, 20) * 2)
    score -= min(confirmed_reports, 10) * 4
    score -= min(resolved_violations, 10) * 12
    if user.profile and user.profile.identity_verified:
        score += 5
    bounded_score = round(max(0, min(100, score)))
    if bounded_score < 25:
        level = "new"
    elif bounded_score < 50:
        level = "established"
    elif bounded_score < 75:
        level = "trusted"
    else:
        level = "recognized"
    return {
        "score": bounded_score,
        "level": level,
        "criteria": {
            "account_age_days": account_age_days,
            "approved_publications": approved,
            "confirmed_reports": confirmed_reports,
            "identity_verified": bool(user.profile and user.profile.identity_verified),
        },
        "weights": {
            "base": 10,
            "account_age_points_per_day": 0.05,
            "account_age_days_cap": 365,
            "approved_publication_points": 2,
            "approved_publications_cap": 20,
            "confirmed_report_penalty": 4,
            "confirmed_violation_penalty": 12,
            "confirmed_cases_cap": 10,
            "verified_identity_bonus": 5,
        },
        "notice": "Trust is contextual and never replaces file security analysis.",
    }


@router.get("/contents")
def list_contents(
    q: str | None = Query(default=None, max_length=120),
    category: str | None = Query(default=None, max_length=48),
    edition: str | None = Query(default=None, pattern="^(java|bedrock|both)$"),
    minecraft_version: str | None = Query(default=None, max_length=64),
    verified_developer: bool = False,
    sort: str = Query(default="recent", pattern="^(recent|popular|rating)$"),
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=12, ge=1, le=48),
    db: Session = Depends(get_db),
):
    query = select(Content).where(Content.status == "published")
    if q:
        query = query.where(Content.name.ilike(f"%{q.strip()}%"))
    if category:
        query = query.where(Content.category == category)
    if edition and edition != "both":
        query = query.where(Content.edition.in_([edition, "both"]))
    if minecraft_version:
        query = query.where(Content.minecraft_version == minecraft_version)
    if verified_developer:
        query = query.join(User, User.id == Content.owner_id).join(
            DeveloperProfile, DeveloperProfile.user_id == User.id
        ).where(DeveloperProfile.identity_verified.is_(True))
    if sort == "recent":
        query = query.order_by(Content.updated_at.desc())
    elif sort == "popular":
        query = query.outerjoin(ReleaseFile).outerjoin(DownloadEvent).group_by(Content.id).order_by(
            func.count(DownloadEvent.id).desc(), Content.updated_at.desc()
        )
    else:
        query = query.outerjoin(Rating).group_by(Content.id).order_by(
            func.avg(Rating.score).desc(), func.count(Rating.id).desc()
        )
    count_query = select(func.count(Content.id)).where(Content.status == "published")
    if q:
        count_query = count_query.where(Content.name.ilike(f"%{q.strip()}%"))
    if category:
        count_query = count_query.where(Content.category == category)
    if edition and edition != "both":
        count_query = count_query.where(Content.edition.in_([edition, "both"]))
    if minecraft_version:
        count_query = count_query.where(Content.minecraft_version == minecraft_version)
    if verified_developer:
        count_query = count_query.join(User, User.id == Content.owner_id).join(
            DeveloperProfile, DeveloperProfile.user_id == User.id
        ).where(DeveloperProfile.identity_verified.is_(True))
    contents = db.scalars(query.offset((page - 1) * per_page).limit(per_page)).unique().all()
    total = db.scalar(count_query) or 0
    return {
        "items": [_content_data(content, db) for content in contents],
        "page": page,
        "per_page": per_page,
        "total": total,
        "pages": (total + per_page - 1) // per_page,
    }


@router.get("/contents/{slug}")
def get_content(slug: str, db: Session = Depends(get_db)):
    content = db.scalar(select(Content).where(Content.slug == slug, Content.status == "published"))
    if content is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Content not found")
    return _content_data(content, db)


@router.get("/developers/{username}")
def developer_profile(username: str, db: Session = Depends(get_db)):
    user = db.scalar(
        select(User).where(func.lower(User.username) == username.lower(), User.active.is_(True))
    )
    if user is None or user.profile is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Developer profile not found")
    contents = db.scalars(
        select(Content)
        .where(Content.owner_id == user.id, Content.status == "published")
        .order_by(Content.updated_at.desc())
        .limit(50)
    ).all()
    return {
        "username": user.username,
        "display_name": user.profile.display_name,
        "bio": user.profile.bio,
        "website": user.profile.website,
        "identity_verified": user.profile.identity_verified,
        "trust": trust_score(user, db),
        "contents": [_content_data(content, db) for content in contents],
    }


@router.post("/contents", status_code=status.HTTP_201_CREATED)
def create_content(
    payload: ContentInput,
    user: User = Depends(csrf_protected),
    db: Session = Depends(get_db),
):
    if user.role != "developer" or user.profile is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Developer profile required")
    slug = _slugify(payload.name)
    if db.scalar(select(Content.id).where(Content.slug == slug)):
        slug = f"{slug}-{uuid.uuid4().hex[:8]}"
    content = Content(
        owner_id=user.id,
        slug=slug,
        name=payload.name.strip(),
        description=payload.description.strip(),
        category=payload.category.strip(),
        edition=payload.edition,
        minecraft_version=payload.minecraft_version.strip(),
        license=payload.license.strip(),
        dependencies=[item.strip()[:120] for item in payload.dependencies if item.strip()],
        credits=payload.credits.strip(),
        changelog=payload.changelog.strip(),
    )
    db.add(content)
    db.flush()
    db.add(
        AuditLog(
            actor_id=user.id,
            action="content.created",
            target_type="content",
            target_id=str(content.id),
        )
    )
    db.commit()
    return _content_data(content, db, include_private=True)


@router.get("/developer/contents")
def developer_contents(user: User = Depends(current_user), db: Session = Depends(get_db)):
    if user.role != "developer":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Developer access required")
    contents = db.scalars(
        select(Content).where(Content.owner_id == user.id).order_by(Content.updated_at.desc())
    ).all()
    return [_content_data(item, db, include_private=True) for item in contents]


@router.patch("/contents/{content_id}")
def update_content(
    content_id: int,
    payload: ContentInput,
    user: User = Depends(csrf_protected),
    db: Session = Depends(get_db),
):
    content = db.get(Content, content_id)
    if content is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Content not found")
    if content.owner_id != user.id or user.role != "developer":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Only the content owner can update it")
    if content.status not in {"draft", "rejected", "published"}:
        raise HTTPException(status.HTTP_409_CONFLICT, "Content cannot be edited in its current state")
    content.name = payload.name.strip()
    content.description = payload.description.strip()
    content.category = payload.category.strip()
    content.edition = payload.edition
    content.minecraft_version = payload.minecraft_version.strip()
    content.license = payload.license.strip()
    content.dependencies = [item.strip() for item in payload.dependencies if item.strip()]
    content.credits = payload.credits.strip()
    content.changelog = payload.changelog.strip()
    if content.status == "published":
        content.status = "pending"
        content.moderation_note = "Updated content requires review."
    content.updated_at = utcnow()
    db.add(
        AuditLog(
            actor_id=user.id,
            action="content.updated",
            target_type="content",
            target_id=str(content.id),
        )
    )
    db.commit()
    return _content_data(content, db, include_private=True)


@router.get("/developer/stats")
def developer_stats(user: User = Depends(current_user), db: Session = Depends(get_db)):
    if user.role != "developer":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Developer access required")
    return {
        "publications": db.scalar(
            select(func.count(Content.id)).where(Content.owner_id == user.id)
        )
        or 0,
        "published": db.scalar(
            select(func.count(Content.id)).where(
                Content.owner_id == user.id, Content.status == "published"
            )
        )
        or 0,
        "downloads": db.scalar(
            select(func.count(DownloadEvent.id))
            .join(ReleaseFile, ReleaseFile.id == DownloadEvent.file_id)
            .join(Content, Content.id == ReleaseFile.content_id)
            .where(Content.owner_id == user.id)
        )
        or 0,
        "reports_open": db.scalar(
            select(func.count(Report.id))
            .outerjoin(Content, Content.id == Report.content_id)
            .outerjoin(Comment, Comment.id == Report.comment_id)
            .where(
                or_(Content.owner_id == user.id, Comment.user_id == user.id),
                Report.status.in_(["open", "reviewing"]),
            )
        )
        or 0,
    }


@router.get("/developer/reports")
def developer_reports(user: User = Depends(current_user), db: Session = Depends(get_db)):
    if user.role != "developer":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Developer access required")
    reports = db.scalars(
        select(Report)
        .outerjoin(Content, Content.id == Report.content_id)
        .outerjoin(Comment, Comment.id == Report.comment_id)
        .where(or_(Content.owner_id == user.id, Comment.user_id == user.id))
        .order_by(Report.created_at.desc())
        .limit(100)
    ).all()
    return [
        {
            "id": report.id,
            "content_name": report.content.name if report.content else None,
            "reason": report.reason,
            "status": report.status,
            "created_at": report.created_at,
        }
        for report in reports
    ]


@router.post("/contents/{content_id}/files", status_code=status.HTTP_202_ACCEPTED)
def upload_release(
    content_id: int,
    background_tasks: BackgroundTasks,
    version: str = Query(min_length=1, max_length=64),
    upload: UploadFile = File(...),
    user: User = Depends(csrf_protected),
    db: Session = Depends(get_db),
):
    content = db.get(Content, content_id)
    if content is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Content not found")
    if content.owner_id != user.id or user.role != "developer":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Only the content owner can upload releases")
    if content.status not in {"draft", "rejected", "published"}:
        raise HTTPException(status.HTTP_409_CONFLICT, "Content is currently under moderation")
    original_name = (upload.filename or "").replace("\\", "/").split("/")[-1]
    if (
        not original_name
        or len(original_name) > 255
        or any(ord(char) < 32 or ord(char) == 127 for char in original_name)
        or Path(original_name).suffix.lower() not in ALLOWED_ARCHIVES
    ):
        raise HTTPException(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, "Unsupported archive format")
    _validate_declared_mime(upload.content_type, image=False)
    key = uuid.uuid4().hex
    data = bytearray()
    hasher = hashlib.sha256()
    try:
        while chunk := upload.file.read(1024 * 1024):
            if len(data) + len(chunk) > settings.max_upload_bytes:
                raise HTTPException(413, "Upload exceeds size limit")
            hasher.update(chunk)
            data.extend(chunk)
    except (OSError, HTTPException):
        raise
    finally:
        upload.file.close()
    if not data:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Empty uploads are not allowed")
    private_storage.put_quarantine(key, bytes(data))
    release = ReleaseFile(
        content_id=content.id,
        version=version.strip(),
        original_name=original_name,
        storage_key=key,
        sha256=hasher.hexdigest(),
        size_bytes=len(data),
        scan_status="queued",
    )
    db.add(release)
    db.flush()
    db.add(
        AuditLog(
            actor_id=user.id,
            action="file.uploaded",
            target_type="release_file",
            target_id=str(release.id),
            details=f"sha256={release.sha256}",
        )
    )
    db.commit()
    background_tasks.add_task(process_security_scan, release.id)
    return {"id": release.id, "scan_status": release.scan_status, "sha256": release.sha256}


@router.post("/contents/{content_id}/images", status_code=status.HTTP_202_ACCEPTED)
def upload_cover_image(
    content_id: int,
    background_tasks: BackgroundTasks,
    upload: UploadFile = File(...),
    user: User = Depends(csrf_protected),
    db: Session = Depends(get_db),
):
    content = db.get(Content, content_id)
    if content is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Content not found")
    if content.owner_id != user.id or user.role != "developer":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Only the content owner can upload images")
    if content.status not in {"draft", "rejected", "published"}:
        raise HTTPException(status.HTTP_409_CONFLICT, "Content is currently under moderation")
    original_name = (upload.filename or "").replace("\\", "/").split("/")[-1]
    if (
        not original_name
        or len(original_name) > 255
        or any(ord(char) < 32 or ord(char) == 127 for char in original_name)
        or Path(original_name).suffix.lower() != ".png"
    ):
        raise HTTPException(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, "Only PNG cover images are supported")
    _validate_declared_mime(upload.content_type, image=True)
    try:
        raw_image = upload.file.read(MAX_IMAGE_BYTES + 1)
    finally:
        upload.file.close()
    if len(raw_image) > MAX_IMAGE_BYTES:
        raise HTTPException(413, "Image exceeds the 5 MiB limit")
    try:
        safe_image = sanitize_png(raw_image)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid or unsafe PNG image") from exc
    key = uuid.uuid4().hex
    private_storage.put_quarantine(key, safe_image)
    sha256 = hashlib.sha256(safe_image).hexdigest()
    image = ReleaseFile(
        content_id=content.id,
        version="cover",
        original_name=original_name,
        storage_key=key,
        sha256=sha256,
        size_bytes=len(safe_image),
        file_type="image",
        scan_status="queued",
        review_status="pending",
    )
    db.add(image)
    db.flush()
    db.add(
        AuditLog(
            actor_id=user.id,
            action="image.uploaded",
            target_type="content_image",
            target_id=str(image.id),
            details=f"sha256={image.sha256}",
        )
    )
    db.commit()
    background_tasks.add_task(process_security_scan, image.id)
    return {"id": image.id, "scan_status": image.scan_status, "sha256": image.sha256}


def process_security_scan(file_id: int) -> None:
    with SessionLocal() as db:
        claimed = db.execute(
            update(ReleaseFile)
            .where(ReleaseFile.id == file_id, ReleaseFile.scan_status == "queued")
            .values(scan_status="scanning")
        )
        if claimed.rowcount != 1:
            db.rollback()
            return
        db.commit()
        release = db.get(ReleaseFile, file_id)
        if release is None:
            return
        try:
            with private_storage.scan_quarantine(release.storage_key) as path:
                if path is None:
                    scan_result = {"status": "inconclusive", "results": {"storage": "file_missing"}}
                    status_value = "inconclusive"
                else:
                    hasher = hashlib.sha256()
                    with path.open("rb") as source:
                        while chunk := source.read(1024 * 1024):
                            hasher.update(chunk)
                    if hasher.hexdigest() != release.sha256:
                        status_value = "rejected"
                        scan_result = {"status": "rejected", "results": {"storage": "sha256_mismatch"}}
                    else:
                        outcome = scan_file(path, release.original_name, release.sha256)
                        status_value = outcome.status
                        scan_result = {"status": outcome.status, "results": outcome.results}
        except Exception as exc:
            status_value = "inconclusive"
            scan_result = {
                "status": "inconclusive",
                "results": {"storage_error": type(exc).__name__},
            }
        scan = SecurityScan(
            file_id=release.id,
            sha256=release.sha256,
            status=status_value,
            scanner_results=json.dumps(scan_result, ensure_ascii=True),
            finished_at=utcnow(),
        )
        db.add(scan)
        if status_value == "approved":
            storage_failure_reason = "approval_move_failed"
            try:
                moved = private_storage.approve(release.storage_key)
            except Exception as exc:
                moved = False
                storage_failure_reason = type(exc).__name__
            if not moved:
                scan.status = "inconclusive"
                scan.scanner_results = json.dumps(
                    {"status": "inconclusive", "results": {"storage_error": storage_failure_reason}}
                )
                status_value = "inconclusive"
        release.scan_status = status_value
        owner_id = db.scalar(select(Content.owner_id).where(Content.id == release.content_id))
        if owner_id:
            db.add(
                Notification(
                    user_id=owner_id,
                    message=f"Security analysis for release {release.version}: {status_value}",
                )
            )
        db.commit()


@router.post("/contents/{content_id}/submit")
def submit_content(
    content_id: int,
    user: User = Depends(csrf_protected),
    db: Session = Depends(get_db),
):
    content = db.get(Content, content_id)
    if content is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Content not found")
    if content.owner_id != user.id or user.role != "developer":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Only the content owner can submit it")
    if content.status not in {"draft", "rejected"}:
        raise HTTPException(status.HTTP_409_CONFLICT, "Content cannot be submitted in its current state")
    approved_files = db.scalar(
        select(func.count(ReleaseFile.id)).where(
            ReleaseFile.content_id == content.id,
            ReleaseFile.scan_status == "approved",
            ReleaseFile.review_status.in_(["pending", "approved"]),
        )
    ) or 0
    if approved_files == 0:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "At least one security-approved release is required before publication review",
        )
    content.status = "pending"
    content.moderation_note = ""
    content.updated_at = utcnow()
    db.add(
        AuditLog(
            actor_id=user.id,
            action="content.submitted",
            target_type="content",
            target_id=str(content.id),
        )
    )
    db.commit()
    return {"id": content.id, "status": content.status}


@router.post("/contents/{content_id}/comments", status_code=status.HTTP_201_CREATED)
def add_comment(
    content_id: int,
    payload: CommentInput,
    user: User = Depends(csrf_protected),
    db: Session = Depends(get_db),
):
    content = db.get(Content, content_id)
    if content is None or content.status != "published":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Content not found")
    if payload.parent_id is not None:
        parent = db.get(Comment, payload.parent_id)
        if parent is None or parent.content_id != content_id or parent.hidden:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Reply target is invalid")
    comment = Comment(
        content_id=content_id,
        user_id=user.id,
        parent_id=payload.parent_id,
        body=payload.body.strip(),
    )
    db.add(comment)
    recipients = {content.owner_id}
    if payload.parent_id is not None:
        recipients.add(parent.user_id)
    for recipient_id in recipients - {user.id}:
        db.add(
            Notification(
                user_id=recipient_id,
                message=f"New community activity on '{content.name}'.",
            )
        )
    db.commit()
    return {"id": comment.id, "body": comment.body, "created_at": comment.created_at}


@router.get("/contents/{content_id}/comments")
def list_comments(content_id: int, db: Session = Depends(get_db)):
    content = db.get(Content, content_id)
    if content is None or content.status != "published":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Content not found")
    rows = db.execute(
        select(Comment, User.username)
        .join(User, User.id == Comment.user_id)
        .where(Comment.content_id == content_id, Comment.hidden.is_(False))
        .order_by(Comment.created_at.asc())
        .limit(200)
    ).all()
    return [
        {
            "id": comment.id,
            "parent_id": comment.parent_id,
            "username": username,
            "body": comment.body,
            "created_at": comment.created_at,
        }
        for comment, username in rows
    ]


@router.put("/contents/{content_id}/rating")
def rate_content(
    content_id: int,
    payload: RatingInput,
    user: User = Depends(csrf_protected),
    db: Session = Depends(get_db),
):
    content = db.get(Content, content_id)
    if content is None or content.status != "published":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Content not found")
    if content.owner_id == user.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Developers cannot rate their own content")
    rating = db.scalar(
        select(Rating).where(Rating.content_id == content_id, Rating.user_id == user.id)
    )
    if rating:
        rating.score = payload.score
    else:
        db.add(Rating(content_id=content_id, user_id=user.id, score=payload.score))
    db.commit()
    return {"saved": True, "score": payload.score}


@router.put("/contents/{content_id}/favorite")
def toggle_favorite(
    content_id: int,
    user: User = Depends(csrf_protected),
    db: Session = Depends(get_db),
):
    content = db.get(Content, content_id)
    if content is None or content.status != "published":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Content not found")
    favorite = db.scalar(
        select(Favorite).where(Favorite.content_id == content_id, Favorite.user_id == user.id)
    )
    if favorite:
        db.delete(favorite)
        saved = False
    else:
        db.add(Favorite(content_id=content_id, user_id=user.id))
        saved = True
    db.commit()
    return {"saved": saved}


@router.post("/reports", status_code=status.HTTP_201_CREATED)
def create_report(
    payload: ReportInput,
    user: User = Depends(csrf_protected),
    db: Session = Depends(get_db),
):
    if (payload.content_id is None) == (payload.comment_id is None):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Report exactly one content or comment")
    if payload.content_id is not None:
        target = db.get(Content, payload.content_id)
        if target is None or target.status != "published":
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Content not found")
        duplicate = db.scalar(
            select(Report.id).where(
                Report.reporter_id == user.id,
                Report.content_id == payload.content_id,
                Report.status.in_(["open", "reviewing"]),
            )
        )
    else:
        comment = db.get(Comment, payload.comment_id)
        if comment is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Comment not found")
        duplicate = db.scalar(
            select(Report.id).where(
                Report.reporter_id == user.id,
                Report.comment_id == payload.comment_id,
                Report.status.in_(["open", "reviewing"]),
            )
        )
    if duplicate:
        raise HTTPException(status.HTTP_409_CONFLICT, "An active report already exists")
    report = Report(
        reporter_id=user.id,
        content_id=payload.content_id,
        comment_id=payload.comment_id,
        reason=payload.reason.strip(),
        details=payload.details.strip(),
    )
    db.add(report)
    db.commit()
    return {"id": report.id, "status": report.status}


@router.get("/files/{file_id}/download")
def download_file(
    file_id: int,
    request_user: tuple[User | None, UserSession | None] = Depends(
        optional_user
    ),
    db: Session = Depends(get_db),
):
    file = db.get(ReleaseFile, file_id)
    if (
        file is None
        or file.file_type != "archive"
        or         file.scan_status != "approved"
        or file.review_status != "approved"
        or file.content.status != "published"
    ):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Download not available")
    data = private_storage.read_approved(file.storage_key)
    if data is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Download not available")
    user = request_user[0]
    db.add(DownloadEvent(file_id=file.id, user_id=user.id if user else None))
    db.commit()
    return StreamingResponse(
        io.BytesIO(data),
        media_type="application/octet-stream",
        headers={
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "private, no-store",
            "Content-Disposition": f"attachment; filename*=UTF-8''{quote(file.original_name, safe='')}",
        },
    )


@router.get("/images/{image_id}")
def get_content_image(image_id: int, db: Session = Depends(get_db)):
    image = db.get(ReleaseFile, image_id)
    if (
        image is None
        or image.file_type != "image"
        or image.scan_status != "approved"
        or image.review_status != "approved"
        or image.content.status != "published"
    ):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Image not available")
    data = private_storage.read_approved(image.storage_key)
    if data is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Image not available")
    return StreamingResponse(
        io.BytesIO(data),
        media_type="image/png",
        headers={
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'none'; sandbox",
            "Cross-Origin-Resource-Policy": "same-origin",
            "Cache-Control": "public, max-age=3600",
        },
    )


@router.get("/account/downloads")
def download_history(user: User = Depends(current_user), db: Session = Depends(get_db)):
    events = db.execute(
        select(DownloadEvent, ReleaseFile, Content)
        .join(ReleaseFile, ReleaseFile.id == DownloadEvent.file_id)
        .join(Content, Content.id == ReleaseFile.content_id)
        .where(DownloadEvent.user_id == user.id)
        .order_by(DownloadEvent.created_at.desc())
        .limit(100)
    ).all()
    return [
        {
            "content": content.name,
            "version": release.version,
            "downloaded_at": event.created_at,
        }
        for event, release, content in events
    ]


@router.get("/account/favorites")
def favorites(user: User = Depends(current_user), db: Session = Depends(get_db)):
    items = db.scalars(
        select(Content)
        .join(Favorite, Favorite.content_id == Content.id)
        .where(Favorite.user_id == user.id, Content.status == "published")
        .order_by(Favorite.created_at.desc())
    ).all()
    return [_content_data(content, db) for content in items]


@router.get("/account/notifications")
def notifications(user: User = Depends(current_user), db: Session = Depends(get_db)):
    return [
        {"id": item.id, "message": item.message, "read": item.read, "created_at": item.created_at}
        for item in db.scalars(
            select(Notification)
            .where(Notification.user_id == user.id)
            .order_by(Notification.created_at.desc())
            .limit(100)
        ).all()
    ]


@router.post("/account/notifications/{notification_id}/read")
def mark_notification_read(
    notification_id: int,
    user: User = Depends(csrf_protected),
    db: Session = Depends(get_db),
):
    item = db.get(Notification, notification_id)
    if item is None or item.user_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Notification not found")
    item.read = True
    db.commit()
    return {"read": True}
