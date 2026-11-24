from __future__ import annotations

import json

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.content_routes import process_security_scan
from app.database import get_db
from app.dependencies import require_roles
from app.models import (
    AuditLog,
    Comment,
    Content,
    DownloadEvent,
    Notification,
    Report,
    ReleaseFile,
    SecurityScan,
    User,
    UserSession,
)
from app.storage import private_storage
from app.schemas import (
    AdminReviewInput,
    IdentityReviewInput,
    ReportReviewInput,
    ReleaseReviewInput,
    ScanReviewInput,
    UserRoleInput,
)

router = APIRouter(prefix="/api/admin", tags=["administration"])


@router.get("/overview")
def overview(
    _: User = Depends(require_roles("admin", "moderator")),
    db: Session = Depends(get_db),
):
    return {
        "users": db.scalar(select(func.count(User.id))) or 0,
        "developers": db.scalar(select(func.count(User.id)).where(User.role == "developer")) or 0,
        "contents_pending": db.scalar(
            select(func.count(Content.id)).where(Content.status == "pending")
        )
        or 0,
        "reports_open": db.scalar(
            select(func.count(Report.id)).where(Report.status.in_(["open", "reviewing"]))
        )
        or 0,
        "files_quarantined": db.scalar(
            select(func.count(ReleaseFile.id)).where(
                ReleaseFile.scan_status.in_(["suspicious", "rejected", "quarantined", "inconclusive"])
            )
        )
        or 0,
        "downloads": db.scalar(select(func.count(DownloadEvent.id))) or 0,
    }


@router.get("/contents")
def moderation_queue(
    _: User = Depends(require_roles("admin", "moderator")),
    db: Session = Depends(get_db),
):
    items = db.scalars(
        select(Content)
        .where(Content.status == "pending")
        .order_by(Content.created_at.asc())
        .limit(200)
    ).all()
    return [
        {
            "id": item.id,
            "name": item.name,
            "slug": item.slug,
            "owner": item.owner.username,
            "category": item.category,
            "edition": item.edition,
            "created_at": item.created_at,
            "files": [
                {
                    "id": file.id,
                    "name": file.original_name,
                    "file_type": file.file_type,
                    "version": file.version,
                    "scan_status": file.scan_status,
                    "sha256": file.sha256,
                }
                for file in item.files
            ],
        }
        for item in items
    ]


@router.post("/contents/{content_id}/review")
def review_content(
    content_id: int,
    payload: AdminReviewInput,
    user: User = Depends(require_roles("admin", "moderator")),
    db: Session = Depends(get_db),
):
    content = db.get(Content, content_id)
    if content is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Content not found")
    if payload.status == "published":
        approved = db.scalar(
            select(func.count(ReleaseFile.id)).where(
                ReleaseFile.content_id == content_id,
                ReleaseFile.file_type == "archive",
                ReleaseFile.scan_status == "approved",
                ReleaseFile.review_status.in_(["pending", "approved"]),
            )
        ) or 0
        if approved == 0:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "Publication requires at least one security-approved release",
            )
        if content.status != "pending":
            raise HTTPException(status.HTTP_409_CONFLICT, "Only pending content can be approved")
        approved_files = db.scalars(
            select(ReleaseFile).where(
                ReleaseFile.content_id == content_id,
                ReleaseFile.file_type == "archive",
                ReleaseFile.scan_status == "approved",
                ReleaseFile.review_status == "pending",
            )
        ).all()
        if not any(
            private_storage.approved_exists(release.storage_key)
            for release in approved_files
        ):
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "No approved release is present in private storage",
            )
        for release in approved_files:
            if private_storage.approved_exists(release.storage_key):
                release.review_status = "approved"
    elif payload.status == "rejected" and content.status != "pending":
        raise HTTPException(status.HTTP_409_CONFLICT, "Only pending content can be rejected")
    elif payload.status == "suspended" and content.status != "published":
        raise HTTPException(status.HTTP_409_CONFLICT, "Only published content can be suspended")
    content.status = payload.status
    content.moderation_note = payload.note.strip()
    db.add(
        AuditLog(
            actor_id=user.id,
            action=f"content.{payload.status}",
            target_type="content",
            target_id=str(content.id),
            details=payload.note.strip(),
        )
    )
    db.add(
        Notification(
            user_id=content.owner_id,
            message=f"Your content '{content.name}' was {payload.status}.",
        )
    )
    db.commit()
    return {"id": content.id, "status": content.status}


@router.get("/reports")
def list_reports(
    state: str = Query(default="open", pattern="^(open|reviewing|resolved|dismissed|all)$"),
    _: User = Depends(require_roles("admin", "moderator")),
    db: Session = Depends(get_db),
):
    query = select(Report).order_by(Report.created_at.asc()).limit(300)
    if state != "all":
        query = query.where(Report.status == state)
    rows = db.scalars(query).all()
    return [
        {
            "id": report.id,
            "reporter": report.reporter_id,
            "content_id": report.content_id,
            "content_name": report.content.name if report.content_id else None,
            "comment_id": report.comment_id,
            "reason": report.reason,
            "details": report.details,
            "status": report.status,
            "created_at": report.created_at,
        }
        for report in rows
    ]


@router.get("/files/pending-review")
def releases_pending_review(
    _: User = Depends(require_roles("admin", "moderator")),
    db: Session = Depends(get_db),
):
    files = db.scalars(
        select(ReleaseFile)
        .join(Content, Content.id == ReleaseFile.content_id)
        .where(
            ReleaseFile.scan_status == "approved",
            ReleaseFile.review_status == "pending",
            Content.status.in_(["published", "pending"]),
        )
        .order_by(ReleaseFile.created_at.asc())
        .limit(200)
    ).all()
    return [
        {
            "id": item.id,
            "content_id": item.content_id,
            "content_name": item.content.name,
            "owner": item.content.owner.username,
            "name": item.original_name,
            "version": item.version,
            "sha256": item.sha256,
            "size_bytes": item.size_bytes,
            "file_type": item.file_type,
        }
        for item in files
    ]


@router.post("/files/{file_id}/review")
def review_release(
    file_id: int,
    payload: ReleaseReviewInput,
    user: User = Depends(require_roles("admin", "moderator")),
    db: Session = Depends(get_db),
):
    release = db.get(ReleaseFile, file_id)
    if release is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Release file not found")
    if payload.status == "approved":
        if release.scan_status != "approved":
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "A release must pass the MSE before human publication approval",
            )
        content = db.get(Content, release.content_id)
        if content is None or content.status not in {"pending", "published"}:
            raise HTTPException(status.HTTP_409_CONFLICT, "Content is not eligible for release review")
        if not private_storage.approved_exists(release.storage_key):
            if not private_storage.approve(release.storage_key):
                raise HTTPException(status.HTTP_409_CONFLICT, "Approved file is missing from private storage")
        if not private_storage.approved_exists(release.storage_key):
            raise HTTPException(status.HTTP_409_CONFLICT, "Approved file is missing from private storage")
        release.review_status = "approved"
    else:
        private_storage.quarantine(release.storage_key)
        release.review_status = "rejected"
    db.add(
        AuditLog(
            actor_id=user.id,
            action=f"release.{payload.status}",
            target_type="release_file",
            target_id=str(release.id),
            details=payload.note.strip(),
        )
    )
    db.commit()
    return {"id": release.id, "review_status": release.review_status}


@router.post("/reports/{report_id}/review")
def review_report(
    report_id: int,
    payload: ReportReviewInput,
    user: User = Depends(require_roles("admin", "moderator")),
    db: Session = Depends(get_db),
):
    report = db.get(Report, report_id)
    if report is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Report not found")
    if payload.confirmed_violation and payload.status != "resolved":
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "A confirmed violation must be resolved",
        )
    report.status = payload.status
    report.resolution = payload.resolution.strip()
    report.confirmed_violation = payload.confirmed_violation
    report.resolved_by = user.id if payload.status in {"resolved", "dismissed"} else None
    if report.comment_id and payload.confirmed_violation:
        comment = db.get(Comment, report.comment_id)
        if comment:
            comment.hidden = True
    db.add(
        AuditLog(
            actor_id=user.id,
            action=f"report.{payload.status}",
            target_type="report",
            target_id=str(report.id),
            details=f"confirmed_violation={payload.confirmed_violation}; {payload.resolution.strip()}",
        )
    )
    db.commit()
    return {"id": report.id, "status": report.status}


@router.get("/security/scans")
def scan_history(
    state: str | None = Query(default=None, pattern="^(queued|scanning|approved|suspicious|rejected|quarantined|inconclusive)$"),
    _: User = Depends(require_roles("admin", "moderator")),
    db: Session = Depends(get_db),
):
    query = select(SecurityScan).order_by(SecurityScan.started_at.desc()).limit(300)
    if state:
        query = query.where(SecurityScan.status == state)
    return [
        {
            "id": scan.id,
            "file_id": scan.file_id,
            "sha256": scan.sha256,
            "status": scan.status,
            "results": json.loads(scan.scanner_results),
            "started_at": scan.started_at,
            "finished_at": scan.finished_at,
            "review_note": scan.review_note,
        }
        for scan in db.scalars(query).all()
    ]


@router.post("/security/files/{file_id}/rescan", status_code=status.HTTP_202_ACCEPTED)
def rescan_file(
    file_id: int,
    background_tasks: BackgroundTasks,
    user: User = Depends(require_roles("admin")),
    db: Session = Depends(get_db),
):
    release = db.get(ReleaseFile, file_id)
    if release is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "File not found")
    if release.scan_status == "scanning":
        raise HTTPException(status.HTTP_409_CONFLICT, "File is already being scanned")
    if not private_storage.approved_exists(release.storage_key):
        with private_storage.scan_quarantine(release.storage_key) as quarantined_path:
            quarantined_exists = quarantined_path is not None
    else:
        quarantined_exists = True
    if not quarantined_exists:
        raise HTTPException(status.HTTP_409_CONFLICT, "Private file is missing; scan cannot run")
    if private_storage.approved_exists(release.storage_key):
        private_storage.quarantine(release.storage_key)
    release.scan_status = "queued"
    db.commit()
    background_tasks.add_task(process_security_scan, release.id)
    db.add(
        AuditLog(
            actor_id=user.id,
            action="security.scan_requested",
            target_type="release_file",
            target_id=str(release.id),
        )
    )
    db.commit()
    return {"id": release.id, "scan_status": release.scan_status}


@router.post("/security/scans/{scan_id}/review")
def review_scan(
    scan_id: int,
    payload: ScanReviewInput,
    user: User = Depends(require_roles("admin")),
    db: Session = Depends(get_db),
):
    scan = db.get(SecurityScan, scan_id)
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found")
    release = db.get(ReleaseFile, scan.file_id)
    if release is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Release file not found")
    latest_scan_id = db.scalar(
        select(SecurityScan.id)
        .where(SecurityScan.file_id == release.id)
        .order_by(SecurityScan.started_at.desc(), SecurityScan.id.desc())
        .limit(1)
    )
    if latest_scan_id != scan.id:
        raise HTTPException(status.HTTP_409_CONFLICT, "Only the latest scan can be reviewed")
    results = json.loads(scan.scanner_results)
    scanner_results = results.get("results", {})
    if payload.decision == "approve_false_positive":
        clamav = scanner_results.get("clamav", {})
        yara = scanner_results.get("yara", {})
        structure = scanner_results.get("structure", {})
        virustotal = scanner_results.get("virustotal", {})
        if (
            scan.status != "suspicious"
            or release.scan_status != "suspicious"
            or clamav.get("status") != "clean"
            or yara.get("status") != "suspicious"
            or structure.get("status") != "clean"
            or virustotal.get("status") not in {"clean", None}
            or "scanner_errors" in scanner_results
        ):
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "Only a YARA-only suspicion with clean structural and antivirus results can be reviewed as a false positive",
            )
        with private_storage.scan_quarantine(release.storage_key) as quarantined_path:
            quarantined_exists = quarantined_path is not None
        if not quarantined_exists:
            raise HTTPException(status.HTTP_409_CONFLICT, "Quarantined file is missing")
        if not private_storage.approve(release.storage_key):
            raise HTTPException(status.HTTP_409_CONFLICT, "Could not move quarantined file to private storage")
        release.scan_status = "approved"
        scan.reviewed_by = user.id
        scan.review_note = payload.note.strip()
        db.add(
            AuditLog(
                actor_id=user.id,
                action="security.false_positive_approved",
                target_type="security_scan",
                target_id=str(scan.id),
                details=payload.note.strip(),
            )
        )
        db.commit()
        return {"scan_id": scan.id, "file_status": release.scan_status}
    release.scan_status = "rejected"
    scan.reviewed_by = user.id
    scan.review_note = payload.note.strip()
    db.add(
        AuditLog(
            actor_id=user.id,
            action="security.scan_rejected",
            target_type="security_scan",
            target_id=str(scan.id),
            details=payload.note.strip(),
        )
    )
    db.commit()
    return {"scan_id": scan.id, "file_status": "rejected"}


@router.get("/users")
def list_users(
    q: str | None = Query(default=None, max_length=120),
    _: User = Depends(require_roles("admin")),
    db: Session = Depends(get_db),
):
    query = select(User).order_by(User.created_at.desc()).limit(200)
    if q:
        query = select(User).where(
            User.username.ilike(f"%{q}%") | User.email.ilike(f"%{q}%")
        ).order_by(User.created_at.desc()).limit(200)
    return [
        {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "active": user.active,
            "email_verified": user.email_verified,
            "created_at": user.created_at,
        }
        for user in db.scalars(query).all()
    ]


@router.patch("/users/{user_id}/role")
def update_user_role(
    user_id: int,
    payload: UserRoleInput,
    admin: User = Depends(require_roles("admin")),
    db: Session = Depends(get_db),
):
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    if target.id == admin.id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Administrators cannot change their own role")
    if payload.role == "developer" and target.profile is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Create a developer profile before granting this role")
    previous_role = target.role
    target.role = payload.role
    db.add(
        AuditLog(
            actor_id=admin.id,
            action="user.role_changed",
            target_type="user",
            target_id=str(target.id),
            details=f"{previous_role} -> {payload.role}",
        )
    )
    db.commit()
    return {"id": target.id, "role": target.role}


@router.post("/users/{user_id}/deactivate")
def deactivate_user(
    user_id: int,
    admin: User = Depends(require_roles("admin")),
    db: Session = Depends(get_db),
):
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    if target.id == admin.id or target.role == "admin":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Cannot deactivate this administrator")
    target.active = False
    db.query(UserSession).filter(UserSession.user_id == target.id).delete()
    db.query(Content).filter(
        Content.owner_id == target.id,
        Content.status == "published",
    ).update({Content.status: "suspended"}, synchronize_session=False)
    db.add(
        AuditLog(
            actor_id=admin.id,
            action="user.deactivated",
            target_type="user",
            target_id=str(target.id),
        )
    )
    db.commit()
    return {"id": target.id, "active": False}


@router.patch("/developers/{user_id}/identity")
def review_developer_identity(
    user_id: int,
    payload: IdentityReviewInput,
    admin: User = Depends(require_roles("admin")),
    db: Session = Depends(get_db),
):
    developer = db.get(User, user_id)
    if developer is None or developer.profile is None or developer.role != "developer":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Developer profile not found")
    developer.profile.identity_verified = payload.verified
    db.add(
        AuditLog(
            actor_id=admin.id,
            action="developer.identity_reviewed",
            target_type="user",
            target_id=str(developer.id),
            details=f"verified={payload.verified}; {payload.note.strip()}",
        )
    )
    db.commit()
    return {"user_id": developer.id, "identity_verified": developer.profile.identity_verified}


@router.get("/audit")
def audit_log(
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=50, ge=1, le=100),
    _: User = Depends(require_roles("admin")),
    db: Session = Depends(get_db),
):
    records = db.scalars(
        select(AuditLog)
        .order_by(AuditLog.created_at.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
    ).all()
    return [
        {
            "id": record.id,
            "actor_id": record.actor_id,
            "action": record.action,
            "target_type": record.target_type,
            "target_id": record.target_id,
            "details": record.details,
            "created_at": record.created_at,
        }
        for record in records
    ]


@router.get("/developers/{user_id}/trust")
def developer_trust(
    user_id: int,
    _: User = Depends(require_roles("admin", "moderator")),
    db: Session = Depends(get_db),
):
    from app.content_routes import trust_score

    user = db.get(User, user_id)
    if user is None or user.profile is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Developer not found")
    return {"username": user.username, **trust_score(user, db)}
