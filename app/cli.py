from __future__ import annotations

import argparse
import getpass

from sqlalchemy import func, select

from app.database import SessionLocal
from app.models import AuditLog, User
from app.security import hash_password, validate_secret_configuration


def create_admin(email: str, username: str) -> None:
    validate_secret_configuration()
    password = getpass.getpass("Administrator password (12+ characters): ")
    if len(password) < 12:
        raise SystemExit("Password must contain at least 12 characters.")
    with SessionLocal() as db:
        existing = db.scalar(
            select(User.id).where(
                (func.lower(User.email) == email.lower())
                | (func.lower(User.username) == username.lower())
            )
        )
        if existing:
            raise SystemExit("Email or username is already in use.")
        admin = User(
            email=email.lower(),
            username=username,
            password_hash=hash_password(password),
            role="admin",
            email_verified=True,
        )
        db.add(admin)
        db.flush()
        db.add(
            AuditLog(
                actor_id=admin.id,
                action="admin.bootstrap",
                target_type="user",
                target_id=str(admin.id),
            )
        )
        db.commit()
    print(f"Administrator {username} created.")


def main() -> None:
    parser = argparse.ArgumentParser(description="ModStation maintenance commands")
    commands = parser.add_subparsers(dest="command", required=True)
    admin = commands.add_parser("create-admin", help="Create the first administrator")
    admin.add_argument("--email", required=True)
    admin.add_argument("--username", required=True)
    args = parser.parse_args()
    if args.command == "create-admin":
        create_admin(args.email, args.username)


if __name__ == "__main__":
    main()
