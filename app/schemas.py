from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, HttpUrl, StringConstraints

Username = Annotated[str, StringConstraints(min_length=3, max_length=32, pattern=r"^[a-zA-Z0-9_]+$")]


class RegisterInput(BaseModel):
    email: EmailStr
    username: Username
    password: Annotated[str, Field(min_length=12, max_length=128)]


class LoginInput(BaseModel):
    email: EmailStr
    password: Annotated[str, Field(min_length=1, max_length=128)]


class TokenInput(BaseModel):
    token: Annotated[str, Field(min_length=32, max_length=200)]


class PasswordResetInput(TokenInput):
    password: Annotated[str, Field(min_length=12, max_length=128)]


class PasswordChangeInput(BaseModel):
    current_password: Annotated[str, Field(min_length=1, max_length=128)]
    new_password: Annotated[str, Field(min_length=12, max_length=128)]


class EmailInput(BaseModel):
    email: EmailStr


class DeveloperInput(BaseModel):
    display_name: Annotated[str, Field(min_length=2, max_length=80)]
    bio: Annotated[str, Field(max_length=1000)] = ""
    website: HttpUrl | None = None


class ContentInput(BaseModel):
    name: Annotated[str, Field(min_length=3, max_length=120)]
    description: Annotated[str, Field(min_length=30, max_length=5000)]
    category: Literal["mods", "maps", "resource-packs", "shaders", "addons"]
    edition: Literal["java", "bedrock", "both"]
    minecraft_version: Annotated[str, Field(min_length=1, max_length=64)]
    license: Annotated[str, Field(min_length=1, max_length=80)]
    dependencies: list[Annotated[str, Field(max_length=120)]] = Field(
        default_factory=list, max_length=30
    )
    credits: Annotated[str, Field(max_length=1000)] = ""
    changelog: Annotated[str, Field(max_length=2000)] = ""


class IdentityReviewInput(BaseModel):
    verified: bool
    note: Annotated[str, Field(min_length=8, max_length=500)]


class CommentInput(BaseModel):
    body: Annotated[str, Field(min_length=2, max_length=2000)]
    parent_id: int | None = None


class RatingInput(BaseModel):
    score: Annotated[int, Field(ge=1, le=5)]


class ReportInput(BaseModel):
    content_id: int | None = None
    comment_id: int | None = None
    reason: Annotated[str, Field(min_length=3, max_length=40)]
    details: Annotated[str, Field(max_length=1000)] = ""


class ProfileInput(BaseModel):
    display_name: Annotated[str, Field(min_length=2, max_length=80)]
    bio: Annotated[str, Field(max_length=1000)] = ""
    website: HttpUrl | None = None


class AdminReviewInput(BaseModel):
    status: Literal["published", "rejected", "suspended"]
    note: Annotated[str, Field(max_length=500)] = ""


class ReportReviewInput(BaseModel):
    status: Literal["reviewing", "resolved", "dismissed"]
    resolution: Annotated[str, Field(max_length=500)] = ""
    confirmed_violation: bool = False


class ScanReviewInput(BaseModel):
    decision: Literal["approve_false_positive", "reject"]
    note: Annotated[str, Field(min_length=8, max_length=500)]


class ReleaseReviewInput(BaseModel):
    status: Literal["approved", "rejected"]
    note: Annotated[str, Field(min_length=8, max_length=500)]


class UserRoleInput(BaseModel):
    role: Literal["user", "developer", "moderator"]


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    username: str
    role: str
    email_verified: bool
