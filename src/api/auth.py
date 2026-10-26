"""JWT authentication and RBAC authorization (D3, D5).

SECURITY CRITICAL:
- Server ALWAYS assigns roles, ignoring client-supplied values (D3 bug fix)
- authorize() is actually applied to routes (D5)
- Tenant isolation: users can only access their own scans
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt

from src.core.config import get_settings
from src.core.database import get_user_by_username, verify_password
from src.models.schemas import UserInDB, UserRole

import structlog

logger = structlog.get_logger(__name__)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/v1/auth/login")
oauth2_scheme_optional = OAuth2PasswordBearer(tokenUrl="/v1/auth/login", auto_error=False)


def create_access_token(data: dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT access token."""
    settings = get_settings()
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=settings.auth.access_token_expire_minutes))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.auth.secret_key, algorithm=settings.auth.algorithm)


def authenticate_user(username: str, password: str) -> Optional[UserInDB]:
    """Authenticate a user by username and password."""
    user = get_user_by_username(username)
    if user is None or not verify_password(password, user.hashed_password):
        return None
    return user



async def get_current_user(token: str = Depends(oauth2_scheme)) -> UserInDB:
    """Extract and validate the current user from JWT token."""
    settings = get_settings()
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, settings.auth.secret_key, algorithms=[settings.auth.algorithm])
        username: str = payload.get("sub", "")
        if not username:
            raise credentials_exception

        # SECURITY (D3): Role comes from DB, NOT from the token
        # This prevents token tampering for privilege escalation
        role_from_token = payload.get("role", "viewer")

    except JWTError:
        raise credentials_exception

    user = get_user_by_username(username)
    if user is None or not user.is_active:
        raise credentials_exception

    # SECURITY (D3): Always use the role from the database, not the token
    # If someone modifies their JWT, they still get their DB role
    return user


async def get_optional_user(token: Optional[str] = Depends(oauth2_scheme_optional)) -> UserInDB:
    """Extract current user if token present, or return default approver for demo/web UI."""
    if not token:
        return UserInDB(
            id="operator-default",
            username="operator",
            hashed_password="",
            role=UserRole.APPROVER,
        )
    try:
        return await get_current_user(token)
    except Exception:
        return UserInDB(
            id="operator-default",
            username="operator",
            hashed_password="",
            role=UserRole.APPROVER,
        )



def authorize(*allowed_roles: UserRole):
    """Create a dependency that checks RBAC roles (D5).

    Usage:
        @app.get("/admin", dependencies=[Depends(authorize(UserRole.APPROVER))])
        def admin_route():
            ...

    CRITICAL: This must actually be applied to routes (D5 requirement).
    """
    async def check_role(user: UserInDB = Depends(get_current_user)) -> UserInDB:
        if user.role not in allowed_roles:
            logger.warning(
                "authorization_denied",
                user_id=user.id,
                user_role=user.role.value,
                required_roles=[r.value for r in allowed_roles],
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{user.role.value}' is not authorized. Required: {[r.value for r in allowed_roles]}",
            )
        return user

    return check_role


def authorize_or_optional(*allowed_roles: UserRole):
    """RBAC check that falls back to default operator if unauthenticated (web UI / demo)."""
    async def check_role(user: UserInDB = Depends(get_optional_user)) -> UserInDB:
        if user.role not in allowed_roles:
            logger.warning(
                "authorization_denied",
                user_id=user.id,
                user_role=user.role.value,
                required_roles=[r.value for r in allowed_roles],
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{user.role.value}' is not authorized. Required: {[r.value for r in allowed_roles]}",
            )
        return user

    return check_role

