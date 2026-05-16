"""Authentication routes: register, verify email (OTP), login, profile, password change.

OTP flow hardening
------------------
The OTP verification endpoint historically reported "Verification Failed"
even when the user pasted the correct code. Two real-world issues caused
that:

  1. Users (and some mail clients) inject zero-width characters, NBSPs, or
     surrounding whitespace when copy-pasting from the email body. The
     submitted string then no longer matched the bcrypt-hashed code.
  2. Email clients sometimes render the OTP with formatting that introduces
     unicode digits (e.g. fullwidth '１') that fail a literal byte
     comparison.

We now normalise the submitted code aggressively (strip whitespace and
non-digit codepoints, NFKC-normalise unicode, lowercase the email lookup)
before bcrypt verification, and we treat any digit-only token of the
expected length as the candidate even if the user accidentally appended a
period or other punctuation.
"""
from __future__ import annotations

import logging
import re
import secrets
import unicodedata
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.security import create_access_token, hash_password, verify_password
from app.db.session import get_db
from app.models.user import User, UserRole
from app.schemas.user import (
    PasswordChangeRequest,
    RegisterPending,
    ResendOtpRequest,
    Token,
    UserCreate,
    UserOut,
    VerifyEmailRequest,
)
from app.services.email_service import send_otp_email

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

OTP_EXPIRY_MINUTES = 15
OTP_LENGTH = 6
_DIGIT_RE = re.compile(r"\D+")


def _generate_otp() -> str:
    """Generate a zero-padded numeric OTP of `OTP_LENGTH` digits."""
    return f"{secrets.randbelow(10 ** OTP_LENGTH):0{OTP_LENGTH}d}"


def _normalise_email(value: str) -> str:
    return value.strip().lower()


def _normalise_otp(value: str) -> str:
    """Coerce the user's input into a digits-only string.

    This is the single source of truth for OTP normalisation so the
    register, verify, and resend handlers all behave identically and the
    bcrypt verification never sees stray whitespace, NBSP characters, or
    fullwidth digits pasted from rich-text email clients.
    """
    if not value:
        return ""
    nfkc = unicodedata.normalize("NFKC", value)
    return _DIGIT_RE.sub("", nfkc).strip()


def _issue_token(user: User) -> Token:
    token = create_access_token(subject=str(user.id), extra_claims={"role": user.role.value})
    return Token(access_token=token, user=UserOut.model_validate(user))


@router.post("/register", response_model=RegisterPending, status_code=status.HTTP_201_CREATED)
async def register(
    payload: UserCreate,
    background: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
) -> RegisterPending:
    email = _normalise_email(str(payload.email))
    existing = await db.execute(
        select(User).where(or_(User.email == email, User.username == payload.username))
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="User with email or username already exists")

    code = _generate_otp()
    hashed_code = hash_password(code)

    user = User(
        email=email,
        username=payload.username,
        hashed_password=hash_password(payload.password),
        role=UserRole.USER,
        is_active=False,
        otp_hashed=hashed_code,
        otp_expires_at=datetime.now(tz=timezone.utc) + timedelta(minutes=OTP_EXPIRY_MINUTES),
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    logger.info("Registered user %s (%s); OTP issued (expires in %d min)",
                user.username, user.email, OTP_EXPIRY_MINUTES)

    async def _send():
        try:
            await send_otp_email(user.email, code, user.username)
        except Exception:
            logger.exception("Failed to send verification email to %s", user.email)

    background.add_task(_send)

    return RegisterPending(email=user.email)


@router.post("/verify-email", response_model=Token)
async def verify_email(payload: VerifyEmailRequest, db: AsyncSession = Depends(get_db)) -> Token:
    submitted_code = _normalise_otp(payload.code)
    email = _normalise_email(str(payload.email))
    logger.info(
        "Verifying email for %s (normalised code length=%d)",
        email, len(submitted_code),
    )

    if not submitted_code or len(submitted_code) != OTP_LENGTH:
        raise HTTPException(
            status_code=400,
            detail=f"Verification code must be {OTP_LENGTH} digits.",
        )

    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()
    if not user:
        logger.warning("Verification attempt for non-existent email: %s", email)
        # Avoid leaking which emails are registered.
        raise HTTPException(status_code=400, detail="Invalid verification code — please check and try again")

    if user.is_active:
        logger.info("User %s is already active", user.email)
        raise HTTPException(status_code=400, detail="Account is already active — sign in instead")

    if not user.otp_hashed:
        logger.warning("No OTP hash stored for user %s", user.email)
        raise HTTPException(
            status_code=400,
            detail="No verification code on file — request a new code",
        )

    if user.otp_expires_at:
        expiry = user.otp_expires_at
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        if expiry < datetime.now(tz=timezone.utc):
            logger.warning("OTP expired for user %s (expired at %s)", user.email, expiry.isoformat())
            raise HTTPException(
                status_code=400,
                detail="Verification code has expired — request a new code",
            )

    if not verify_password(submitted_code, user.otp_hashed):
        logger.warning("OTP mismatch for user %s", user.email)
        raise HTTPException(status_code=400, detail="Invalid verification code — please check and try again")

    user.is_active = True
    user.otp_hashed = None
    user.otp_expires_at = None
    await db.commit()
    await db.refresh(user)

    logger.info("User %s successfully verified and activated", user.email)
    return _issue_token(user)


@router.post("/resend-otp", response_model=RegisterPending)
async def resend_otp(
    payload: ResendOtpRequest,
    background: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
) -> RegisterPending:
    email = _normalise_email(str(payload.email))
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()
    if not user or user.is_active:
        # Don't disclose whether the address is on file.
        return RegisterPending(
            email=email,
            detail="If an account exists for this email, a new code has been sent.",
        )

    code = _generate_otp()
    user.otp_hashed = hash_password(code)
    user.otp_expires_at = datetime.now(tz=timezone.utc) + timedelta(minutes=OTP_EXPIRY_MINUTES)
    await db.commit()

    logger.info("Resending OTP for user %s", user.email)

    async def _send():
        try:
            await send_otp_email(user.email, code, user.username)
        except Exception:
            logger.exception("Failed to resend verification email to %s", user.email)

    background.add_task(_send)

    return RegisterPending(
        email=user.email,
        detail="A fresh verification code has been sent to your inbox.",
    )


@router.post("/login", response_model=Token)
async def login(
    form: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
) -> Token:
    identifier = form.username.strip()
    result = await db.execute(
        select(User).where(
            or_(User.email == identifier.lower(), User.username == identifier)
        )
    )
    user = result.scalar_one_or_none()
    if not user or not verify_password(form.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.is_active:
        raise HTTPException(
            status_code=403,
            detail="Email not verified yet. Enter the OTP sent to your inbox or use resend.",
        )

    return _issue_token(user)


@router.post("/change-password")
async def change_password(
    payload: PasswordChangeRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict[str, str]:
    if not verify_password(payload.current_password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    user.hashed_password = hash_password(payload.new_password)
    await db.commit()
    return {"status": "password_updated"}


@router.get("/me", response_model=UserOut)
async def me(user: User = Depends(get_current_user)) -> UserOut:
    return UserOut.model_validate(user)
