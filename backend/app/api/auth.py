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

In addition (v4):

  * OTPs expire after 10 minutes, not 15.
  * Resend is rate-limited server-side (``OTP_RESEND_COOLDOWN_SECONDS``)
    so an automated client cannot loop and burn through verification
    codes.
  * Verify is rate-limited per account: after ``OTP_MAX_ATTEMPTS`` wrong
    submissions the active OTP is invalidated and the user is told to
    request a fresh one. This protects against brute-force enumeration
    of a 6-digit code.
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

OTP_EXPIRY_MINUTES = 10
OTP_LENGTH = 6
OTP_MAX_ATTEMPTS = 5
OTP_RESEND_COOLDOWN_SECONDS = 30
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


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _otp_payload(user: User, code: str) -> None:
    """Stamp a fresh OTP onto a user row (caller commits)."""
    user.otp_hashed = hash_password(code)
    user.otp_expires_at = _now() + timedelta(minutes=OTP_EXPIRY_MINUTES)
    user.otp_attempts = 0
    user.otp_last_sent_at = _now()


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

    user = User(
        email=email,
        username=payload.username,
        hashed_password=hash_password(payload.password),
        role=UserRole.USER,
        is_active=False,
    )
    _otp_payload(user, code)
    db.add(user)
    await db.commit()
    await db.refresh(user)

    logger.info(
        "Registered user %s (%s); OTP issued (expires in %d min)",
        user.username, user.email, OTP_EXPIRY_MINUTES,
    )

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

    if user.otp_expires_at and _aware(user.otp_expires_at) < _now():
        logger.warning("OTP expired for user %s", user.email)
        raise HTTPException(
            status_code=400,
            detail="This verification code has expired. Please request a new code.",
        )

    if (user.otp_attempts or 0) >= OTP_MAX_ATTEMPTS:
        # Invalidate the active OTP so a brute-forcer can't keep poking.
        user.otp_hashed = None
        user.otp_expires_at = None
        await db.commit()
        logger.warning("OTP attempt lockout triggered for %s", user.email)
        raise HTTPException(
            status_code=429,
            detail="Too many incorrect attempts. Request a new code to continue.",
        )

    if not verify_password(submitted_code, user.otp_hashed):
        user.otp_attempts = (user.otp_attempts or 0) + 1
        await db.commit()
        remaining = max(OTP_MAX_ATTEMPTS - user.otp_attempts, 0)
        logger.warning("OTP mismatch for user %s (attempts=%s)", user.email, user.otp_attempts)
        detail = "Invalid verification code — please check and try again"
        if remaining <= 2:
            detail += f" ({remaining} attempt{'s' if remaining != 1 else ''} remaining)"
        raise HTTPException(status_code=400, detail=detail)

    user.is_active = True
    user.otp_hashed = None
    user.otp_expires_at = None
    user.otp_attempts = 0
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

    # Server-side cooldown: spam protection without confusing legitimate
    # users who just hit "Resend" a second time after the network round-trip
    # didn't show a toast.
    if user.otp_last_sent_at:
        elapsed = (_now() - _aware(user.otp_last_sent_at)).total_seconds()
        if elapsed < OTP_RESEND_COOLDOWN_SECONDS:
            wait = int(OTP_RESEND_COOLDOWN_SECONDS - elapsed)
            raise HTTPException(
                status_code=429,
                detail=(
                    f"Please wait {wait} more second{'s' if wait != 1 else ''} "
                    "before requesting another code."
                ),
            )

    code = _generate_otp()
    _otp_payload(user, code)
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
