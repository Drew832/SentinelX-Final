"""AI security chat endpoint."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.db.session import get_db
from app.models.user import User
from app.schemas.cve import ChatRequest, ChatResponse
from app.services.ai_service import answer_question

router = APIRouter(prefix="/ai", tags=["ai"])


@router.post("/chat", response_model=ChatResponse)
async def chat(
    payload: ChatRequest,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> ChatResponse:
    return await answer_question(db, payload)
