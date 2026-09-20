"""Integration tests for /history and /report Telegram commands."""

from unittest.mock import AsyncMock, MagicMock
from datetime import datetime, timezone
import pytest
from telegram import Chat, Message, Update, User as TgUser
from app.bot.handlers.history import history_handler
from app.bot.handlers.report import report_command
from app.db.models.scan import Scan
from app.db.models.user import User


def create_mock_update_and_context(user_id=12345, text="/history", args=None):
    """Helper to generate realistic Telegram Update and Context mock objects."""
    update = MagicMock(spec=Update)
    user = TgUser(id=user_id, is_bot=False, first_name="Bob", username="bob_hunter")
    chat = Chat(id=user_id, type="private")

    message = MagicMock(spec=Message)
    message.text = text
    message.chat = chat
    message.from_user = user

    reply_msg = MagicMock(spec=Message)
    reply_msg.edit_text = AsyncMock()
    reply_msg.delete = AsyncMock()
    message.reply_text = AsyncMock(return_value=reply_msg)
    message.reply_document = AsyncMock()

    update.effective_user = user
    update.effective_chat = chat
    update.effective_message = message

    context = MagicMock()
    context.args = args or []

    return update, context, message, reply_msg


@pytest.mark.asyncio
async def test_history_handler_empty(test_engine):
    """Verify history handler response when user has no prior scans."""
    update, context, message, _ = create_mock_update_and_context(user_id=999111, text="/history")

    await history_handler(update, context)

    assert message.reply_text.called
    c_args, c_kwargs = message.reply_text.call_args
    reply_str = c_args[0] if c_args else c_kwargs.get("text", "")
    assert "No scans found" in reply_str


@pytest.mark.asyncio
async def test_history_handler_with_scans(test_engine, db_session):
    """Verify history handler returns list of prior scans."""
    user = User(
        telegram_user_id=888222,
        username="soc_analyst",
        first_name="Analyst",
        created_at=datetime.now(timezone.utc),
        last_seen_at=datetime.now(timezone.utc),
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)

    scan = Scan(
        scan_uuid="SCAN-2026-HIST01",
        user_id=user.id,
        original_url="https://phish-target.test",
        normalized_url="https://phish-target.test",
        domain="phish-target.test",
        status="completed",
        risk_score=75.0,
        risk_level="HIGH",
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(scan)
    await db_session.commit()

    update, context, message, _ = create_mock_update_and_context(user_id=888222, text="/history")

    await history_handler(update, context)

    assert message.reply_text.called
    _, kwargs = message.reply_text.call_args
    history_text = kwargs.get("text", "")
    assert "YOUR RECENT SCANS" in history_text
    assert "phish-target.test" in history_text
    assert "SCAN-2026-HIST01" in history_text
    assert "75/100 (HIGH)" in history_text


@pytest.mark.asyncio
async def test_report_command_usage(test_engine):
    """Verify /report without arguments shows usage help."""
    update, context, message, _ = create_mock_update_and_context(user_id=123, text="/report", args=[])

    await report_command(update, context)

    assert message.reply_text.called
    c_args, c_kwargs = message.reply_text.call_args
    usage_str = c_args[0] if c_args else c_kwargs.get("text", "")
    assert "Usage:" in usage_str


@pytest.mark.asyncio
async def test_report_command_generates_document(test_engine, db_session):
    """Verify /report generates and sends PDF document for valid scan ID."""
    scan = Scan(
        scan_uuid="SCAN-2026-PDF001",
        original_url="https://invoice-download.test",
        normalized_url="https://invoice-download.test",
        domain="invoice-download.test",
        status="completed",
        risk_score=60.0,
        risk_level="MODERATE",
        confidence_score=80.0,
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(scan)
    await db_session.commit()

    update, context, message, reply_msg = create_mock_update_and_context(
        user_id=123, text="/report SCAN-2026-PDF001", args=["SCAN-2026-PDF001"]
    )

    await report_command(update, context)

    assert message.reply_document.called
    _, doc_kwargs = message.reply_document.call_args
    assert doc_kwargs.get("filename") == "PhishGraph_SCAN-2026-PDF001.pdf"
    assert "invoice-download.test" in doc_kwargs.get("caption", "")
