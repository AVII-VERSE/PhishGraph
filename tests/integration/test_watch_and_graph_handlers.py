"""Integration tests for /watch, /unwatch, /watchlist, and /graph Telegram handlers."""

from unittest.mock import AsyncMock, MagicMock
from datetime import datetime, timezone
import pytest
from telegram import Chat, Message, Update, User as TgUser

from app.bot.handlers.graph import graph_command
from app.bot.handlers.watch import unwatch_command, watch_command, watchlist_command
from app.db.models.scan import Scan


def create_mock_update_and_context(user_id=444555, text="/watch", args=None):
    """Helper to generate mock Telegram Update and Context objects."""
    update = MagicMock(spec=Update)
    user = TgUser(id=user_id, is_bot=False, first_name="Eve", username="eve_soc")
    chat = Chat(id=user_id, type="private")

    message = MagicMock(spec=Message)
    message.text = text
    message.chat = chat
    message.from_user = user

    reply_msg = MagicMock(spec=Message)
    reply_msg.edit_text = AsyncMock()
    message.reply_text = AsyncMock(return_value=reply_msg)

    update.effective_user = user
    update.effective_chat = chat
    update.effective_message = message

    context = MagicMock()
    context.args = args or []

    return update, context, message


@pytest.mark.asyncio
async def test_watch_and_unwatch_lifecycle(test_engine):
    """Verify complete /watch -> /watchlist -> /unwatch workflow."""
    # 1. Watch command
    update, context, message = create_mock_update_and_context(
        user_id=123789,
        text="/watch https://suspicious-target.test/login",
        args=["https://suspicious-target.test/login"],
    )

    await watch_command(update, context)

    assert message.reply_text.called
    c_args, c_kwargs = message.reply_text.call_args
    reply_text = c_args[0] if c_args else c_kwargs.get("text", "")
    assert "WATCHLIST ACTIVATED" in reply_text
    assert "suspicious-target.test" in reply_text

    # 2. Watchlist command
    update_wl, context_wl, message_wl = create_mock_update_and_context(
        user_id=123789,
        text="/watchlist",
    )
    await watchlist_command(update_wl, context_wl)

    assert message_wl.reply_text.called
    c_args, c_kwargs = message_wl.reply_text.call_args
    wl_text = c_args[0] if c_args else c_kwargs.get("text", "")
    assert "YOUR ACTIVE WATCHLIST" in wl_text
    assert "suspicious-target.test" in wl_text

    # 3. Unwatch command
    update_uw, context_uw, message_uw = create_mock_update_and_context(
        user_id=123789,
        text="/unwatch suspicious-target.test",
        args=["suspicious-target.test"],
    )
    await unwatch_command(update_uw, context_uw)

    assert message_uw.reply_text.called
    c_args, c_kwargs = message_uw.reply_text.call_args
    uw_text = c_args[0] if c_args else c_kwargs.get("text", "")
    assert "Watchlist Updated" in uw_text
    assert "Stopped monitoring `suspicious-target.test`" in uw_text


@pytest.mark.asyncio
async def test_graph_command(test_engine, db_session):
    """Verify /graph command returns network entity overview."""
    scan = Scan(
        scan_uuid="SCAN-2026-GRAPH01",
        original_url="https://network-pivot.test",
        normalized_url="https://network-pivot.test",
        domain="network-pivot.test",
        status="completed",
        risk_score=80.0,
        risk_level="HIGH",
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(scan)
    await db_session.commit()

    update, context, message = create_mock_update_and_context(
        user_id=555666,
        text="/graph SCAN-2026-GRAPH01",
        args=["SCAN-2026-GRAPH01"],
    )

    await graph_command(update, context)

    assert message.reply_text.called
    c_args, c_kwargs = message.reply_text.call_args
    graph_text = c_args[0] if c_args else c_kwargs.get("text", "")
    assert "CAMPAIGN INFRASTRUCTURE GRAPH" in graph_text
    assert "network-pivot.test" in graph_text
    assert "/api/v1/scans/SCAN-2026-GRAPH01/graph" in graph_text
