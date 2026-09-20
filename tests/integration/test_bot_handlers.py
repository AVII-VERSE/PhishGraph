"""Integration tests for Telegram bot command and message handlers."""

from unittest.mock import AsyncMock, MagicMock
import pytest
from telegram import Chat, Message, Update, User as TgUser
from app.bot.handlers.analyze import analyze_command, url_message_handler
from app.bot.handlers.start import help_handler, start_handler
from app.db.models.user import User


def create_mock_update_and_context(user_id=12345, text="/start", args=None):
    """Helper to generate realistic Telegram Update and Context mock objects."""
    update = MagicMock(spec=Update)
    user = TgUser(id=user_id, is_bot=False, first_name="Alice", username="alice_sec")
    chat = Chat(id=user_id, type="private")

    message = MagicMock(spec=Message)
    message.text = text
    message.chat = chat
    message.from_user = user

    # Mock reply_text returning a message that supports edit_text
    reply_msg = MagicMock(spec=Message)
    reply_msg.edit_text = AsyncMock()
    message.reply_text = AsyncMock(return_value=reply_msg)

    update.effective_user = user
    update.effective_chat = chat
    update.effective_message = message

    context = MagicMock()
    context.args = args or []

    return update, context, message, reply_msg


@pytest.mark.asyncio
async def test_start_handler(test_engine):
    """Verify /start handler registers user and sends welcome message."""
    update, context, message, _ = create_mock_update_and_context(user_id=888999, text="/start")

    await start_handler(update, context)

    assert message.reply_text.called
    reply_args, reply_kwargs = message.reply_text.call_args
    assert "Welcome to PhishGraph" in reply_kwargs.get("text", "")


@pytest.mark.asyncio
async def test_help_handler():
    """Verify /help handler sends command instructions."""
    update, context, message, _ = create_mock_update_and_context(user_id=888999, text="/help")

    await help_handler(update, context)

    assert message.reply_text.called
    reply_args, reply_kwargs = message.reply_text.call_args
    assert "/analyze" in reply_kwargs.get("text", "")


@pytest.mark.asyncio
async def test_analyze_command_workflow(test_engine):
    """Verify /analyze command creates scan and edits progress message with result."""
    update, context, message, reply_msg = create_mock_update_and_context(
        user_id=555666,
        text="/analyze https://secure-account-verify.example/login",
        args=["https://secure-account-verify.example/login"],
    )

    await analyze_command(update, context)

    # Initial progress message
    assert message.reply_text.called
    _, prog_kwargs = message.reply_text.call_args
    assert "Scan started" in prog_kwargs.get("text", "")

    # In-place edit with scan result
    assert reply_msg.edit_text.called
    _, edit_kwargs = reply_msg.edit_text.call_args
    assert "PHISHGRAPH ANALYSIS" in edit_kwargs.get("text", "")
    assert "secure-account-verify.example" in edit_kwargs.get("text", "")


@pytest.mark.asyncio
async def test_url_auto_detection_handler(test_engine):
    """Verify messages containing raw URLs trigger analysis automatically."""
    update, context, message, reply_msg = create_mock_update_and_context(
        user_id=777888,
        text="Hey, can you check this link: https://urgent-crypto-airdrop.example/claim ?",
    )

    await url_message_handler(update, context)

    assert message.reply_text.called
    _, prog_kwargs = message.reply_text.call_args
    assert "Scan started" in prog_kwargs.get("text", "")

    assert reply_msg.edit_text.called
    _, edit_kwargs = reply_msg.edit_text.call_args
    assert "PHISHGRAPH ANALYSIS" in edit_kwargs.get("text", "")


@pytest.mark.asyncio
async def test_forwarded_message_with_social_engineering(test_engine):
    """Verify that forwarded/lure text triggers social engineering findings (Section 5.7)."""
    update, context, message, reply_msg = create_mock_update_and_context(
        user_id=111222,
        text="URGENT: Your PayPal account has been locked. Verify immediately: https://fake-paypa1.example/login",
    )

    await url_message_handler(update, context)

    assert reply_msg.edit_text.called
    _, edit_kwargs = reply_msg.edit_text.call_args
    edited_text = edit_kwargs.get("text", "")
    assert "MESSAGE ANALYSIS" in edited_text
    assert "Potential social-engineering signals" in edited_text
    assert "PHISHGRAPH ANALYSIS" in edited_text


@pytest.mark.asyncio
async def test_qr_image_handler_workflow(test_engine):
    """Verify QR image handler extracts URL and executes full scan pipeline (Section 5.8)."""
    from app.bot.handlers.qr import qr_image_handler, qr_analyzer
    from app.analyzers.qr_analyzer import QRCodeResult

    update, context, message, reply_msg = create_mock_update_and_context(
        user_id=333555,
        text="",
    )

    # Attach mock photo
    mock_photo = MagicMock()
    mock_file = MagicMock()
    mock_file.download_as_bytearray = AsyncMock(return_value=bytearray(b"dummy-image-bytes"))
    mock_photo.get_file = AsyncMock(return_value=mock_file)
    message.photo = [mock_photo]

    # Mock QR analyzer returning valid result
    qr_analyzer.decode_image_bytes = MagicMock(
        return_value=QRCodeResult(
            has_qr=True,
            raw_payload="https://qr-phishing.test/login",
            extracted_url="https://qr-phishing.test/login",
            domain="qr-phishing.test",
        )
    )

    await qr_image_handler(update, context)

    # Initial acknowledgement
    assert message.reply_text.called
    _, reply_kwargs = message.reply_text.call_args
    assert "QR CODE DETECTED" in reply_kwargs.get("text", "")

    # Result update
    assert reply_msg.edit_text.called
    _, edit_kwargs = reply_msg.edit_text.call_args
    assert "PHISHGRAPH ANALYSIS" in edit_kwargs.get("text", "")
    assert "qr-phishing.test" in edit_kwargs.get("text", "")

