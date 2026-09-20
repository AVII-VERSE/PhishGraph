"""Analyze command and automatic URL detection message handler."""

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes
from app.bot.formatters.scan_result import (
    format_generic_error,
    format_invalid_url_error,
    format_progress_message,
    format_scan_result,
)
from app.db.session import async_session_factory
from app.logging import get_logger
from app.services.scan_service import ScanService, extract_urls_from_text

logger = get_logger("phishgraph.bot.analyze")


async def process_target_url(update: Update, target_url: str) -> None:
    """Core URL processing pipeline for both /analyze and auto-detected URLs."""
    if not update.effective_user or not update.effective_message:
        return

    tg_user = update.effective_user
    session_factory = async_session_factory()

    async with session_factory() as session:
        user = await ScanService.get_or_create_user(
            session=session,
            telegram_user_id=tg_user.id,
            username=tg_user.username,
            first_name=tg_user.first_name,
        )

        try:
            scan = await ScanService.create_scan(
                session=session,
                raw_url=target_url,
                user_id=user.id,
            )
        except ValueError:
            await update.effective_message.reply_text(
                text=format_invalid_url_error(target_url),
                parse_mode=ParseMode.MARKDOWN,
            )
            return

        # Send initial progress message
        progress_msg = await update.effective_message.reply_text(
            text=format_progress_message(scan.scan_uuid, scan.domain),
            parse_mode=ParseMode.MARKDOWN,
        )

        try:
            # Execute scan
            completed_scan = await ScanService.execute_mvp_scan(session=session, scan_id=scan.id)
            result_text = format_scan_result(completed_scan)

            # Edit progress message in place as specified in Section 18
            try:
                await progress_msg.edit_text(text=result_text, parse_mode=ParseMode.MARKDOWN)
            except Exception:
                await update.effective_message.reply_text(text=result_text, parse_mode=ParseMode.MARKDOWN)

        except Exception as exc:
            logger.error(f"Failed to execute scan for {target_url}: {exc}", exc_info=True)
            err_text = format_generic_error("Scan processing encountered a temporary issue.")
            try:
                await progress_msg.edit_text(text=err_text, parse_mode=ParseMode.MARKDOWN)
            except Exception:
                await update.effective_message.reply_text(text=err_text, parse_mode=ParseMode.MARKDOWN)


async def analyze_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /analyze <url> command."""
    if not update.effective_message:
        return

    args = context.args or []
    if not args:
        await update.effective_message.reply_text(
            "ℹ️ *Usage:* `/analyze <url>`\n\nExample: `/analyze https://example.com`",
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    raw_url = args[0]
    await process_target_url(update, raw_url)


async def url_message_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Automatically detect URLs in chat messages and initiate analysis."""
    if not update.effective_message or not update.effective_message.text:
        return

    text = update.effective_message.text.strip()
    # Ignore slash commands handled by CommandHandler
    if text.startswith("/"):
        return

    urls = extract_urls_from_text(text)
    if not urls:
        return

    # Process first extracted URL in MVP phase
    target_url = urls[0]
    logger.info(f"Auto-detected URL in message: {target_url}")
    await process_target_url(update, target_url)
