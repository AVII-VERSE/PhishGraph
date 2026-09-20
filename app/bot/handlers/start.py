"""Start and help command handlers."""

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes
from app.bot.formatters.scan_result import format_help_message, format_start_message
from app.db.session import async_session_factory
from app.logging import get_logger
from app.services.scan_service import ScanService

logger = get_logger("phishgraph.bot.start")


async def start_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /start command, register user, and return welcome guide."""
    if not update.effective_user or not update.effective_message:
        return

    tg_user = update.effective_user
    session_factory = async_session_factory()
    async with session_factory() as session:
        await ScanService.get_or_create_user(
            session=session,
            telegram_user_id=tg_user.id,
            username=tg_user.username,
            first_name=tg_user.first_name,
        )

    logger.info(f"User {tg_user.id} invoked /start")
    await update.effective_message.reply_text(
        text=format_start_message(),
        parse_mode=ParseMode.MARKDOWN,
    )


async def help_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /help command and return available operations."""
    if not update.effective_message:
        return

    logger.info("User requested /help")
    await update.effective_message.reply_text(
        text=format_help_message(),
        parse_mode=ParseMode.MARKDOWN,
    )
