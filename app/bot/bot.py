"""Telegram Bot application builder and runner."""

import asyncio
from typing import Optional
from telegram.ext import (
    Application,
    ApplicationBuilder,
    CommandHandler,
    MessageHandler,
    filters,
)
from app.bot.handlers.analyze import analyze_command, url_message_handler
from app.bot.handlers.start import help_handler, start_handler
from app.config import get_settings
from app.db.session import init_db
from app.logging import get_logger, setup_logging

logger = get_logger("phishgraph.bot")


def build_bot_app(token: Optional[str] = None) -> Application:
    """Construct and configure the python-telegram-bot Application."""
    settings = get_settings()
    bot_token = token or settings.TELEGRAM_BOT_TOKEN

    if not bot_token:
        raise ValueError("TELEGRAM_BOT_TOKEN is not configured in environment or .env file.")

    app = ApplicationBuilder().token(bot_token).build()

    # Register Command Handlers
    app.add_handler(CommandHandler("start", start_handler))
    app.add_handler(CommandHandler("help", help_handler))
    app.add_handler(CommandHandler("analyze", analyze_command))

    # Register URL message auto-detection handler
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, url_message_handler))

    return app


def run_bot() -> None:
    """Entry point to run the Telegram Bot polling loop."""
    settings = get_settings()
    setup_logging(log_level=settings.LOG_LEVEL)
    logger.info(f"Starting {settings.APP_NAME} Telegram Bot...")

    if not settings.TELEGRAM_BOT_TOKEN:
        logger.warning(
            "TELEGRAM_BOT_TOKEN is empty. Bot polling cannot start. "
            "Please configure TELEGRAM_BOT_TOKEN in your .env file."
        )
        return

    # Ensure DB tables exist
    if settings.is_sqlite:
        asyncio.run(init_db())

    bot_app = build_bot_app()
    logger.info("Bot polling initiated. Listening for Telegram messages...")
    bot_app.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    run_bot()
