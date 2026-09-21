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
from app.bot.handlers.graph import graph_command
from app.bot.handlers.history import history_handler
from app.bot.handlers.qr import qr_image_handler
from app.bot.handlers.report import report_command
from app.bot.handlers.start import help_handler, start_handler
from app.bot.handlers.watch import unwatch_command, watch_command, watchlist_command
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

    from telegram.request import HTTPXRequest
    proxy_url = getattr(settings, "TELEGRAM_PROXY_URL", None)
    request_kwargs = {
        "connect_timeout": 30.0,
        "read_timeout": 30.0,
        "write_timeout": 30.0,
        "pool_timeout": 30.0,
    }
    if proxy_url:
        request_kwargs["proxy"] = proxy_url

    request_client = HTTPXRequest(**request_kwargs)

    app = ApplicationBuilder().token(bot_token).request(request_client).build()

    # Register Command Handlers
    app.add_handler(CommandHandler("start", start_handler))
    app.add_handler(CommandHandler("help", help_handler))
    app.add_handler(CommandHandler("analyze", analyze_command))
    app.add_handler(CommandHandler("history", history_handler))
    app.add_handler(CommandHandler("report", report_command))
    app.add_handler(CommandHandler("watch", watch_command))
    app.add_handler(CommandHandler("unwatch", unwatch_command))
    app.add_handler(CommandHandler("watchlist", watchlist_command))
    app.add_handler(CommandHandler("graph", graph_command))

    # Register Interactive Callback Button Handler
    from app.bot.handlers.callbacks import callback_query_handler
    from telegram.ext import CallbackQueryHandler
    app.add_handler(CallbackQueryHandler(callback_query_handler))

    # Register URL message auto-detection handler
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, url_message_handler))

    # Register QR code image handler (Section 5.8)
    app.add_handler(MessageHandler(filters.PHOTO | filters.Document.IMAGE, qr_image_handler))

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
