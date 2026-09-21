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
from app.bot.handlers.superuser import phishreport_command
from app.bot.handlers.watch import unwatch_command, watch_command, watchlist_command
from app.config import get_settings
from app.db.session import init_db
from app.logging import get_logger, setup_logging

logger = get_logger("phishgraph.bot")


async def set_bot_profile(app: Application) -> None:
    """Configure bot profile description, about text, and slash command menu."""
    from telegram import BotCommand

    try:
        # 1. Short Description (shown on profile preview card)
        await app.bot.set_my_short_description(
            "🛡️ PhishGraph: AI-driven cyber threat intelligence, phishing defense, brand spoofing & campaign correlation bot."
        )

        # 2. Full Description (shown when a user opens the chat before pressing Start)
        await app.bot.set_my_description(
            "🛡️ *Welcome to PhishGraph Cybersecurity Platform!*\n\n"
            "An enterprise-grade defensive security intelligence bot.\n\n"
            "⚡ *What PhishGraph Does:*\n"
            "• 🔍 Instant deep URL heuristics & entropy analysis\n"
            "• 🏷️ Brand impersonation & typosquatting detection\n"
            "• 🎯 MITRE ATT&CK® matrix mapping\n"
            "• 📡 Multi-feed Threat Radar (VirusTotal, ThreatFox, URLhaus, OTX, GSB, AbuseIPDB)\n"
            "• 🌐 Infrastructure reconnaissance (DNS, GeoIP, ASN, RDAP)\n"
            "• 🕸️ Campaign fingerprint correlation (Favicon, SSL serials)\n"
            "• 📄 Executive PDF Threat Dossier export\n"
            "• 👁️ Continuous drift monitoring\n\n"
            "👉 Send any link, forward a suspicious email, or send a QR code image to begin!"
        )

        # 3. Interactive Bot Command Menu
        commands = [
            BotCommand("start", "Launch PhishGraph welcome dashboard"),
            BotCommand("help", "View complete guide & command directory"),
            BotCommand("analyze", "Execute multi-engine security assessment: /analyze <url>"),
            BotCommand("history", "View recent investigation timeline"),
            BotCommand("watchlist", "Inspect actively monitored drift targets"),
            BotCommand("report", "Download executive PDF dossier: /report <scan_id>"),
            BotCommand("graph", "Generate Cytoscape campaign graph data"),
            BotCommand("phishreport", "🔐 [Admin] Phishing Awareness PDF: /phishreport <scan_id>"),
        ]
        await app.bot.set_my_commands(commands)
        logger.info("Successfully updated Telegram bot profile descriptions and command menu.")
    except Exception as exc:
        logger.warning(f"Could not update bot profile settings: {exc}")


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

    app = (
        ApplicationBuilder()
        .token(bot_token)
        .request(request_client)
        .post_init(set_bot_profile)
        .build()
    )

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
    app.add_handler(CommandHandler("phishreport", phishreport_command))

    # Register Interactive Callback Button Handler
    from app.bot.handlers.callbacks import callback_query_handler
    from telegram.ext import CallbackQueryHandler
    app.add_handler(CallbackQueryHandler(callback_query_handler))

    # Register URL message auto-detection handler
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, url_message_handler))

    # Register QR code image handler (Section 5.8)
    app.add_handler(MessageHandler(filters.PHOTO | filters.Document.IMAGE, qr_image_handler))

    # Register Telegram Inline Query Handler (@BotUsername <url>)
    from app.bot.handlers.inline import inline_query_handler
    from telegram.ext import InlineQueryHandler
    app.add_handler(InlineQueryHandler(inline_query_handler))

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
