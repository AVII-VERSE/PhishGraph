"""Scan history Telegram command handler."""

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from app.db.session import async_session_factory
from app.logging import get_logger
from app.services.scan_service import ScanService

logger = get_logger("phishgraph.bot.handlers.history")


async def history_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /history command returning recent scans for the calling user."""
    if not update.effective_user or not update.effective_message:
        return

    session_factory = async_session_factory()
    async with session_factory() as session:
        scans = await ScanService.get_user_scans(
            session=session,
            telegram_user_id=update.effective_user.id,
            limit=10,
        )

        if not scans:
            await update.effective_message.reply_text(
                text="ℹ️ *No scans found.*\n\nYou have not submitted any URLs yet. Send me a link or image to start.",
                parse_mode=ParseMode.MARKDOWN,
            )
            return

        lines = [
            "📋 *YOUR RECENT SCANS*\n",
        ]
        for idx, scan in enumerate(scans, 1):
            risk_badge = f"{int(scan.risk_score)}/100 ({scan.risk_level or 'PENDING'})" if scan.risk_score is not None else "Pending"
            lines.append(f"*{idx}. {scan.domain}*")
            lines.append(f"• ID: `{scan.scan_uuid}`")
            lines.append(f"• Threat Risk: {risk_badge}")
            lines.append(f"• Status: `{scan.status}`")
            lines.append("")

        lines.append("────────────────────")
        lines.append("📥 To download an investigation PDF report:")
        lines.append(f"`/report {scans[0].scan_uuid}`")

        await update.effective_message.reply_text(
            text="\n".join(lines),
            parse_mode=ParseMode.MARKDOWN,
        )
