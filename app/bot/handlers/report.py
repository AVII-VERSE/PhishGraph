"""Investigation report Telegram command handler."""

import io
from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from app.bot.formatters.scan_result import format_generic_error
from app.db.session import async_session_factory
from app.logging import get_logger
from app.reports.report_generator import generate_pdf_report
from app.services.scan_service import ScanService

logger = get_logger("phishgraph.bot.handlers.report")


async def report_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /report <scan_id> command generating and sending an investigation PDF."""
    if not update.effective_message:
        return

    args = context.args or []
    if not args:
        await update.effective_message.reply_text(
            text="ℹ️ *Usage:* `/report <scan_id>`\n\nExample: `/report SCAN-2026-000123`\nUse `/history` to view your recent scan IDs.",
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    scan_uuid = args[0].strip()

    status_msg = await update.effective_message.reply_text(
        f"⏳ Generating threat investigation report for `{scan_uuid}`...",
        parse_mode=ParseMode.MARKDOWN,
    )

    try:
        session_factory = async_session_factory()
        async with session_factory() as session:
            scan_details = await ScanService.get_scan_full_details(
                session=session,
                scan_uuid=scan_uuid,
            )

        if not scan_details:
            await status_msg.edit_text(
                f"❌ *Scan Not Found*\n\nNo scan record exists with ID `{scan_uuid}`.",
                parse_mode=ParseMode.MARKDOWN,
            )
            return

        pdf_bytes = generate_pdf_report(scan_details)
        pdf_file = io.BytesIO(pdf_bytes)
        pdf_file.name = f"PhishGraph_{scan_uuid}.pdf"

        await update.effective_message.reply_document(
            document=pdf_file,
            filename=f"PhishGraph_{scan_uuid}.pdf",
            caption=f"📄 *Investigation Report for {scan_details['scan']['domain']}*\nScan ID: `{scan_uuid}`",
            parse_mode=ParseMode.MARKDOWN,
        )
        try:
            await status_msg.delete()
        except Exception:
            pass

    except Exception as exc:
        logger.error(f"Failed to generate report for {scan_uuid}: {exc}", exc_info=True)
        await status_msg.edit_text(
            format_generic_error("Failed to compile investigation PDF report."),
            parse_mode=ParseMode.MARKDOWN,
        )
