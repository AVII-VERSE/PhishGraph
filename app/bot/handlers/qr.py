"""QR code image message handler."""

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from app.analyzers.qr_analyzer import QRAnalyzer
from app.bot.formatters.scan_result import (
    format_generic_error,
    format_qr_detected_message,
    format_scan_result,
)
from app.db.session import async_session_factory
from app.logging import get_logger
from app.services.scan_service import ScanService

logger = get_logger("phishgraph.bot.handlers.qr")
qr_analyzer = QRAnalyzer()


async def qr_image_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle photo or image document containing a potential QR code."""
    if not update.effective_message:
        return

    photo_file = None
    if update.effective_message.photo:
        photo_file = await update.effective_message.photo[-1].get_file()
    elif update.effective_message.document and update.effective_message.document.mime_type:
        if update.effective_message.document.mime_type.startswith("image/"):
            photo_file = await update.effective_message.document.get_file()

    if not photo_file:
        return

    try:
        image_bytes = await photo_file.download_as_bytearray()
        result = qr_analyzer.decode_image_bytes(bytes(image_bytes))

        if not result.has_qr:
            await update.effective_message.reply_text(
                text="ℹ️ No readable QR code detected in this image.",
            )
            return

        if result.error or not result.extracted_url:
            await update.effective_message.reply_text(
                text=f"⚠️ *QR Code Issue:*\n\n{result.error or 'Could not extract a valid web URL.'}",
                parse_mode=ParseMode.MARKDOWN,
            )
            return

        # Rate limiting check (Section 39)
        from app.services.rate_limiter import get_rate_limiter
        from app.services.metrics_service import MetricsService

        user_id = update.effective_user.id if update.effective_user else 0
        rate_limiter = get_rate_limiter()
        is_limited, _ = await rate_limiter.check_scan_rate_limit(user_id)
        if is_limited:
            MetricsService.record_rate_limit_hit()
            await update.effective_message.reply_text(
                text="⏳ Rate limit reached.\nPlease try again later.",
            )
            return

        # 1. Acknowledge QR code detection
        ack_msg = await update.effective_message.reply_text(
            text=format_qr_detected_message(result.extracted_url),
            parse_mode=ParseMode.MARKDOWN,
        )

        # 2. Execute full scan pipeline
        session_factory = async_session_factory()
        async with session_factory() as session:
            user = None
            if update.effective_user:
                user = await ScanService.get_or_create_user(
                    session=session,
                    telegram_user_id=update.effective_user.id,
                    username=update.effective_user.username,
                    first_name=update.effective_user.first_name,
                )

            scan = await ScanService.create_scan(
                session=session,
                raw_url=result.extracted_url,
                user_id=user.id if user else None,
            )

            (
                scan,
                heuristics,
                dns_res,
                rdap_res,
                tls_res,
                redir_res,
                ti_results,
                brand_res,
                puny_res,
                risk_res,
                correlation_res,
            ) = await ScanService.execute_scan(session=session, scan_id=scan.id)
            MetricsService.record_scan_executed(risk_res.risk_score)

            report_text = format_scan_result(
                scan=scan,
                heuristics=heuristics,
                dns_res=dns_res,
                rdap_res=rdap_res,
                tls_res=tls_res,
                redir_res=redir_res,
                ti_results=ti_results,
                brand_res=brand_res,
                puny_res=puny_res,
                risk_res=risk_res,
                correlation_res=correlation_res,
            )

            from app.bot.formatters.scan_result import build_scan_keyboard
            keyboard = build_scan_keyboard(scan.scan_uuid, scan.domain)

            try:
                await ack_msg.edit_text(
                    text=report_text,
                    parse_mode=ParseMode.MARKDOWN,
                    reply_markup=keyboard,
                )
            except Exception:
                await update.effective_message.reply_text(
                    text=report_text,
                    parse_mode=ParseMode.MARKDOWN,
                    reply_markup=keyboard,
                )

    except Exception as exc:
        logger.error(f"Error handling QR code image: {exc}", exc_info=True)
        await update.effective_message.reply_text(
            text=format_generic_error("Failed to process QR code image."),
            parse_mode=ParseMode.MARKDOWN,
        )
