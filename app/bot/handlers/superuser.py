"""Super-User exclusive command handlers for PhishGraph.

Available commands (restricted to SUPER_USER_TELEGRAM_ID):
  /phishreport <scan_id>  — Generate a full Phishing Awareness PDF report:
                             • Executive risk summary with MITRE mapping
                             • Simulated phishing email template (victim view)
                             • Infrastructure evidence (DNS / TLS / redirects / TI)
                             • Defensive recommendations & GeoIP attribution
"""

import io
from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from app.bot.middleware.admin_guard import require_super_user
from app.db.session import async_session_factory
from app.logging import get_logger
from app.reports.phishing_awareness_report import generate_phishing_awareness_pdf
from app.services.scan_service import ScanService

logger = get_logger("phishgraph.bot.handlers.superuser")


@require_super_user
async def phishreport_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /phishreport <scan_id> — Super-user phishing awareness PDF generator.

    Generates a comprehensive 4-section PDF:
    1. Executive summary + risk badge + MITRE ATT&CK mapping
    2. Simulated phishing email template (awareness training)
    3. Infrastructure evidence (DNS, TLS, redirect chain, threat-intel)
    4. Defensive recommendations + GeoIP attribution
    """
    if not update.effective_message:
        return

    args = context.args or []
    if not args:
        await update.effective_message.reply_text(
            text=(
                "🔐 *PhishReport — Super-User Command*\n\n"
                "*Usage:* `/phishreport <scan_id>`\n\n"
                "Generates a multi-section Phishing Awareness PDF report:\n"
                "• Executive threat summary with MITRE ATT&CK® mapping\n"
                "• 📧 Simulated phishing email template (victim view)\n"
                "• 🔬 Infrastructure evidence (DNS, TLS, Redirects, Threat-Intel)\n"
                "• 🛡️ Defensive recommendations & GeoIP attribution\n\n"
                "_Use /history to find recent scan IDs._"
            ),
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    scan_uuid = args[0].strip()
    user = update.effective_user

    logger.info(
        "Super-user phishreport requested",
        extra={"telegram_user_id": user.id, "scan_uuid": scan_uuid},
    )

    status_msg = await update.effective_message.reply_text(
        f"⏳ *Compiling Phishing Awareness Report* for `{scan_uuid}`...\n"
        "_Gathering scan data, building email simulation, rendering PDF..._",
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
                f"❌ *Scan Not Found*\n\nNo scan record with ID `{scan_uuid}` found in the database.\n"
                "_Use /history to view recent scan IDs._",
                parse_mode=ParseMode.MARKDOWN,
            )
            return

        # Flatten scan_details for the PDF generator
        flat = _flatten_scan_details(scan_details)
        pdf_bytes = generate_phishing_awareness_pdf(flat)

        pdf_file = io.BytesIO(pdf_bytes)
        domain = flat.get("domain") or scan_uuid
        filename = f"PhishAwareness_{domain.replace('.', '_')}_{scan_uuid[:8]}.pdf"
        pdf_file.name = filename

        risk_level = flat.get("risk_level", "UNKNOWN").upper()
        risk_score = flat.get("risk_score", 0)
        risk_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "MINIMAL": "⚪"}.get(risk_level, "⚫")

        caption = (
            f"🔐 *Phishing Awareness Report*\n"
            f"🎯 Target: `{domain}`\n"
            f"📊 Risk: {risk_emoji} `{risk_level}` ({risk_score}/100)\n"
            f"🆔 Scan ID: `{scan_uuid}`\n\n"
            f"_⚠️ CONFIDENTIAL — Defensive security use only._"
        )

        await update.effective_message.reply_document(
            document=pdf_file,
            filename=filename,
            caption=caption,
            parse_mode=ParseMode.MARKDOWN,
        )

        try:
            await status_msg.delete()
        except Exception:
            pass

        logger.info(
            "Phishing awareness report sent successfully",
            extra={"scan_uuid": scan_uuid, "telegram_user_id": user.id, "pdf_size": len(pdf_bytes)},
        )

    except Exception as exc:
        logger.error(f"phishreport command failed for {scan_uuid}: {exc}", exc_info=True)
        await status_msg.edit_text(
            (
                "❌ *Report Generation Failed*\n\n"
                f"Error: `{str(exc)[:200]}`\n\n"
                "_Check bot logs for full traceback._"
            ),
            parse_mode=ParseMode.MARKDOWN,
        )


def _flatten_scan_details(scan_details: dict) -> dict:
    """Flatten the nested scan_details dict returned by ScanService.get_scan_full_details
    into a single flat dict suitable for the PDF generator.
    """
    scan = scan_details.get("scan") or {}
    risk = scan_details.get("risk_assessment") or {}

    flat: dict = {}

    # Core scan fields
    for field in ("scan_uuid", "url", "domain", "scanned_at", "risk_score",
                  "risk_level", "confidence_score"):
        flat[field] = scan.get(field)

    # Risk factors & MITRE from risk_assessment block
    flat["risk_factors"] = risk.get("factors") or scan.get("risk_factors") or []
    flat["mitre_techniques"] = risk.get("mitre_techniques") or scan.get("mitre_techniques") or []

    # Brand matches
    brand = scan_details.get("brand_analysis") or {}
    flat["brand_matches"] = brand.get("matched_brands") or []

    # DNS / TLS / redirects / threat-intel — keyed directly
    flat["dns_records"] = scan_details.get("dns_records") or []
    flat["tls_info"] = scan_details.get("tls_info") or {}
    flat["redirect_chain"] = scan_details.get("redirect_chain") or []
    flat["threat_intel_results"] = scan_details.get("threat_intel_results") or []
    flat["geo_data"] = scan_details.get("geo_data") or {}

    return flat
