"""Inline query handler allowing users to inspect URLs from any chat via @BotUsername."""

import hashlib
from telegram import InlineQueryResultArticle, InputTextMessageContent, Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes
from app.analyzers.url_analyzer import analyze_url_heuristics
from app.logging import get_logger

logger = get_logger("phishgraph.bot.inline")


async def inline_query_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle inline query typed by user: @PhishGraphBot <url>."""
    query = update.inline_query.query.strip() if update.inline_query else ""
    if not query or not (query.startswith("http://") or query.startswith("https://")):
        return

    heuristics = analyze_url_heuristics(query)
    is_high_risk = heuristics.is_high_abuse_tld or len(heuristics.suspicious_keywords_found) >= 2

    title = "🚨 DANGEROUS / SUSPICIOUS LINK" if is_high_risk else "🛡️ PHISHGRAPH LINK CHECK"
    description = (
        f"Suspicious signals detected ({', '.join(heuristics.suspicious_keywords_found)})"
        if is_high_risk
        else f"Target: {heuristics.hostname}"
    )

    text_content = (
        f"🛡️ *PhishGraph Inline Threat Verification*\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🔗 *URL:* `{query}`\n"
        f"🌐 *Host:* `{heuristics.hostname}`\n"
        f"⚠️ *Status:* {'🚨 High Risk Indicators' if is_high_risk else '🟢 Standard Examination'}\n"
        f"🔍 *Observed Keywords:* `{', '.join(heuristics.suspicious_keywords_found) or 'None'}`\n\n"
        f"_Run full investigation with_ @PhishGraphBot"
    )

    query_hash = hashlib.md5(query.encode()).hexdigest()
    results = [
        InlineQueryResultArticle(
            id=query_hash,
            title=title,
            description=description,
            input_message_content=InputTextMessageContent(
                message_text=text_content,
                parse_mode=ParseMode.MARKDOWN,
            ),
        )
    ]

    await update.inline_query.answer(results, cache_time=10)
