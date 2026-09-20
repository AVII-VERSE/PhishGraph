"""Watchlist Telegram command handlers."""

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from app.db.session import async_session_factory
from app.logging import get_logger
from app.services.scan_service import ScanService
from app.services.watch_service import WatchService

logger = get_logger("phishgraph.bot.handlers.watch")


async def watch_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /watch <url> command to monitor target for risk drift."""
    if not update.effective_user or not update.effective_message:
        return

    args = context.args or []
    if not args:
        await update.effective_message.reply_text(
            text="ℹ️ *Usage:* `/watch <url>`\n\nExample: `/watch https://example.com`",
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    raw_url = args[0].strip()
    session_factory = async_session_factory()
    async with session_factory() as session:
        user = await ScanService.get_or_create_user(
            session=session,
            telegram_user_id=update.effective_user.id,
            username=update.effective_user.username,
            first_name=update.effective_user.first_name,
        )

        try:
            watch = await WatchService.add_watch(
                session=session,
                user_id=user.id,
                raw_url=raw_url,
                interval_hours=12,
            )

            await update.effective_message.reply_text(
                text=(
                    f"👁️ *WATCHLIST ACTIVATED*\n\n"
                    f"*Target:* `{watch.domain}`\n"
                    f"*URL:* `{watch.url}`\n"
                    f"*Check Interval:* Every {watch.interval_hours} hours\n\n"
                    f"_You will receive an alert if infrastructure or risk changes._\n"
                    f"Use `/watchlist` to view all active targets or `/unwatch {watch.domain}` to cancel."
                ),
                parse_mode=ParseMode.MARKDOWN,
            )
        except ValueError as val_err:
            await update.effective_message.reply_text(
                text=f"❌ *Invalid URL:* {val_err}",
                parse_mode=ParseMode.MARKDOWN,
            )


async def unwatch_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /unwatch <domain/url> to remove target from monitoring."""
    if not update.effective_user or not update.effective_message:
        return

    args = context.args or []
    if not args:
        await update.effective_message.reply_text(
            text="ℹ️ *Usage:* `/unwatch <domain_or_url>`\n\nExample: `/unwatch example.com`",
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    target = args[0].strip()
    session_factory = async_session_factory()
    async with session_factory() as session:
        user = await ScanService.get_or_create_user(
            session=session,
            telegram_user_id=update.effective_user.id,
            username=update.effective_user.username,
            first_name=update.effective_user.first_name,
        )

        removed = await WatchService.remove_watch(
            session=session,
            user_id=user.id,
            target=target,
        )

        if removed:
            await update.effective_message.reply_text(
                text=f"✅ *Watchlist Updated*\n\nStopped monitoring `{target}`.",
                parse_mode=ParseMode.MARKDOWN,
            )
        else:
            await update.effective_message.reply_text(
                text=f"ℹ️ Target `{target}` was not found in your active watchlist.",
                parse_mode=ParseMode.MARKDOWN,
            )


async def watchlist_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /watchlist command displaying all currently monitored targets."""
    if not update.effective_user or not update.effective_message:
        return

    session_factory = async_session_factory()
    async with session_factory() as session:
        watches = await WatchService.get_user_watchlist(
            session=session,
            telegram_user_id=update.effective_user.id,
        )

        if not watches:
            await update.effective_message.reply_text(
                text="ℹ️ *Your Watchlist is Empty*\n\nUse `/watch <url>` to start monitoring suspicious links for risk drift.",
                parse_mode=ParseMode.MARKDOWN,
            )
            return

        lines = [
            "👁️ *YOUR ACTIVE WATCHLIST*\n",
        ]
        for idx, w in enumerate(watches, 1):
            score_desc = f"{int(w.last_risk_score)}/100 ({w.last_risk_level})" if w.last_risk_score is not None else "Pending Initial Scan"
            lines.append(f"*{idx}. {w.domain}*")
            lines.append(f"• URL: `{w.url}`")
            lines.append(f"• Risk: {score_desc}")
            lines.append(f"• Interval: Every {w.interval_hours}h")
            lines.append(f"• Stop: `/unwatch {w.domain}`")
            lines.append("")

        await update.effective_message.reply_text(
            text="\n".join(lines),
            parse_mode=ParseMode.MARKDOWN,
        )
