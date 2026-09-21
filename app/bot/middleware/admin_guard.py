"""Admin guard middleware for super-user-only Telegram commands.

Provides a decorator and helper that blocks access to privileged commands
unless the invoking Telegram user's numeric ID matches SUPER_USER_TELEGRAM_ID
configured in the environment / .env file.
"""

import functools
from typing import Callable, Awaitable, Any

from telegram import Update
from telegram.ext import ContextTypes

from app.config import get_settings
from app.logging import get_logger

logger = get_logger("phishgraph.admin_guard")

# ── Denial message ──────────────────────────────────────────────────────────

_DENIED_MSG = (
    "⛔ *Access Denied*\n\n"
    "This command is restricted to the designated super-user only.\n"
    "Contact the bot administrator if you believe this is an error."
)


def _get_super_user_id() -> int | None:
    """Return the configured super-user Telegram ID, or None if not set."""
    return get_settings().SUPER_USER_TELEGRAM_ID


def is_super_user(user_id: int) -> bool:
    """Return True if *user_id* matches the configured super-user ID."""
    su_id = _get_super_user_id()
    if su_id is None:
        # No super-user configured — nobody is privileged
        return False
    return user_id == su_id


def require_super_user(handler: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:
    """Decorator that restricts a command handler to the super user only.

    Usage::

        @require_super_user
        async def my_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
            ...
    """
    @functools.wraps(handler)
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE, *args: Any, **kwargs: Any) -> Any:
        user = update.effective_user
        if user is None or not is_super_user(user.id):
            uid = user.id if user else "unknown"
            logger.warning(
                "Unauthorized super-user command attempt",
                extra={"telegram_user_id": uid, "handler": handler.__name__},
            )
            await update.message.reply_text(_DENIED_MSG, parse_mode="Markdown")
            return None
        return await handler(update, context, *args, **kwargs)

    return wrapper
