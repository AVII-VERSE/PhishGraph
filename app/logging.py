"""Structured logging configuration with secrets redaction."""

import json
import logging
import re
import sys
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any, Optional

# Context variables for request / scan tracing
scan_id_ctx: ContextVar[Optional[str]] = ContextVar("scan_id_ctx", default=None)
user_id_ctx: ContextVar[Optional[int]] = ContextVar("user_id_ctx", default=None)

# Patterns for sensitive token redaction in log messages
SECRET_PATTERNS = [
    re.compile(r"bot[0-9]+:[A-Za-z0-9_-]+", re.IGNORECASE),  # Telegram Bot Token
    re.compile(r"(api[_-]?key|token|secret|password|bearer)[=:\s]+(['\"]?)([\w\-\.]{8,})\2", re.IGNORECASE),
]


class SecretScrubber(logging.Filter):
    """Filter that intercepts and masks secrets in log messages and record arguments."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = self.scrub_text(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: self.scrub_value(v) for k, v in record.args.items()}
            elif isinstance(record.args, (list, tuple)):
                record.args = tuple(self.scrub_value(v) for v in record.args)
        return True

    @classmethod
    def scrub_text(cls, text: str) -> str:
        for pattern in SECRET_PATTERNS:
            text = pattern.sub(r"\1=***REDACTED***", text) if pattern.groups > 0 else pattern.sub("***REDACTED_BOT_TOKEN***", text)
        return text

    @classmethod
    def scrub_value(cls, val: Any) -> Any:
        if isinstance(val, str):
            return cls.scrub_text(val)
        return val


class JSONFormatter(logging.Formatter):
    """Structured JSON formatter adhering to PhishGraph logging specification."""

    def format(self, record: logging.LogRecord) -> str:
        log_payload: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "module": getattr(record, "module_name", record.name),
            "event": getattr(record, "event", "log"),
            "message": record.getMessage(),
            "scan_id": getattr(record, "scan_id", scan_id_ctx.get()),
            "user_id_internal": getattr(record, "user_id_internal", user_id_ctx.get()),
        }

        if hasattr(record, "duration_ms"):
            log_payload["duration_ms"] = record.duration_ms

        if record.exc_info:
            log_payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_payload, default=str)


def setup_logging(log_level: str = "INFO", json_format: bool = False) -> None:
    """Configure root logger with scrubber and appropriate formatter."""
    root = logging.getLogger()
    root.setLevel(log_level.upper())

    # Remove existing handlers
    for h in list(root.handlers):
        root.removeHandler(h)

    handler = logging.StreamHandler(sys.stdout)
    handler.addFilter(SecretScrubber())

    if json_format:
        handler.setFormatter(JSONFormatter())
    else:
        fmt = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(fmt)

    root.addHandler(handler)


def get_logger(name: str) -> logging.Logger:
    """Get a named logger with PhishGraph standards."""
    return logging.getLogger(name)
