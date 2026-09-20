"""Telegram message formatters adhering to PhishGraph design specification."""

from app.db.models.scan import Scan


def format_start_message() -> str:
    """Return welcome start message."""
    return (
        "🛡 *Welcome to PhishGraph*\n\n"
        "Send me a URL, suspicious message, or QR-code image.\n\n"
        "I can analyze:\n"
        "• URL structure\n"
        "• Domain age\n"
        "• DNS\n"
        "• TLS metadata\n"
        "• Safe redirects\n"
        "• Threat intelligence\n"
        "• Brand impersonation\n"
        "• Related infrastructure\n"
        "• Historical risk changes\n\n"
        "Use /help for commands."
    )


def format_help_message() -> str:
    """Return command help message."""
    return (
        "🔍 *PhishGraph Investigation Commands*\n\n"
        "• `/analyze <url>` — Perform full security analysis on a link\n"
        "• `/domain <domain>` — Inspect registration age & metadata\n"
        "• `/dns <domain>` — Query DNS record breakdown\n"
        "• `/ssl <domain>` — Inspect TLS/HTTPS certificate\n"
        "• `/redirects <url>` — Trace safe redirect hops\n"
        "• `/history` — View your recent URL investigations\n"
        "• `/report <scan_id>` — Retrieve full report\n"
        "• `/watch <url>` — Monitor URL for risk drift\n"
        "• `/help` — Show this guide\n\n"
        "_Tip: You can also simply paste or forward any message containing a URL!_"
    )


def format_progress_message(scan_uuid: str, domain: str) -> str:
    """Return initial scan progress message."""
    return (
        "🔍 *Scan started*\n"
        f"Domain: `{domain}`\n"
        f"Scan ID: `{scan_uuid}`\n\n"
        "Analyzing:\n"
        "• URL structure\n"
        "• Domain intelligence\n"
        "• DNS\n"
        "• TLS\n"
        "• Redirects\n"
        "• Threat intelligence\n"
        "• Brand similarity\n"
        "• Infrastructure correlation"
    )


def format_scan_result(scan: Scan) -> str:
    """Format completed scan summary for Telegram."""
    risk_emoji = "🟢"
    if scan.risk_level == "CRITICAL":
        risk_emoji = "🚨"
    elif scan.risk_level == "HIGH":
        risk_emoji = "🔴"
    elif scan.risk_level == "MODERATE":
        risk_emoji = "🟡"

    risk_score_str = f"{int(scan.risk_score) if scan.risk_score is not None else 0}/100"
    conf_score_str = f"{int(scan.confidence_score) if scan.confidence_score is not None else 0}/100"

    return (
        f"{risk_emoji} *PHISHGRAPH ANALYSIS*\n\n"
        f"*Scan ID:* `{scan.scan_uuid}`\n"
        f"*URL:* `{scan.original_url}`\n\n"
        f"*Threat Risk:* {risk_score_str} — {scan.risk_level or 'PENDING'}\n"
        f"*Evidence Confidence:* {conf_score_str}\n\n"
        f"*Domain:* `{scan.domain}`\n"
        f"*Status:* `{scan.status.upper()}`\n\n"
        "────────────────────\n"
        "_Detailed indicator analyzers and threat feeds will populate in next phase._"
    )


def format_invalid_url_error(raw_url: str) -> str:
    """Format invalid URL error message."""
    return (
        "❌ *Invalid URL*\n\n"
        f"The link `{raw_url}` is not valid. Please provide a valid http:// or https:// URL."
    )


def format_generic_error(error_msg: str) -> str:
    """Format generic error message without leaking tracebacks."""
    return (
        "⚠️ *Analysis Error*\n\n"
        f"An error occurred while processing your request: {error_msg}\n"
        "Please try again later or check that the domain is reachable."
    )
