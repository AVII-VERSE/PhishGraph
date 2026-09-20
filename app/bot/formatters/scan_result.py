"""Telegram message formatters adhering to PhishGraph design specification."""

from typing import Optional
from app.analyzers.dns_analyzer import DNSAnalysisResult
from app.analyzers.domain_analyzer import DomainIntelligenceResult
from app.analyzers.redirect_analyzer import RedirectChainResult
from app.analyzers.tls_analyzer import TLSAnalysisResult
from app.analyzers.url_analyzer import URLFeatures
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


def format_scan_result(
    scan: Scan,
    heuristics: Optional[URLFeatures] = None,
    dns_res: Optional[DNSAnalysisResult] = None,
    rdap_res: Optional[DomainIntelligenceResult] = None,
    tls_res: Optional[TLSAnalysisResult] = None,
    redir_res: Optional[RedirectChainResult] = None,
) -> str:
    """Format completed scan report for Telegram adhering to Section 5.1 & 42 of spec."""
    risk_emoji = "🟢"
    if scan.risk_level == "CRITICAL":
        risk_emoji = "🚨"
    elif scan.risk_level == "HIGH":
        risk_emoji = "🔴"
    elif scan.risk_level == "MODERATE":
        risk_emoji = "🟡"

    risk_score_str = f"{int(scan.risk_score) if scan.risk_score is not None else 0}/100"
    conf_score_str = f"{int(scan.confidence_score) if scan.confidence_score is not None else 0}/100"

    sections = [
        f"{risk_emoji} *PHISHGRAPH ANALYSIS*",
        "",
        f"*Scan ID:* `{scan.scan_uuid}`",
        f"*URL:* `{scan.original_url}`",
        "",
        f"*Threat Risk:* {risk_score_str} — *{scan.risk_level or 'LOW'}*",
        f"*Evidence Confidence:* {conf_score_str}",
        "────────────────────",
    ]

    # Key Findings / Alerts
    findings: list[str] = []
    if heuristics:
        findings.extend([f"⚠️ {s}" for s in heuristics.heuristic_signals])
    if rdap_res:
        findings.extend([f"⚠️ {s}" for s in rdap_res.signals])
    if tls_res:
        findings.extend([f"⚠️ {s}" for s in tls_res.signals])
    if redir_res:
        findings.extend([f"⚠️ {s}" for s in redir_res.signals])

    if findings:
        sections.append("*Key Findings:*")
        sections.extend(findings[:5])
        sections.append("────────────────────")

    # Infrastructure Breakdown
    infra_lines = ["*Infrastructure:*"]
    if dns_res and dns_res.resolved_ips:
        ips_str = ", ".join(dns_res.resolved_ips[:3])
        infra_lines.append(f"• *IP:* `{ips_str}`")
    if dns_res and dns_res.nameservers:
        ns_str = ", ".join(dns_res.nameservers[:2])
        infra_lines.append(f"• *Nameservers:* `{ns_str}`")
    if rdap_res and rdap_res.domain_age_days is not None:
        infra_lines.append(f"• *Domain Age:* {rdap_res.domain_age_days} days")
    if rdap_res and rdap_res.registrar:
        infra_lines.append(f"• *Registrar:* {rdap_res.registrar}")
    if tls_res:
        tls_status = "Valid" if tls_res.is_valid else ("Self-Signed" if tls_res.is_self_signed else "Unavailable")
        infra_lines.append(f"• *TLS:* {tls_status} ({tls_res.tls_version or 'N/A'})")
    if redir_res:
        infra_lines.append(f"• *Redirects:* {redir_res.total_hops} hop(s)")

    if len(infra_lines) > 1:
        sections.extend(infra_lines)
        sections.append("────────────────────")

    sections.append("_Assessment based on observed indicators. Avoid submitting credentials unless verified._")
    return "\n".join(sections)


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
