"""Telegram message formatters adhering to PhishGraph design specification."""

from typing import List, Optional
from app.analyzers.brand_analyzer import BrandImpersonationResult
from app.analyzers.dns_analyzer import DNSAnalysisResult
from app.analyzers.domain_analyzer import DomainIntelligenceResult
from app.analyzers.punycode_analyzer import PunycodeAnalysisResult
from app.analyzers.redirect_analyzer import RedirectChainResult
from app.analyzers.tls_analyzer import TLSAnalysisResult
from app.analyzers.url_analyzer import URLFeatures
from app.correlation.correlation_engine import CorrelationResult
from app.db.models.scan import Scan
from app.scoring.risk_engine import RiskAssessmentResult
from app.threat_intel.base import ThreatIntelResult


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
        "• Threat intelligence feeds\n"
        "• Brand impersonation & typosquatting\n"
        "• Punycode / homoglyphs\n"
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
        "• Threat intelligence feeds\n"
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
    ti_results: Optional[List[ThreatIntelResult]] = None,
    brand_res: Optional[BrandImpersonationResult] = None,
    puny_res: Optional[PunycodeAnalysisResult] = None,
    risk_res: Optional[RiskAssessmentResult] = None,
    correlation_res: Optional[CorrelationResult] = None,
) -> str:
    """Format completed scan report for Telegram adhering to Section 5.1, 13, 14 & 42 of spec."""
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

    # Brand / Impersonation Alert
    if brand_res and brand_res.has_brand_impersonation:
        sections.append("*Brand & Impersonation Signals:*")
        for match in brand_res.matches:
            if not match.is_official_domain:
                sections.append(
                    f"⚠️ Possible impersonation: *{match.brand_name.capitalize()}* (similarity: {match.similarity_score})"
                )
        sections.append("────────────────────")

    # Threat Intelligence Highlights
    ti_hits = [ti for ti in (ti_results or []) if ti.is_positive]
    if ti_hits:
        sections.append("*Threat Intelligence:*")
        for ti in ti_hits:
            status_desc = "MALICIOUS" if ti.malicious else "SUSPICIOUS"
            lbl = f" — {', '.join(ti.labels[:2])}" if ti.labels else ""
            sections.append(f"• *{ti.provider.upper()}:* {status_desc}{lbl}")
        sections.append("────────────────────")

    # Campaign Correlation
    if correlation_res and correlation_res.matches:
        sections.append("*🕸 CAMPAIGN CORRELATION*")
        cnt = len(correlation_res.matches)
        plural = "domain" if cnt == 1 else "domains"
        sections.append(f"_{cnt} potentially related {plural} observed:_\n")
        rel_descriptions = {
            "SAME_FAVICON_HASH": "Same favicon hash",
            "SAME_TLS_SERIAL": "Same TLS certificate serial",
            "SAME_REDIRECT_TARGET": "Same redirect target",
            "SAME_NAMESERVER": "Same nameserver",
            "SAME_IP": "Same IP address",
            "SAME_ASN": "Same ASN",
            "SAME_REGISTRAR": "Same registrar",
            "SAME_BRAND_TARGET": "Same targeted brand",
        }
        for match in correlation_res.matches[:3]:
            sections.append(f"`{match.related_domain}` *(Correlation: {match.score}/100)*")
            for rel in match.relations[:3]:
                sections.append(f"• {rel_descriptions.get(rel, rel)}")
            sections.append("")
        sections.append("────────────────────")

    # Key Findings / Alerts
    findings: list[str] = []
    if heuristics:
        findings.extend([f"⚠️ {s}" for s in heuristics.heuristic_signals])
    if puny_res and puny_res.signals:
        findings.extend([f"⚠️ {s}" for s in puny_res.signals])
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

    # Explainable Risk Breakdown ("Why this score?")
    if risk_res and risk_res.factors:
        sections.append("*Why this score?*")
        for f in risk_res.factors[:5]:
            sections.append(f"• `+{int(f.weight)}` {f.factor_description}")
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


def format_qr_detected_message(extracted_url: str) -> str:
    """Format QR code detection acknowledgment message (Section 5.8)."""
    return (
        "📷 *QR CODE DETECTED*\n\n"
        "*Extracted URL:*\n"
        f"`{extracted_url}`\n\n"
        "_Starting security analysis..._"
    )


def format_message_analysis(findings: list[str]) -> str:
    """Format social engineering message analysis summary (Section 5.7)."""
    lines = [
        "📨 *MESSAGE ANALYSIS*",
        "",
        "*Potential social-engineering signals:*",
    ]
    for finding in findings:
        lines.append(f"• {finding}")
    lines.append("")
    lines.append("────────────────────")
    return "\n".join(lines)
