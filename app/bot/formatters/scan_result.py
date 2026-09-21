"""Telegram message formatters adhering to PhishGraph design specification."""

from typing import List, Optional
from telegram import InlineKeyboardButton, InlineKeyboardMarkup

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


def make_meter(score: float, length: int = 10) -> str:
    """Build graphical Unicode progress bar e.g. ▓▓▓▓▓▓▓░░░."""
    clamped = max(0, min(100, int(score)))
    filled = int(round((clamped / 100) * length))
    empty = length - filled
    return "▓" * filled + "░" * empty


def build_scan_keyboard(scan_uuid: str, domain: str) -> InlineKeyboardMarkup:
    """Build interactive action buttons for inline Telegram UX."""
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("📄 PDF Dossier", callback_data=f"pdf:{scan_uuid}"),
                InlineKeyboardButton("🕸 Campaign Graph", callback_data=f"graph:{scan_uuid}"),
            ],
            [
                InlineKeyboardButton("📦 STIX 2.1 JSON", callback_data=f"stix:{scan_uuid}"),
                InlineKeyboardButton("👁 Watch Drift", callback_data=f"watch:{domain}"),
            ],
            [
                InlineKeyboardButton("🔄 Re-Scan Target", callback_data=f"rescan:{scan_uuid}"),
            ],
        ]
    )



def format_start_message() -> str:
    """Return welcome start message."""
    return (
        "🛡️ *Welcome to PhishGraph Platform*\n"
        "━━━━━━━━━━━━━━━━━━━━━━\n"
        "Defensive Cyber Threat Intelligence & Infrastructure Correlation Engine.\n\n"
        "Send me any *suspicious link*, *phishing email text*, or *QR-code photo* to initiate a multi-engine security assessment.\n\n"
        "*Capabilities:*\n"
        "• 🔍 *Deep URL Heuristics:* Entropy, suspicious keywords, TLD risk\n"
        "• 🏷️ *Brand Spoofing:* Typosquatting, Leetspeak, Punycode/IDN\n"
        "• 🌐 *Infrastructure:* DNS, GeoIP, ASN, hosting, RDAP domain age\n"
        "• 🔒 *TLS / SSL:* Cipher validity, issuer CA, expiration\n"
        "• 📡 *Threat Feeds:* VirusTotal, URLhaus, OTX, SafeBrowsing, AbuseIPDB\n"
        "• 🕸️ *Campaign Correlation:* Favicon hashes, shared certs & IPs\n"
        "• 📄 *Reporting:* Executive HTML & downloadable PDF Threat Dossiers\n"
        "• 👁️ *Watchlist:* Real-time risk drift & infrastructure shift alerts\n\n"
        "Use `/help` for all commands."
    )


def format_help_message() -> str:
    """Return command help message."""
    return (
        "🔍 *PhishGraph Command Directory*\n"
        "━━━━━━━━━━━━━━━━━━━━━━\n"
        "• `/analyze <url>` — Execute full multi-engine security assessment\n"
        "• `/domain <target>` — Inspect RDAP registration age, status & registrar\n"
        "• `/dns <domain>` — Query DNS record breakdown (A, AAAA, MX, NS, TXT)\n"
        "• `/ssl <domain>` — Check TLS certificate chain, issuer, and validity\n"
        "• `/redirects <url>` — Trace HTTP redirect chain with SSRF protection\n"
        "• `/history` — View your recent investigation timeline\n"
        "• `/report <scan_id>` — Generate & download executive PDF threat dossier\n"
        "• `/watch <url>` — Put target into automated background drift monitoring\n"
        "• `/unwatch <domain>` — Remove domain from active monitoring\n"
        "• `/watchlist` — List all actively monitored targets\n"
        "• `/graph <scan_id>` — Generate Cytoscape campaign graph data\n\n"
        "_Tip: You can also simply paste or forward any message containing a URL, or send a QR image directly!_"
    )


def format_progress_message(scan_uuid: str, domain: str) -> str:
    """Return initial scan progress message."""
    return (
        "🔍 *Scan started*\n"
        "━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🎯 *Target Domain:* `{domain}`\n"
        f"🆔 *Scan Reference:* `{scan_uuid}`\n\n"
        "⚡ *Analyzing:*\n"
        "• URL Heuristics & Shannon Entropy...\n"
        "• DNS Recon & GeoIP Resolution...\n"
        "• RDAP Domain Age & Registrar...\n"
        "• TLS Certificate Chain Inspection...\n"
        "• SSRF-Safe Redirect Tracing...\n"
        "• Multi-Feed Threat Radar (VT, URLhaus, OTX, GSB, AbuseIPDB)...\n"
        "• Brand Spoofing & Punycode Analysis...\n"
        "• Favicon Hashing & Campaign Correlation..."
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
    risk_score = float(scan.risk_score or 0.0)
    conf_score = float(scan.confidence_score or 0.0)

    # Modern SOC Threat Card Framing
    if risk_score >= 75 or scan.risk_level == "CRITICAL":
        risk_badge = "🚨 CRITICAL"
        risk_bar = f"🟥 [{make_meter(risk_score)}] `{int(risk_score)}/100`"
        shield_icon = "🛑"
    elif risk_score >= 50 or scan.risk_level == "HIGH":
        risk_badge = "🔴 HIGH"
        risk_bar = f"🟧 [{make_meter(risk_score)}] `{int(risk_score)}/100`"
        shield_icon = "⚠️"
    elif risk_score >= 25 or scan.risk_level == "MODERATE":
        risk_badge = "🟡 MODERATE"
        risk_bar = f"🟨 [{make_meter(risk_score)}] `{int(risk_score)}/100`"
        shield_icon = "⚡"
    else:
        risk_badge = "🟢 LOW"
        risk_bar = f"🟩 [{make_meter(risk_score)}] `{int(risk_score)}/100`"
        shield_icon = "🛡️"

    conf_bar = f"🛡️ [{make_meter(conf_score)}] `{int(conf_score)}/100`"

    sections = [
        "╔══════════════════════════════╗",
        f"  {shield_icon} *PHISHGRAPH ANALYSIS & CYBER INTEL*  ",
        "╚══════════════════════════════╝",
        f"🌐 *Target URL:* `{scan.normalized_url or scan.original_url}`",
        f"🆔 *Scan ID:* `{scan.scan_uuid}`",
        "──────────────────────────────",
        "📊 *THREAT RISK EVALUATION*",
        f"• *Threat Level:* {risk_badge}",
        f"• *Risk Score:* {risk_bar}",
        f"• *Confidence:* {conf_bar}",
        "──────────────────────────────",
    ]



    # Brand / Impersonation Alert
    if brand_res and brand_res.has_brand_impersonation:
        sections.append("🏷️ *BRAND & IMPERSONATION SIGNALS*")
        for match in brand_res.matches:
            if not match.is_official_domain:
                sections.append(
                    f"⚠️ *Spoofed Target:* `{match.brand_name.capitalize()}`\n"
                    f"• Similarity Score: `{int(match.similarity_score * 100)}%`\n"
                    f"• Squatting Technique: `{match.detection_method.replace('_', ' ').capitalize()}`\n"
                    f"• Official Domain: `No (Unverified third-party)`"
                )
        sections.append("──────────────────────")

    # Threat Intelligence Radar
    sections.append("📡 *THREAT RADAR*")
    all_ti = ti_results or []
    ti_map = {ti.provider.lower(): ti for ti in all_ti}
    providers_order = ["virustotal", "urlhaus", "threatfox", "otx", "safebrowsing", "abuseipdb"]

    has_any_positive = False
    for p in providers_order:
        p_obj = ti_map.get(p)
        name = p.capitalize() if p not in ("otx", "threatfox") else ("AlienVault OTX" if p == "otx" else "ThreatFox IOC")
        if p == "safebrowsing":
            name = "Safe Browsing"
        elif p == "abuseipdb":
            name = "AbuseIPDB"
        elif p == "virustotal":
            name = "VirusTotal"


        if p_obj:
            if p_obj.malicious:
                has_any_positive = True
                label_txt = f" ({', '.join(p_obj.labels[:2])})" if p_obj.labels else ""
                sections.append(f"• {name}: 🚨 *MALICIOUS*{label_txt}")
            elif p_obj.suspicious:
                has_any_positive = True
                sections.append(f"• {name}: ⚠️ *SUSPICIOUS*")
            else:
                sections.append(f"• {name}: 🟢 Clean / Not Listed")
        else:
            sections.append(f"• {name}: ⏳ Unlisted")

    sections.append("──────────────────────")

    # Infrastructure & Network Recon
    infra_lines = ["🌐 *INFRASTRUCTURE & HOSTING*"]
    if dns_res and dns_res.resolved_ips:
        ip_str = dns_res.resolved_ips[0]
        geo_details = ""
        flag = getattr(dns_res, "flag_emoji", "🌐") or "🌐"
        country = getattr(dns_res, "country", "")
        city = getattr(dns_res, "city", "")
        isp = getattr(dns_res, "isp", "")
        loc_parts = [p for p in (city, country) if p]
        if loc_parts or isp:
            geo_details = f" ({flag} {', '.join(loc_parts)}" + (f" • {isp}" if isp else "") + ")"
        infra_lines.append(f"• *Primary IP:* `{ip_str}`{geo_details}")
        if len(dns_res.resolved_ips) > 1:
            more_ips = ", ".join(f"`{x}`" for x in dns_res.resolved_ips[1:3])
            infra_lines.append(f"• *Other IPs:* {more_ips}")

    if rdap_res:
        if rdap_res.domain_age_days is not None:
            age_badge = "🚨 Newly Registered (<7d)" if rdap_res.domain_age_days < 7 else f"{rdap_res.domain_age_days} days"
            infra_lines.append(f"• *Domain Age:* {age_badge}")
        if rdap_res.registrar:
            infra_lines.append(f"• *Registrar:* `{rdap_res.registrar}`")

    if dns_res and dns_res.nameservers:
        ns_str = ", ".join(f"`{ns}`" for ns in dns_res.nameservers[:2])
        infra_lines.append(f"• *Nameservers:* {ns_str}")

    if tls_res:
        if tls_res.is_valid:
            issuer_name = tls_res.issuer.get("organizationName") or tls_res.issuer.get("commonName") or "Valid CA"
            days_left = ""
            if tls_res.valid_until:
                from datetime import datetime, timezone
                delta = (tls_res.valid_until - datetime.now(timezone.utc)).days
                days_left = f" • Expires in {delta}d"
            infra_lines.append(f"• *TLS Security:* 🔒 Valid ({issuer_name}{days_left})")
        elif tls_res.is_self_signed:
            infra_lines.append("• *TLS Security:* ⚠️ Self-Signed Certificate")
        else:
            infra_lines.append("• *TLS Security:* ❌ No Valid HTTPS Certificate")

    if redir_res and redir_res.total_hops > 0:
        infra_lines.append(f"• *Redirect Chain:* {redir_res.total_hops} hop(s)")

    if len(infra_lines) > 1:
        sections.extend(infra_lines)
        sections.append("──────────────────────")

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
        sections.append("──────────────────────")

    # Key Findings / Signals
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
        sections.append("🔍 *KEY SECURITY OBSERVATIONS*")
        sections.extend(findings[:5])
        sections.append("──────────────────────")

    # Explainable Risk Breakdown ("Why this score?")
    if risk_res and risk_res.factors:
        sections.append("💡 *WHY THIS SCORE?*")
        for f in risk_res.factors[:5]:
            sections.append(f"• `+{int(f.weight)}` {f.factor_description}")
        sections.append("──────────────────────")

    # MITRE ATT&CK Matrix Mapping
    if risk_res and getattr(risk_res, "mitre_techniques", None):
        sections.append("🎯 *MITRE ATT&CK® TACTICS & TECHNIQUES*")
        for t in risk_res.mitre_techniques[:3]:
            sections.append(f"• `{t.technique_id}`: *{t.technique_name}* ({t.tactic})")
        sections.append("──────────────────────")


    # Final Verdict Summary
    if risk_score >= 70:
        verdict = "🚨 *DANGEROUS:* High-risk malicious indicators detected. Do NOT enter credentials or download any files."
    elif risk_score >= 40:
        verdict = "⚠️ *SUSPICIOUS:* Unusual infrastructure or brand similarity detected. Exercise extreme caution."
    else:
        verdict = "🟢 *BENIGN:* No prominent malicious signals detected in public feeds. Always verify the domain before signing in."

    sections.append(verdict)
    sections.append("\n_Use the buttons below to download the PDF dossier or inspect graph correlations._")
    return "\n".join(sections)


def format_invalid_url_error(raw_url: str) -> str:
    """Format invalid URL error message."""
    return (
        "❌ *Invalid URL*\n"
        "━━━━━━━━━━━━━━━━━━━━━━\n"
        f"The link `{raw_url}` could not be validated.\n"
        "Please provide a full, valid web URL starting with `http://` or `https://`."
    )


def format_generic_error(error_msg: str) -> str:
    """Format generic error message without leaking tracebacks."""
    return (
        "⚠️ *Analysis Error*\n"
        "━━━━━━━━━━━━━━━━━━━━━━\n"
        f"An error occurred while processing your request: {error_msg}\n"
        "Please try again later or verify that the target domain is reachable."
    )


def format_qr_detected_message(extracted_url: str) -> str:
    """Format QR code detection acknowledgment message (Section 5.8)."""
    return (
        "📷 *QR CODE DETECTED*\n"
        "━━━━━━━━━━━━━━━━━━━━━━\n"
        "*Destination URL:*\n"
        f"`{extracted_url}`\n\n"
        "⚡ _Running full security reconnaissance pipeline..._"
    )


def format_message_analysis(findings: list[str]) -> str:
    """Format social engineering message analysis summary (Section 5.7)."""
    lines = [
        "📨 *MESSAGE ANALYSIS*",
        "━━━━━━━━━━━━━━━━━━━━━━",
        "*Potential social-engineering signals:*",
    ]
    for finding in findings:
        lines.append(f"• {finding}")
    lines.append("──────────────────────")
    return "\n".join(lines)
