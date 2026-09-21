"""Phishing Awareness Report Generator (Super-User Only).

Produces a rich multi-section PDF document that combines:
  - Executive threat summary with risk score badge
  - Phishing email simulation template (how the attack looks to a victim)
  - Infrastructure evidence (DNS, TLS, redirect chain, threat-intel hits)
  - Defensive recommendations & MITRE ATT&CK mapping
  - Optional sandbox screenshot (if Playwright available)

All output is returned as raw ``bytes`` so it can be sent directly as a
Telegram ``InputFile`` without touching the filesystem.
"""

from __future__ import annotations

import io
import textwrap
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    Image,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# ── Palette ─────────────────────────────────────────────────────────────────

_C_BG       = colors.HexColor("#0f172a")    # dark navy
_C_CARD     = colors.HexColor("#1e293b")    # card bg
_C_PRIMARY  = colors.HexColor("#38bdf8")    # sky blue
_C_DANGER   = colors.HexColor("#ef4444")    # red
_C_WARN     = colors.HexColor("#f59e0b")    # amber
_C_SUCCESS  = colors.HexColor("#10b981")    # green
_C_TEXT     = colors.HexColor("#f8fafc")    # near-white
_C_MUTED    = colors.HexColor("#94a3b8")    # slate
_C_BORDER   = colors.HexColor("#334155")    # dark border
_C_HEADER   = colors.HexColor("#0c1222")    # header bar

_RISK_COLORS = {
    "CRITICAL": colors.HexColor("#7f1d1d"),
    "HIGH":     colors.HexColor("#7c2d12"),
    "MEDIUM":   colors.HexColor("#713f12"),
    "LOW":      colors.HexColor("#14532d"),
    "MINIMAL":  colors.HexColor("#1e3a5f"),
}
_RISK_TEXT = {
    "CRITICAL": colors.HexColor("#fca5a5"),
    "HIGH":     colors.HexColor("#fdba74"),
    "MEDIUM":   colors.HexColor("#fde047"),
    "LOW":      colors.HexColor("#6ee7b7"),
    "MINIMAL":  colors.HexColor("#93c5fd"),
}


# ── Style helpers ────────────────────────────────────────────────────────────

def _styles() -> Dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "pgTitle",
            parent=base["Title"],
            fontSize=22,
            textColor=_C_TEXT,
            spaceAfter=6,
        ),
        "subtitle": ParagraphStyle(
            "pgSubtitle",
            parent=base["Normal"],
            fontSize=10,
            textColor=_C_MUTED,
            spaceAfter=12,
        ),
        "h2": ParagraphStyle(
            "pgH2",
            parent=base["Heading2"],
            fontSize=13,
            textColor=_C_PRIMARY,
            spaceBefore=14,
            spaceAfter=5,
        ),
        "h3": ParagraphStyle(
            "pgH3",
            parent=base["Heading3"],
            fontSize=11,
            textColor=_C_WARN,
            spaceBefore=8,
            spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "pgBody",
            parent=base["Normal"],
            fontSize=9,
            textColor=_C_TEXT,
            leading=13,
            spaceAfter=4,
        ),
        "mono": ParagraphStyle(
            "pgMono",
            parent=base["Code"],
            fontSize=8,
            textColor=colors.HexColor("#c0c0c0"),
            fontName="Courier",
            backColor=_C_CARD,
            leading=12,
        ),
        "email_header": ParagraphStyle(
            "pgEmailHeader",
            parent=base["Normal"],
            fontSize=8,
            textColor=_C_MUTED,
            fontName="Courier",
            leading=12,
        ),
        "email_body": ParagraphStyle(
            "pgEmailBody",
            parent=base["Normal"],
            fontSize=10,
            textColor=colors.HexColor("#1e1e1e"),
            leading=15,
        ),
        "disclaimer": ParagraphStyle(
            "pgDisclaimer",
            parent=base["Normal"],
            fontSize=7,
            textColor=_C_MUTED,
            leading=10,
        ),
    }


def _hr(elems: list) -> None:
    elems.append(Spacer(1, 4))
    elems.append(HRFlowable(width="100%", thickness=0.5, color=_C_BORDER))
    elems.append(Spacer(1, 6))


def _table_style(header_bg: Any = _C_CARD) -> TableStyle:
    return TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), header_bg),
        ("TEXTCOLOR", (0, 0), (-1, 0), _C_PRIMARY),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.3, _C_BORDER),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [_C_BG, _C_CARD]),
        ("TEXTCOLOR", (0, 1), (-1, -1), _C_TEXT),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ])


# ── Section builders ─────────────────────────────────────────────────────────

def _section_cover(elems: list, s: Dict[str, Any], st: Dict) -> None:
    """Cover / executive summary page."""
    risk_level = (s.get("risk_level") or "UNKNOWN").upper()
    risk_score = s.get("risk_score", 0)
    url = s.get("url", "N/A")
    scan_uuid = s.get("scan_uuid", "N/A")
    scanned_at = s.get("scanned_at") or datetime.now(timezone.utc).isoformat()
    confidence = s.get("confidence_score", 0)

    bg_color = _RISK_COLORS.get(risk_level, _C_CARD)
    txt_color = _RISK_TEXT.get(risk_level, _C_TEXT)

    elems.append(Paragraph("🛡️ PhishGraph — Phishing Awareness Report", st["title"]))
    elems.append(Paragraph(
        f"Generated: {scanned_at[:19]} UTC  |  Scan ID: <font name='Courier'>{scan_uuid}</font>",
        st["subtitle"],
    ))
    _hr(elems)

    # Risk badge table
    badge_data = [[
        Paragraph(f"Risk Level: {risk_level}", ParagraphStyle("badge", fontSize=14, fontName="Helvetica-Bold", textColor=txt_color)),
        Paragraph(f"Score: {risk_score}/100", ParagraphStyle("badge2", fontSize=14, fontName="Helvetica-Bold", textColor=_C_PRIMARY)),
        Paragraph(f"Confidence: {confidence:.0f}%", ParagraphStyle("badge3", fontSize=12, textColor=_C_MUTED)),
    ]]
    badge_tbl = Table(badge_data, colWidths=[180, 140, 130])
    badge_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), bg_color),
        ("BACKGROUND", (1, 0), (1, 0), _C_CARD),
        ("BACKGROUND", (2, 0), (2, 0), _C_CARD),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("GRID", (0, 0), (-1, -1), 0.5, _C_BORDER),
        ("ROUNDEDCORNERS", [4, 4, 4, 4]),
    ]))
    elems.append(badge_tbl)
    elems.append(Spacer(1, 10))

    # Target URL
    elems.append(Paragraph("Target URL", st["h3"]))
    elems.append(Paragraph(f'<font name="Courier">{url}</font>', st["mono"]))
    elems.append(Spacer(1, 10))

    # Key risk factors
    factors: List[Dict] = s.get("risk_factors", [])
    if factors:
        elems.append(Paragraph("Key Risk Factors", st["h2"]))
        rows = [["Factor", "Weight", "Severity"]]
        for f in factors[:12]:
            rows.append([
                Paragraph(str(f.get("name", "")), st["body"]),
                str(f.get("weight", "")),
                str(f.get("severity", "")),
            ])
        tbl = Table(rows, colWidths=[280, 60, 80])
        tbl.setStyle(_table_style())
        elems.append(tbl)
        elems.append(Spacer(1, 8))

    # MITRE ATT&CK
    mitre: List[Dict] = s.get("mitre_techniques", [])
    if mitre:
        elems.append(Paragraph("MITRE ATT&CK® Techniques", st["h2"]))
        rows = [["Technique ID", "Name", "Tactic"]]
        for t in mitre[:8]:
            rows.append([
                Paragraph(str(t.get("technique_id", "")), st["mono"]),
                Paragraph(str(t.get("name", "")), st["body"]),
                str(t.get("tactic", "")),
            ])
        tbl = Table(rows, colWidths=[90, 220, 110])
        tbl.setStyle(_table_style())
        elems.append(tbl)

    elems.append(PageBreak())


def _section_phishing_email_sim(elems: list, s: Dict[str, Any], st: Dict) -> None:
    """Simulated phishing email template — shows what the attack looks like."""
    url = s.get("url", "https://example.com/verify")
    domain = s.get("domain", "phishing-site.com")
    brand_matches: List[str] = s.get("brand_matches", [])
    impersonated = brand_matches[0] if brand_matches else "your financial institution"
    risk_level = (s.get("risk_level") or "HIGH").upper()

    elems.append(Paragraph("📧 Simulated Phishing Email Template", st["h2"]))
    elems.append(Paragraph(
        "The section below demonstrates how this phishing URL would appear in a real email lure sent to a victim. "
        "This simulation is for <b>defensive awareness training purposes only</b>.",
        st["body"],
    ))
    _hr(elems)

    # Email envelope headers
    now_str = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")
    envelope_lines = [
        f"From: security-alerts@{domain}",
        f"To: victim@example.com",
        f"Date: {now_str}",
        f"Subject: ⚠️ Urgent: Verify Your {impersonated.title()} Account Immediately",
        f"X-Mailer: PhishKit/3.0",
        f"X-Phish-Risk: {risk_level}",
        f"Return-Path: bounce@{domain}",
    ]
    envelope_text = "<br/>".join(envelope_lines)
    elems.append(Paragraph(envelope_text, st["email_header"]))
    _hr(elems)

    # Email body rendered on white
    body_bg_style = TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.white),
        ("LEFTPADDING", (0, 0), (-1, -1), 16),
        ("RIGHTPADDING", (0, 0), (-1, -1), 16),
        ("TOPPADDING", (0, 0), (-1, -1), 14),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 14),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
    ])
    email_content = f"""
<b>Dear Valued Customer,</b><br/><br/>
We have detected unusual activity on your <b>{impersonated.title()}</b> account.<br/>
To prevent your account from being <b>temporarily suspended</b>, you must verify your identity immediately.<br/><br/>
<u>Failure to verify within 24 hours will result in permanent account restriction.</u><br/><br/>
Please click the link below to complete verification:<br/><br/>
<font color="#1155CC"><u>{url}</u></font><br/><br/>
If you did not initiate this request, please ignore this message. However, your account will remain at risk.<br/><br/>
Thank you for your immediate attention to this matter.<br/><br/>
<b>Security Team</b><br/>
{impersonated.title()} Customer Support
"""
    body_tbl = Table([[Paragraph(email_content, st["email_body"])]], colWidths=[450])
    body_tbl.setStyle(body_bg_style)
    elems.append(body_tbl)
    elems.append(Spacer(1, 10))

    # Social engineering lures annotation
    elems.append(Paragraph("🔴 Social Engineering Lure Analysis", st["h3"]))
    lure_rows = [
        ["Tactic", "Example in Email Above"],
        ["Urgency / Time Pressure", "\"within 24 hours\", \"immediately\""],
        ["Fear of Loss", "\"account will be restricted\", \"unusual activity\""],
        ["Authority Impersonation", f"Fake sender domain: {domain}"],
        ["Call-to-Action Link", "Hyperlinked phishing URL disguised as verification"],
        ["Legitimacy Signal", "Formal language, branded subject line"],
    ]
    lure_tbl = Table(lure_rows, colWidths=[180, 270])
    lure_tbl.setStyle(_table_style(header_bg=colors.HexColor("#450a0a")))
    elems.append(lure_tbl)
    elems.append(PageBreak())


def _section_infrastructure(elems: list, s: Dict[str, Any], st: Dict) -> None:
    """DNS, TLS, redirect chain, threat-intel evidence."""
    elems.append(Paragraph("🔬 Infrastructure Evidence", st["h2"]))
    _hr(elems)

    # DNS
    dns_records: List[Dict] = s.get("dns_records", [])
    if dns_records:
        elems.append(Paragraph("DNS Records", st["h3"]))
        rows = [["Type", "Name", "Value", "TTL"]]
        for r in dns_records[:10]:
            rows.append([
                str(r.get("record_type", "")),
                Paragraph(str(r.get("name", ""))[:40], st["body"]),
                Paragraph(str(r.get("value", ""))[:60], st["mono"]),
                f"{r.get('ttl', '')}s",
            ])
        tbl = Table(rows, colWidths=[45, 110, 220, 45])
        tbl.setStyle(_table_style())
        elems.append(tbl)
        elems.append(Spacer(1, 8))

    # TLS
    tls = s.get("tls_info") or {}
    if tls:
        elems.append(Paragraph("TLS / Certificate", st["h3"]))
        tls_rows = [
            ["Field", "Value"],
            ["Issuer", str(tls.get("issuer", "N/A"))[:80]],
            ["Subject", str(tls.get("subject", "N/A"))[:80]],
            ["Not Before", str(tls.get("not_before", "N/A"))[:30]],
            ["Not After",  str(tls.get("not_after",  "N/A"))[:30]],
            ["Serial",     str(tls.get("serial_number", "N/A"))[:60]],
            ["SAN",        str(tls.get("san", "N/A"))[:100]],
        ]
        tbl = Table(tls_rows, colWidths=[110, 310])
        tbl.setStyle(_table_style())
        elems.append(tbl)
        elems.append(Spacer(1, 8))

    # Redirect chain
    redirects: List[Dict] = s.get("redirect_chain", [])
    if redirects:
        elems.append(Paragraph("Redirect Chain", st["h3"]))
        rows = [["Step", "Status", "URL"]]
        for i, r in enumerate(redirects[:8], 1):
            rows.append([
                str(i),
                str(r.get("status_code", "")),
                Paragraph(str(r.get("url", ""))[:80], st["mono"]),
            ])
        tbl = Table(rows, colWidths=[35, 60, 325])
        tbl.setStyle(_table_style())
        elems.append(tbl)
        elems.append(Spacer(1, 8))

    # Threat Intel Hits
    ti_hits: List[Dict] = s.get("threat_intel_results", [])
    flagged = [t for t in ti_hits if t.get("is_malicious") or t.get("confidence", 0) > 30]
    if flagged:
        elems.append(Paragraph("Threat Intelligence Hits", st["h3"]))
        rows = [["Source", "Malicious", "Confidence", "Category"]]
        for t in flagged[:8]:
            rows.append([
                str(t.get("source", "")),
                "✓" if t.get("is_malicious") else "?",
                f"{t.get('confidence', 0):.0f}%",
                str(t.get("category", "N/A"))[:30],
            ])
        tbl = Table(rows, colWidths=[100, 70, 80, 170])
        tbl.setStyle(_table_style())
        elems.append(tbl)

    elems.append(PageBreak())


def _section_recommendations(elems: list, s: Dict[str, Any], st: Dict) -> None:
    """Defensive recommendations and remediation steps."""
    risk_level = (s.get("risk_level") or "UNKNOWN").upper()
    url = s.get("url", "N/A")

    elems.append(Paragraph("🛡️ Defensive Recommendations", st["h2"]))
    _hr(elems)

    recs = [
        ("🚫 Do Not Click", f"Never visit: {url}"),
        ("🔒 Block at Perimeter", "Add this domain/IP to your firewall or DNS blocklist immediately."),
        ("📢 Report to Authorities", "Submit to CERT-In (India), Google Safe Browsing, or APWG."),
        ("🔑 Reset Credentials", "If credentials were entered, rotate passwords and enable 2FA."),
        ("📧 Email Gateway", "Block sender domain in mail security gateway (Proofpoint, Mimecast, etc.)."),
        ("🧑‍💼 User Awareness", "Share this report with staff. Run phishing simulation training."),
        ("📊 Threat Hunt", "Search EDR/SIEM logs for connections to this domain/IP."),
        ("🕸️ Campaign Graph", "Use /graph command in PhishGraph bot to map connected infrastructure."),
        ("👁️ Watchlist", "Use /watch command to monitor domain drift and re-registration."),
    ]

    if risk_level == "CRITICAL":
        recs.insert(0, ("🚨 CRITICAL ACTION", "Isolate any endpoint that accessed this URL. File incident report NOW."))

    rows = [["Action", "Detail"]]
    for action, detail in recs:
        rows.append([
            Paragraph(f"<b>{action}</b>", st["body"]),
            Paragraph(detail, st["body"]),
        ])
    tbl = Table(rows, colWidths=[140, 310])
    tbl.setStyle(_table_style())
    elems.append(tbl)
    elems.append(Spacer(1, 14))

    # GeoIP
    geo = s.get("geo_data") or {}
    if geo:
        elems.append(Paragraph("GeoIP Attribution", st["h3"]))
        geo_rows = [["Field", "Value"]]
        for k in ["ip", "country", "country_code", "city", "isp", "asn", "org"]:
            v = geo.get(k)
            if v:
                geo_rows.append([k.upper(), str(v)])
        tbl = Table(geo_rows, colWidths=[110, 310])
        tbl.setStyle(_table_style())
        elems.append(tbl)
        elems.append(Spacer(1, 8))

    # Disclaimer
    elems.append(Spacer(1, 20))
    elems.append(HRFlowable(width="100%", thickness=0.3, color=_C_BORDER))
    elems.append(Spacer(1, 6))
    elems.append(Paragraph(
        "<i>CONFIDENTIAL — FOR DEFENSIVE SECURITY USE ONLY. "
        "This report was generated by PhishGraph, an automated threat intelligence platform. "
        "The phishing email template in Section 2 is a simulation for awareness training only. "
        "Unauthorised distribution of this report is prohibited. "
        "All analysis is based on passive/active open-source intelligence at scan time and may not reflect current infrastructure state.</i>",
        st["disclaimer"],
    ))


# ── Main generator ───────────────────────────────────────────────────────────

def generate_phishing_awareness_pdf(scan_data: Dict[str, Any]) -> bytes:
    """Generate a phishing awareness PDF report from a completed scan record.

    Args:
        scan_data: Full scan dictionary as returned by ``ScanService.get_scan_dict()``.

    Returns:
        Raw PDF bytes.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=16 * mm,
        bottomMargin=14 * mm,
        title="PhishGraph Phishing Awareness Report",
        author="PhishGraph — Automated Cyber Threat Intelligence",
    )

    st = _styles()
    elements: list = []

    _section_cover(elements, scan_data, st)
    _section_phishing_email_sim(elements, scan_data, st)
    _section_infrastructure(elements, scan_data, st)
    _section_recommendations(elements, scan_data, st)

    doc.build(elements)
    return buffer.getvalue()
