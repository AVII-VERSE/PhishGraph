"""Investigation Report Generator.

Produces comprehensive HTML and PDF threat investigation reports adhering to
PhishGraph specification Section 31.
"""

import io
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from jinja2 import Template
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

HTML_REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PhishGraph Threat Report - {{ scan.scan_uuid }}</title>
<style>
  :root {
    --bg-dark: #0f172a;
    --card-bg: #1e293b;
    --text-main: #f8fafc;
    --text-muted: #94a3b8;
    --border: #334155;
    --primary: #38bdf8;
    --danger: #ef4444;
    --warning: #f59e0b;
    --success: #10b981;
  }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background-color: var(--bg-dark);
    color: var(--text-main);
    margin: 0;
    padding: 2rem;
    line-height: 1.6;
  }
  .container { max-width: 1000px; margin: 0 auto; }
  .header {
    border-bottom: 2px solid var(--border);
    padding-bottom: 1.5rem;
    margin-bottom: 2rem;
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
  }
  .badge {
    padding: 0.35rem 0.85rem;
    border-radius: 9999px;
    font-weight: 700;
    font-size: 0.875rem;
    text-transform: uppercase;
    display: inline-block;
  }
  .badge-CRITICAL { background: #7f1d1d; color: #fca5a5; border: 1px solid var(--danger); }
  .badge-HIGH { background: #7c2d12; color: #fdba74; border: 1px solid #ea580c; }
  .badge-MODERATE { background: #78350f; color: #fde68a; border: 1px solid var(--warning); }
  .badge-LOW { background: #064e3b; color: #6ee7b7; border: 1px solid var(--success); }
  .card {
    background: var(--card-bg);
    border: 1px solid var(--border);
    border-radius: 0.75rem;
    padding: 1.5rem;
    margin-bottom: 1.5rem;
  }
  h2 { color: var(--primary); font-size: 1.25rem; margin-top: 0; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }
  table { width: 100%; border-collapse: collapse; margin-top: 0.5rem; font-size: 0.9rem; }
  th, td { text-align: left; padding: 0.65rem; border-bottom: 1px solid var(--border); }
  th { color: var(--text-muted); text-transform: uppercase; font-size: 0.75rem; }
  .meta-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; }
  .meta-item .label { font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; }
  .meta-item .val { font-size: 1rem; font-weight: 600; word-break: break-all; }
  .disclaimer { font-size: 0.8rem; color: var(--text-muted); margin-top: 3rem; text-align: center; }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div>
      <h1 style="margin: 0; color: var(--primary);">🛡️ PhishGraph Security Investigation</h1>
      <div style="color: var(--text-muted); font-size: 0.9rem; margin-top: 0.35rem;">
        Scan ID: <code>{{ scan.scan_uuid }}</code> | Generated: {{ generated_at }}
      </div>
    </div>
    <div>
      <span class="badge badge-{{ scan.risk_level or 'LOW' }}">
        {{ scan.risk_level or 'LOW' }} RISK ({{ scan.risk_score|round|int }}/100)
      </span>
    </div>
  </div>

  <div class="card">
    <h2>1. Executive Summary</h2>
    <div class="meta-grid">
      <div class="meta-item">
        <div class="label">Target URL</div>
        <div class="val">{{ scan.original_url }}</div>
      </div>
      <div class="meta-item">
        <div class="label">Target Domain</div>
        <div class="val">{{ scan.domain }}</div>
      </div>
      <div class="meta-item">
        <div class="label">Threat Risk Score</div>
        <div class="val">{{ scan.risk_score|round|int }}/100</div>
      </div>
      <div class="meta-item">
        <div class="label">Evidence Confidence</div>
        <div class="val">{{ scan.confidence_score|round|int }}/100</div>
      </div>
    </div>
  </div>

  {% if risk_factors %}
  <div class="card">
    <h2>2. Contributing Risk Factors</h2>
    <table>
      <thead>
        <tr><th>Code</th><th>Factor Description</th><th>Weight</th><th>Source</th></tr>
      </thead>
      <tbody>
        {% for f in risk_factors %}
        <tr>
          <td><code>{{ f.factor_code }}</code></td>
          <td>{{ f.factor_description }}</td>
          <td style="color: var(--danger); font-weight: bold;">+{{ f.weight|round|int }}</td>
          <td>{{ f.evidence_source }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
  {% endif %}

  {% if threat_intel %}
  <div class="card">
    <h2>3. Threat Intelligence Feeds</h2>
    <table>
      <thead>
        <tr><th>Provider</th><th>Status</th><th>Score</th><th>Labels</th></tr>
      </thead>
      <tbody>
        {% for ti in threat_intel %}
        <tr>
          <td><strong>{{ ti.provider|upper }}</strong></td>
          <td>{{ ti.provider_status }}</td>
          <td>{{ ti.provider_score if ti.provider_score is not none else 'N/A' }}</td>
          <td>{{ ti.labels or 'None' }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
  {% endif %}

  {% if dns_records %}
  <div class="card">
    <h2>4. Resolved DNS Infrastructure</h2>
    <table>
      <thead>
        <tr><th>Type</th><th>Name</th><th>Value</th><th>TTL</th></tr>
      </thead>
      <tbody>
        {% for r in dns_records %}
        <tr>
          <td><code>{{ r.record_type }}</code></td>
          <td>{{ r.name }}</td>
          <td><code>{{ r.value }}</code></td>
          <td>{{ r.ttl }}s</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
  {% endif %}

  {% if tls_record %}
  <div class="card">
    <h2>5. TLS / SSL Certificate Metadata</h2>
    <div class="meta-grid">
      <div class="meta-item"><div class="label">Issuer</div><div class="val">{{ tls_record.issuer or 'N/A' }}</div></div>
      <div class="meta-item"><div class="label">Subject</div><div class="val">{{ tls_record.subject or 'N/A' }}</div></div>
      <div class="meta-item"><div class="label">Serial Number</div><div class="val">{{ tls_record.serial_number or 'N/A' }}</div></div>
      <div class="meta-item"><div class="label">TLS Version</div><div class="val">{{ tls_record.tls_version or 'N/A' }}</div></div>
    </div>
  </div>
  {% endif %}

  {% if redirects %}
  <div class="card">
    <h2>6. Redirect Chain</h2>
    <table>
      <thead>
        <tr><th>Hop</th><th>Source</th><th>Destination</th><th>HTTP Status</th></tr>
      </thead>
      <tbody>
        {% for h in redirects %}
        <tr>
          <td>Hop #{{ h.hop_number }}</td>
          <td>{{ h.source_url }}</td>
          <td>{{ h.destination_url }}</td>
          <td><code>{{ h.status_code }}</code></td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
  {% endif %}

  {% if correlations %}
  <div class="card">
    <h2>7. Campaign Infrastructure Correlations</h2>
    <table>
      <thead>
        <tr><th>Target Scan</th><th>Correlation Score</th><th>Shared Relations</th></tr>
      </thead>
      <tbody>
        {% for c in correlations %}
        <tr>
          <td>Scan #{{ c.target_scan_id }}</td>
          <td><strong>{{ c.correlation_score }}/100</strong></td>
          <td>{{ c.relationship_types|join(', ') }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
  {% endif %}

  <div class="disclaimer">
    PhishGraph Defensive Cybersecurity Platform — For SOC triage and research purposes only.<br>
    Assessment based on observed indicators at scan time.
  </div>
</div>
</body>
</html>
"""


def generate_html_report(scan_data: Dict[str, Any]) -> str:
    """Render HTML threat investigation report from scan data."""
    template = Template(HTML_REPORT_TEMPLATE)
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return template.render(
        scan=scan_data.get("scan", {}),
        dns_records=scan_data.get("dns_records", []),
        tls_record=scan_data.get("tls_record"),
        redirects=scan_data.get("redirects", []),
        threat_intel=scan_data.get("threat_intel", []),
        risk_factors=scan_data.get("risk_factors", []),
        fingerprint=scan_data.get("fingerprint"),
        correlations=scan_data.get("correlations", []),
        generated_at=now_iso,
    )


def generate_pdf_report(scan_data: Dict[str, Any]) -> bytes:
    """Build a structured PDF investigation report using ReportLab."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Heading1"],
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0f172a"),
    )
    h2_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#0284c7"),
        spaceBefore=12,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["Normal"],
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#1e293b"),
    )

    elements: List[Any] = []

    # Title & Header
    scan = scan_data.get("scan", {})
    scan_uuid = scan.get("scan_uuid", "N/A")
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    elements.append(Paragraph("🛡️ PhishGraph Threat Investigation Report", title_style))
    elements.append(Paragraph(f"<b>Scan ID:</b> {scan_uuid} | <b>Generated:</b> {timestamp}", body_style))
    elements.append(Spacer(1, 10))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284c7"), spaceAfter=12))

    # Executive Summary Table
    risk_level = scan.get("risk_level", "LOW")
    risk_score = scan.get("risk_score", 0)
    conf_score = scan.get("confidence_score", 0)

    summary_data = [
        ["Target URL:", Paragraph(scan.get("original_url", "N/A"), body_style)],
        ["Target Domain:", scan.get("domain", "N/A")],
        ["Threat Risk:", f"{int(risk_score)}/100 ({risk_level})"],
        ["Evidence Confidence:", f"{int(conf_score)}/100"],
    ]
    summary_table = Table(summary_data, colWidths=[120, 420])
    summary_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#0f172a")),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ])
    )
    elements.append(Paragraph("1. Executive Summary", h2_style))
    elements.append(summary_table)

    # Risk Factors
    risk_factors = scan_data.get("risk_factors", [])
    if risk_factors:
        elements.append(Paragraph("2. Contributing Risk Factors", h2_style))
        factor_rows = [["Code", "Description", "Weight", "Source"]]
        for f in risk_factors[:8]:
            factor_rows.append([
                f.get("factor_code", ""),
                Paragraph(f.get("factor_description", ""), body_style),
                f"+{int(f.get('weight', 0))}",
                f.get("evidence_source", ""),
            ])
        f_table = Table(factor_rows, colWidths=[90, 290, 60, 100])
        f_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ])
        )
        elements.append(f_table)

    # Threat Intelligence
    ti_results = scan_data.get("threat_intel", [])
    if ti_results:
        elements.append(Paragraph("3. Threat Intelligence Feeds", h2_style))
        ti_rows = [["Provider", "Status", "Score", "Labels"]]
        for ti in ti_results:
            ti_rows.append([
                ti.get("provider", "").upper(),
                ti.get("provider_status", ""),
                str(ti.get("provider_score") if ti.get("provider_score") is not None else "N/A"),
                ti.get("labels", "") or "None",
            ])
        ti_table = Table(ti_rows, colWidths=[100, 100, 80, 260])
        ti_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ])
        )
        elements.append(ti_table)

    # DNS Records
    dns_records = scan_data.get("dns_records", [])
    if dns_records:
        elements.append(Paragraph("4. DNS Records", h2_style))
        dns_rows = [["Type", "Name", "Value", "TTL"]]
        for r in dns_records[:10]:
            dns_rows.append([
                r.get("record_type", ""),
                r.get("name", ""),
                Paragraph(r.get("value", ""), body_style),
                f"{r.get('ttl', '')}s",
            ])
        dns_table = Table(dns_rows, colWidths=[50, 150, 280, 60])
        dns_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ])
        )
        elements.append(dns_table)

    # Disclaimer
    elements.append(Spacer(1, 15))
    elements.append(
        Paragraph(
            "<i>Disclaimer: This automated assessment is based on observed threat indicators and infrastructure metadata at scan time. "
            "It does not constitute absolute proof of ownership or malicious intent.</i>",
            body_style,
        )
    )

    doc.build(elements)
    return buffer.getvalue()
