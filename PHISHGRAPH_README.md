# PhishGraph

> **Phishing Infrastructure & Campaign Intelligence Telegram Bot**  
> A defensive cybersecurity project for analyzing suspicious URLs, correlating related infrastructure, detecting phishing indicators, and explaining *why* a link may be risky.

---

## 1. Project Overview

PhishGraph is a Telegram-based phishing investigation assistant designed for defensive cybersecurity, SOC analysis, academic research, and security awareness workflows.

A user can send a suspicious URL, domain, QR code, or forwarded message to the Telegram bot. PhishGraph extracts indicators, performs passive and low-impact security checks, queries external threat-intelligence providers, calculates an explainable risk score, and correlates the infrastructure with previously observed indicators.

The main purpose is not to answer only:

> “Is this URL malicious?”

Instead, PhishGraph should answer:

> “Why is this URL suspicious, what evidence supports the assessment, what infrastructure is connected to it, and does it appear related to any previously observed phishing campaign?”

This design makes the project more useful than a simple URL reputation checker because it combines URL analysis, threat intelligence, infrastructure fingerprinting, historical correlation, and campaign-level reasoning.

### Project Goals

PhishGraph should be able to:

- Accept URLs directly through Telegram.
- Extract URLs automatically from forwarded messages.
- Decode URLs from QR-code images.
- Analyze URL structure and suspicious patterns.
- Check domain age and registration metadata through RDAP/WHOIS-style sources.
- Resolve DNS records.
- Inspect HTTPS and TLS certificate metadata.
- Follow and record redirect chains safely.
- Query multiple threat-intelligence services.
- Detect possible typosquatting and brand impersonation.
- Create infrastructure fingerprints.
- Correlate new URLs with previously scanned infrastructure.
- Calculate an explainable threat-risk score.
- Calculate an independent evidence-confidence score.
- Store scan history and observations.
- Detect risk changes over time.
- Generate investigation summaries and downloadable reports.
- Provide a foundation for a future web-based SOC dashboard.

---

# 2. Core Idea

Traditional URL scanning bots normally perform one or more reputation lookups and return a verdict. PhishGraph extends this model by maintaining an internal knowledge base of previous scans.

Example:

```text
User submits:
https://paypa1-secure-login.example

PhishGraph analyzes:

URL Features
    ↓
Domain Intelligence
    ↓
DNS
    ↓
TLS Certificate
    ↓
Redirect Chain
    ↓
Threat Intelligence
    ↓
Brand Similarity
    ↓
Infrastructure Fingerprint
    ↓
Historical Correlation
    ↓
Risk + Confidence
    ↓
Campaign Relationships
    ↓
Telegram Investigation Report
```

Instead of treating every scan as isolated, PhishGraph should preserve useful indicators and connect related observations.

For example:

```text
paypa1-secure-login.example
        │
        ├── Same nameserver ───── paypal-verify.example
        │
        ├── Same favicon hash ─── paypal-account.example
        │
        └── Same hosting ASN ──── secure-login.example
```

The system must clearly distinguish between **evidence of similarity** and **proof of common ownership**. Correlation should be reported as a confidence-based relationship, not as a guaranteed attribution.

---

# 3. Recommended Technology Stack

## Backend

- Python
- FastAPI
- Pydantic
- SQLAlchemy
- Alembic
- HTTPX for asynchronous HTTP requests
- dnspython for DNS queries
- Python `ssl` and `socket` libraries for certificate inspection
- `cryptography` where deeper certificate parsing is required
- Redis for caching and rate-limit state
- PostgreSQL for persistent storage

## Telegram Layer

- `python-telegram-bot` or an equivalent maintained Telegram Bot API framework

## Optional Background Processing

For the MVP, asynchronous FastAPI tasks are sufficient.

For later versions:

- Celery, Dramatiq, or RQ
- Redis as broker/backend

## Reporting

- Jinja2 for HTML templates
- WeasyPrint or ReportLab for PDF generation

## QR Processing

- OpenCV or Pillow
- `pyzbar` or another QR decoder

## Future Dashboard

- React
- TypeScript
- Vite
- Tailwind CSS
- Recharts or another charting library
- Cytoscape.js for infrastructure/campaign graphs

## Deployment

- Docker
- Docker Compose
- Nginx or Caddy reverse proxy
- PostgreSQL
- Redis

---

# 4. High-Level Architecture

```text
                         ┌──────────────────────┐
                         │    Telegram User     │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │   Telegram Bot App   │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │   FastAPI Backend    │
                         └──────────┬───────────┘
                                    │
             ┌──────────────────────┼──────────────────────┐
             │                      │                      │
             ▼                      ▼                      ▼
     ┌───────────────┐      ┌───────────────┐      ┌───────────────┐
     │ URL Analyzer  │      │ Threat Intel  │      │ Msg/QR Parser │
     └───────┬───────┘      └───────┬───────┘      └───────┬───────┘
             │                      │                      │
             └──────────────────────┼──────────────────────┘
                                    ▼
                         ┌──────────────────────┐
                         │ Fingerprint Engine   │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │ Correlation Engine   │
                         └──────────┬───────────┘
                                    │
                       ┌────────────┴────────────┐
                       ▼                         ▼
              ┌────────────────┐       ┌────────────────┐
              │ PostgreSQL DB  │       │     Redis      │
              └────────┬───────┘       └────────────────┘
                       │
                       ▼
              ┌────────────────┐
              │  Risk Engine   │
              └────────┬───────┘
                       │
                       ▼
              ┌────────────────┐
              │ Report Builder │
              └────────┬───────┘
                       │
                       ▼
              ┌────────────────┐
              │ Telegram Reply │
              └────────────────┘
```

---

# 5. Main User Workflows

## 5.1 Direct URL Scan

The user sends:

```text
https://suspicious.example/login
```

The bot should automatically recognize the message as a URL and start analysis.

Expected response flow:

```text
🔍 Scan started
Domain: suspicious.example
Scan ID: SCAN-2026-000123

Analyzing:
• URL structure
• Domain intelligence
• DNS
• TLS
• Redirects
• Threat intelligence
• Brand similarity
• Infrastructure correlation
```

Final response:

```text
🚨 PHISHGRAPH ANALYSIS

URL: https://suspicious.example/login

Threat Risk: 81/100 — HIGH
Evidence Confidence: 76/100

Key Findings:
⚠ Domain registered recently
⚠ Suspicious login-related keyword
⚠ Similarity to known financial brand
⚠ Listed by one threat-intelligence source
⚠ Infrastructure overlaps with 2 previously suspicious domains

Infrastructure:
IP: 203.0.113.10
ASN: ASXXXXX
TLS: Valid
Redirects: 2

Campaign Correlation:
2 related observations found

Scan ID: SCAN-2026-000123
```

---

## 5.2 Command-Based Scan

```text
/analyze https://example.com
```

Useful when the user wants explicit control.

---

## 5.3 Domain Intelligence

```text
/domain example.com
```

Return:

- Registration date
- Domain age
- Registrar
- Expiration date where available
- Domain status
- Nameservers
- DNS overview
- Threat reputation summary

---

## 5.4 DNS Lookup

```text
/dns example.com
```

Return:

- A
- AAAA
- MX
- NS
- TXT
- CNAME
- SOA
- CAA

DNS results must be bounded and formatted cleanly so that very large TXT responses do not flood Telegram messages.

---

## 5.5 TLS/SSL Inspection

```text
/ssl example.com
```

Return:

- HTTPS reachable or not
- Certificate subject
- Common name
- Subject Alternative Names
- Issuer
- Valid from
- Valid until
- Days remaining
- Hostname match
- Certificate validity
- Negotiated TLS version

Do not perform intrusive TLS enumeration in the first version.

---

## 5.6 Redirect Chain

```text
/redirects https://short.example/abc
```

Return:

```text
Redirect Chain

1. short.example/abc
   ↓ 301
2. tracker.example/x
   ↓ 302
3. login.example/
   ↓ 200
4. Final destination
```

Important defensive requirement:

- Maximum redirect count must be limited.
- Every destination must be validated before connection.
- Internal/private network destinations must be blocked.

---

## 5.7 Forwarded Message Analysis

The user forwards a suspicious Telegram message:

```text
Your account has been locked.
Verify immediately:
https://example-login.test
```

PhishGraph should:

1. Extract all URLs.
2. Detect urgency language.
3. Identify possible brand names.
4. Analyze each URL.
5. Compare claimed brand with actual domain.
6. Produce a combined social-engineering summary.

Example:

```text
📨 MESSAGE ANALYSIS

Potential social-engineering signals:
• Urgency: “immediately”
• Account-lockout pressure
• External verification link
• Claimed brand does not match destination domain

URL Risk: HIGH
```

---

## 5.8 QR-Code Analysis

The user sends an image containing a QR code.

Flow:

```text
Image
  ↓
QR Decoder
  ↓
Extract URL
  ↓
URL Validator
  ↓
PhishGraph Scan Pipeline
```

Response:

```text
📷 QR CODE DETECTED

Extracted URL:
https://suspicious.example

Starting security analysis...
```

The bot must never automatically open arbitrary local schemes such as `file://`, `ftp://`, or custom application protocols. For the initial version, only `http://` and `https://` should be supported.

---

# 6. Feature Specification

## 6.1 URL Parsing and Normalization

Before any analysis, normalize the input.

Required tasks:

- Trim whitespace.
- Decode safe URL encodings for display.
- Preserve original URL separately.
- Parse scheme.
- Extract hostname.
- Normalize internationalized domain names.
- Extract port.
- Extract path.
- Extract query parameters.
- Remove URL fragment from network requests where appropriate.
- Validate syntax.

Store both:

```text
original_url
normalized_url
```

Never silently change the meaning of the user-supplied URL.

---

## 6.2 URL Heuristic Analyzer

Analyze local URL features without depending on external reputation APIs.

Suggested features:

- Total URL length
- Hostname length
- Path length
- Number of subdomains
- Number of query parameters
- Excessive hyphen use
- Excessive numeric characters
- IP-address-based hostname
- Presence of `@`
- Double slash in path
- URL encoding density
- Punycode prefix (`xn--`)
- Suspicious keywords
- Multiple suspicious keywords
- Common URL-shortener domains
- Unusual port
- Very high path entropy
- Very high query entropy
- Repeated brand-like strings

Suggested suspicious keyword list:

```text
login
signin
verify
verification
account
secure
update
password
wallet
payment
bank
banking
confirm
unlock
support
recovery
```

The keyword list must be configurable and must never be treated as definitive proof of phishing.

---

## 6.3 Domain Intelligence

Use RDAP as the preferred structured source where possible.

Collect:

- Domain creation date
- Updated date
- Expiration date
- Registrar
- Domain status
- Nameservers
- Available registrant organization metadata where legally/publicly exposed

Derived fields:

```text
domain_age_days
expires_in_days
recently_registered
recently_updated
```

Suggested initial heuristic:

```text
Age < 7 days      → strong suspicious-age signal
Age < 30 days     → moderate suspicious-age signal
Age < 90 days     → weak suspicious-age signal
```

Do not assign malicious verdicts based only on age.

---

## 6.4 DNS Analyzer

Use asynchronous DNS resolution.

Collect:

```text
A
AAAA
MX
NS
TXT
CNAME
SOA
CAA
```

Store each record separately so that later correlation is possible.

Derived signals may include:

- No A/AAAA record
- No MX record
- Fast infrastructure changes observed across repeated scans
- Shared nameservers with previous suspicious observations
- Shared IPs with previous suspicious observations

A shared IP alone must not be considered strong evidence because CDNs and shared hosting environments commonly host unrelated domains.

---

## 6.5 TLS Analyzer

For HTTPS targets, collect:

- Certificate subject
- Certificate issuer
- Serial number if useful for correlation
- Common Name
- Subject Alternative Names
- Validity start
- Validity end
- Days remaining
- Hostname match
- Negotiated TLS version
- Self-signed indicator

Possible alerts:

```text
Certificate expired
Hostname mismatch
Self-signed certificate
Certificate expires soon
No HTTPS available
```

A valid certificate does not imply that a site is trustworthy.

---

## 6.6 Redirect Analyzer

Use HTTPX with redirection disabled initially.

Process each hop manually:

1. Request current URL.
2. Read status code.
3. If redirect, extract `Location`.
4. Normalize destination.
5. Re-run SSRF validation.
6. Continue until terminal response or maximum hop count.

Recommended limit:

```text
MAX_REDIRECTS = 10
```

Store:

```text
source_url
destination_url
status_code
hop_number
source_domain
destination_domain
```

Derived signals:

- Cross-domain redirect
- Multiple domain changes
- URL shortener to unrelated domain
- Redirect to IP-address hostname
- Redirect to a newly registered domain

---

# 7. Threat-Intelligence Integrations

Each integration must live behind its own provider interface.

Example interface:

```python
class ThreatIntelProvider:
    async def lookup_url(self, url: str):
        ...

    async def lookup_domain(self, domain: str):
        ...

    async def lookup_ip(self, ip: str):
        ...
```

Potential providers:

- VirusTotal
- URLhaus
- AlienVault OTX
- Google Safe Browsing
- AbuseIPDB for public IP reputation where applicable
- PhishTank where permitted by available API/data access

Do not make the entire scan fail because one provider is unavailable.

Every provider should return a normalized structure such as:

```json
{
  "provider": "example_provider",
  "status": "success",
  "malicious": false,
  "suspicious": true,
  "score": 20,
  "labels": ["phishing"],
  "raw_reference": "provider-result-id"
}
```

Provider API keys must never be exposed in Telegram responses, logs, Git commits, or client-side code.

---

# 8. Brand Impersonation Engine

This module attempts to detect whether a domain resembles a known brand.

Important: this is a similarity detector, not a legal or attribution engine.

## Input Data

Maintain a configurable list:

```json
{
  "paypal": ["paypal.com"],
  "google": ["google.com"],
  "microsoft": ["microsoft.com", "live.com", "office.com"],
  "amazon": ["amazon.com"],
  "apple": ["apple.com"]
}
```

The list should later support regional official domains.

## Detection Methods

- Exact brand keyword in non-official domain
- Levenshtein distance
- Jaro-Winkler similarity
- Character substitution
- Number-for-letter substitution
- Hyphen insertion
- Extra word insertion
- Missing character
- Punycode / IDN indicator

Example:

```text
paypa1-secure-login.example
```

Possible output:

```text
Possible brand similarity: PayPal
Similarity score: 0.91
Official domain match: No
```

Do not claim that a domain is malicious solely because it contains a brand name.

---

# 9. Punycode and Homograph Analysis

Detect `xn--` domains and decode their Unicode representation for inspection.

Possible signals:

- Mixed scripts
- Characters visually similar to Latin letters
- Brand-like Unicode domain

Output example:

```text
⚠ Internationalized domain detected
ASCII: xn--example-...
Unicode: ...

Possible visual-similarity risk.
```

Never render untrusted Unicode domains in a way that hides their ASCII/punycode form. Show both forms.

---

# 10. Entropy Analysis

Shannon entropy can be used as a weak heuristic for unusually random URL paths or query values.

Calculate entropy for:

- Path segments
- Query values
- Long subdomain labels

Example:

```text
Normal:
/account/login

Potentially machine-generated:
/A8dJ93kLmP01xZ77
```

Entropy must have low weight in the risk model because legitimate tracking links and CDNs can also use high-entropy identifiers.

---

# 11. Infrastructure Fingerprint Engine

Every completed scan should generate a structured fingerprint.

Example fields:

```text
Domain
Resolved IPs
ASN
Nameservers
Registrar
TLS issuer
TLS certificate serial
Certificate SANs
Favicon hash
Page hash (optional, later phase)
Redirect destination domains
HTTP server header (optional)
Content title (optional)
```

Fingerprint example:

```json
{
  "domain": "example.test",
  "ips": ["203.0.113.10"],
  "asn": "AS64500",
  "nameservers": ["ns1.provider.test"],
  "tls_issuer": "Example CA",
  "favicon_hash": "mmh3:123456789",
  "redirect_domains": ["example-login.test"]
}
```

Use fingerprints for correlation, not for attribution.

---

# 12. Favicon Fingerprinting

Later versions may download a site's favicon and calculate one or more hashes.

Possible options:

- SHA-256
- MurmurHash3 for compatibility with common search/pivot workflows
- Perceptual hash for visual similarity

Safety requirements:

- Enforce download size limit.
- Enforce timeout.
- Revalidate resolved IP.
- Do not process non-image payloads blindly.

Favicon similarity is a useful supporting signal but not proof that two domains belong to the same operator.

---

# 13. Campaign Correlation Engine

This is one of the central PhishGraph features.

The engine compares a new scan with historical observations.

Possible relationships:

```text
SAME_IP
SAME_NAMESERVER
SAME_ASN
SAME_REGISTRAR
SAME_TLS_SERIAL
OVERLAPPING_TLS_SAN
SAME_FAVICON_HASH
SIMILAR_PAGE_HASH
SAME_REDIRECT_TARGET
SIMILAR_DOMAIN_PATTERN
SAME_BRAND_TARGET
```

Each relation receives a weight.

Example initial weights:

```text
Same favicon hash             +25
Same TLS certificate serial   +25
Same redirect target          +20
Same uncommon nameserver      +15
Same IP                       +10
Same ASN                      +5
Same registrar                +3
Same targeted brand           +5
```

Weights are starting points only and should be tuned after testing.

Correlation result:

```json
{
  "related_domain": "example2.test",
  "score": 72,
  "relations": [
    "SAME_FAVICON_HASH",
    "SAME_NAMESERVER",
    "SAME_ASN"
  ]
}
```

Telegram output:

```text
🕸 CAMPAIGN CORRELATION

3 potentially related domains found.

example2.test
• Same favicon hash
• Same nameserver
• Same ASN
Correlation: 72/100
```

Do not call the group a confirmed attacker campaign unless there is external evidence supporting that conclusion. Prefer wording such as:

- “potentially related cluster”
- “shared infrastructure observed”
- “possible campaign relationship”

---

# 14. Risk Scoring Engine

The risk score measures suspiciousness.

Recommended range:

```text
0–100
```

Suggested classification:

```text
0–24   LOW
25–49  MODERATE
50–74  HIGH
75–100 CRITICAL
```

Example starting weights:

```text
Known malicious URL reputation        +35
Known phishing feed match             +30
Brand impersonation high similarity   +20
Domain age < 7 days                    +18
Domain age < 30 days                   +12
Punycode with brand similarity         +15
IP-address hostname                    +10
Suspicious login/payment keywords      +5
Cross-domain redirect chain            +5
Multiple suspicious redirects          +8
Invalid TLS                             +8
Self-signed TLS                         +5
High URL entropy                        +3
Related suspicious infrastructure      +15
```

Cap total at 100.

Risk results must include explanations.

Bad output:

```text
Risk: 86
```

Good output:

```text
Risk: 86/100 — CRITICAL

Main contributors:
+30 URLhaus phishing match
+20 brand impersonation similarity
+18 domain registered 3 days ago
+15 related suspicious infrastructure
+5 suspicious login keyword
```

---

# 15. Evidence Confidence Score

Risk and confidence are different.

Risk asks:

> How suspicious does the evidence appear?

Confidence asks:

> How much independent and reliable evidence supports the assessment?

Example confidence factors:

```text
Multiple independent threat-intel providers agree
Historical observations available
RDAP information available
DNS data available
TLS metadata available
Infrastructure correlation supported by multiple indicators
```

Confidence should decrease when:

- External providers are unavailable.
- Domain registration data is missing.
- Target could not be reached.
- Only weak heuristics are available.

Example:

```text
Risk: 82/100
Confidence: 31/100

Interpretation:
The URL exhibits several suspicious characteristics, but external evidence is limited.
```

---

# 16. Risk Drift / Monitoring

Command:

```text
/watch https://example.test
```

Purpose:

Re-check a URL or domain periodically and compare the result with previous observations.

Store snapshots:

```text
scan_id
timestamp
risk_score
confidence_score
provider_results
dns_snapshot
resolved_ips
tls_fingerprint
```

Possible notification:

```text
🚨 THREAT STATUS CHANGED

Domain: example.test
Previous risk: 34
Current risk: 77

Changes:
• Threat feed match added
• Resolved IP changed
• 2 additional suspicious-domain correlations found
```

For the first implementation, monitoring can run at conservative intervals such as every 6, 12, or 24 hours rather than continuously.

---

# 17. Telegram Bot Commands

Recommended initial commands:

```text
/start
/help
/analyze <url>
/domain <domain>
/dns <domain>
/ssl <domain>
/redirects <url>
/reputation <url>
/history
/report <scan_id>
/watch <url>
/unwatch <watch_id>
/watchlist
/about
```

Future commands:

```text
/graph <scan_id>
/cluster <domain>
/compare <domain1> <domain2>
/export <scan_id>
/settings
```

---

# 18. Telegram User Experience

## Start Message

```text
🛡 Welcome to PhishGraph

Send me a URL, suspicious message, or QR-code image.

I can analyze:
• URL structure
• Domain age
• DNS
• TLS
• Redirects
• Threat intelligence
• Brand impersonation
• Related infrastructure
• Historical risk changes

Use /help for commands.
```

## Scan Progress

For slow scans, edit one Telegram message rather than sending many messages.

Example:

```text
🔍 Analyzing URL...

✅ URL structure
✅ DNS
✅ TLS
⏳ Domain intelligence
⏳ Threat intelligence
⏳ Correlation
```

Then replace it with the final result.

---

# 19. Suggested Repository Structure

```text
phishgraph/
│
├── README.md
├── .env.example
├── .gitignore
├── docker-compose.yml
├── Dockerfile
├── pyproject.toml
├── requirements.txt
│
├── app/
│   ├── main.py
│   ├── config.py
│   ├── logging.py
│   │
│   ├── api/
│   │   ├── dependencies.py
│   │   ├── routes/
│   │   │   ├── health.py
│   │   │   ├── scans.py
│   │   │   ├── domains.py
│   │   │   ├── reports.py
│   │   │   └── watchlist.py
│   │   └── schemas/
│   │       ├── scan.py
│   │       ├── domain.py
│   │       └── report.py
│   │
│   ├── bot/
│   │   ├── bot.py
│   │   ├── handlers/
│   │   │   ├── start.py
│   │   │   ├── analyze.py
│   │   │   ├── domain.py
│   │   │   ├── dns.py
│   │   │   ├── ssl.py
│   │   │   ├── qr.py
│   │   │   ├── forwarded_message.py
│   │   │   ├── history.py
│   │   │   └── report.py
│   │   └── formatters/
│   │       ├── scan_result.py
│   │       └── errors.py
│   │
│   ├── analyzers/
│   │   ├── url_analyzer.py
│   │   ├── domain_analyzer.py
│   │   ├── dns_analyzer.py
│   │   ├── tls_analyzer.py
│   │   ├── redirect_analyzer.py
│   │   ├── brand_analyzer.py
│   │   ├── entropy_analyzer.py
│   │   ├── punycode_analyzer.py
│   │   ├── favicon_analyzer.py
│   │   └── message_analyzer.py
│   │
│   ├── threat_intel/
│   │   ├── base.py
│   │   ├── virustotal.py
│   │   ├── urlhaus.py
│   │   ├── otx.py
│   │   ├── safebrowsing.py
│   │   └── abuseipdb.py
│   │
│   ├── correlation/
│   │   ├── fingerprint.py
│   │   ├── correlation_engine.py
│   │   ├── graph_builder.py
│   │   └── similarity.py
│   │
│   ├── scoring/
│   │   ├── risk_engine.py
│   │   ├── confidence_engine.py
│   │   └── weights.py
│   │
│   ├── reports/
│   │   ├── builder.py
│   │   └── templates/
│   │       └── scan_report.html
│   │
│   ├── db/
│   │   ├── base.py
│   │   ├── session.py
│   │   ├── models/
│   │   │   ├── user.py
│   │   │   ├── scan.py
│   │   │   ├── domain.py
│   │   │   ├── dns_record.py
│   │   │   ├── tls_record.py
│   │   │   ├── threat_intel.py
│   │   │   ├── fingerprint.py
│   │   │   ├── correlation.py
│   │   │   └── watch.py
│   │   └── repositories/
│   │
│   ├── services/
│   │   ├── scan_service.py
│   │   ├── report_service.py
│   │   ├── watch_service.py
│   │   └── notification_service.py
│   │
│   └── security/
│       ├── url_safety.py
│       ├── rate_limit.py
│       └── secrets.py
│
├── migrations/
├── tests/
│   ├── unit/
│   ├── integration/
│   └── fixtures/
│
├── scripts/
│   ├── seed_brands.py
│   ├── create_admin.py
│   └── dev_run.sh
│
└── docs/
    ├── architecture.md
    ├── api.md
    ├── scoring.md
    └── development.md
```

---

# 20. Database Design

## users

```text
id
telegram_user_id
username
first_name
created_at
last_seen_at
is_blocked
```

## scans

```text
id
scan_uuid
user_id
original_url
normalized_url
domain
status
risk_score
risk_level
confidence_score
created_at
completed_at
```

## domains

```text
id
domain
punycode_domain
unicode_domain
created_date
updated_date
expires_date
registrar
first_seen_at
last_seen_at
```

## dns_records

```text
id
scan_id
record_type
name
value
ttl
```

## tls_records

```text
id
scan_id
issuer
subject
common_name
serial_number
valid_from
valid_until
hostname_valid
tls_version
certificate_hash
```

## redirects

```text
id
scan_id
hop_number
source_url
destination_url
status_code
```

## threat_intel_results

```text
id
scan_id
provider
provider_status
malicious
suspicious
provider_score
labels
reference_id
raw_json
created_at
```

## fingerprints

```text
id
scan_id
domain
ip_set
asn
nameserver_set
registrar
tls_serial
tls_issuer
favicon_hash
page_hash
redirect_domain_set
created_at
```

## correlations

```text
id
source_scan_id
target_scan_id
correlation_score
relationship_types
created_at
```

## scan_risk_factors

```text
id
scan_id
factor_code
factor_description
weight
evidence_source
```

## watches

```text
id
user_id
url
active
interval_hours
last_scan_at
next_scan_at
last_risk_score
created_at
```

---

# 21. API Design

## Health

```text
GET /health
```

## Scan

```text
POST /api/v1/scans
GET  /api/v1/scans/{scan_id}
GET  /api/v1/scans/{scan_id}/correlations
GET  /api/v1/scans/{scan_id}/report
```

Example request:

```json
{
  "url": "https://example.com"
}
```

## Domain

```text
GET /api/v1/domains/{domain}
GET /api/v1/domains/{domain}/history
GET /api/v1/domains/{domain}/cluster
```

## Watchlist

```text
POST   /api/v1/watchlist
GET    /api/v1/watchlist
DELETE /api/v1/watchlist/{id}
```

The Telegram bot may call service functions directly in a monolithic MVP. Keep API boundaries clean so that the future dashboard can reuse them.

---

# 22. Scan Pipeline

Implement one orchestration service.

Pseudo-flow:

```python
async def analyze_url(url, user):
    target = normalize_and_validate(url)

    local_features = analyze_url_features(target)

    results = await asyncio.gather(
        analyze_domain(target.domain),
        analyze_dns(target.domain),
        analyze_tls(target),
        analyze_redirects(target),
        query_threat_intel(target),
        return_exceptions=True,
    )

    brand = analyze_brand_similarity(target)
    fingerprint = build_fingerprint(results)
    correlations = correlate_with_history(fingerprint)

    risk = calculate_risk(
        local_features,
        results,
        brand,
        correlations,
    )

    confidence = calculate_confidence(
        results,
        correlations,
    )

    persist_scan(...)

    return build_report(...)
```

Rules:

- Use async I/O for network-bound tasks.
- Every module must have a timeout.
- One failed integration must not fail the whole scan.
- Normalize errors into structured result objects.
- Log failures without exposing secrets.

---

# 23. Caching Strategy

Redis can reduce API usage and improve response times.

Suggested cache durations:

```text
DNS                 10–30 minutes
RDAP                 12–24 hours
TLS                  1–6 hours
VirusTotal           based on provider limits / policy
URLhaus              short cache
Brand list           24 hours
Static configuration long-lived
```

Cache keys:

```text
phishgraph:dns:{domain}
phishgraph:rdap:{domain}
phishgraph:tls:{domain}:{port}
phishgraph:vt:url:{sha256}
```

Do not cache sensitive user data unnecessarily.

---

# 24. Security Requirements

This section is mandatory because PhishGraph itself processes attacker-controlled URLs.

## 24.1 SSRF Protection

Before every outbound request:

1. Parse hostname.
2. Reject unsupported schemes.
3. Resolve hostname.
4. Inspect every resolved IP.
5. Reject private, loopback, link-local, multicast, unspecified, and reserved ranges as appropriate.
6. Reject cloud metadata targets.
7. Re-check destination after every redirect.

Block examples:

```text
127.0.0.0/8
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
169.254.0.0/16
::1
fc00::/7
fe80::/10
```

Also protect against DNS rebinding by validating the actual destination address used for connection where possible.

## 24.2 Request Limits

Recommended starting limits:

```text
HTTP timeout:            5–10 seconds
Maximum redirects:       10
Maximum response body:   small bounded size
Maximum QR image size:   bounded
Maximum Telegram file:   bounded by bot policy
```

## 24.3 No Active Exploitation

PhishGraph should remain a defensive analysis platform.

The default project must not:

- Exploit websites.
- Attempt authentication bypass.
- Brute-force accounts.
- Perform aggressive vulnerability scans.
- Launch port scans across arbitrary hosts.
- Execute downloaded files.
- Execute JavaScript from remote sites.

Use passive intelligence and low-impact requests.

## 24.4 Secrets

Keep secrets in environment variables:

```text
TELEGRAM_BOT_TOKEN
DATABASE_URL
REDIS_URL
VIRUSTOTAL_API_KEY
OTX_API_KEY
GOOGLE_SAFE_BROWSING_API_KEY
ABUSEIPDB_API_KEY
```

Never commit `.env`.

---

# 25. Environment File

Example `.env.example`:

```env
APP_ENV=development
APP_NAME=PhishGraph
LOG_LEVEL=INFO

TELEGRAM_BOT_TOKEN=

DATABASE_URL=postgresql+asyncpg://phishgraph:phishgraph@postgres:5432/phishgraph
REDIS_URL=redis://redis:6379/0

VIRUSTOTAL_API_KEY=
OTX_API_KEY=
GOOGLE_SAFE_BROWSING_API_KEY=
ABUSEIPDB_API_KEY=

MAX_REDIRECTS=10
HTTP_TIMEOUT_SECONDS=8
MAX_RESPONSE_BYTES=1048576

ENABLE_QR_SCAN=true
ENABLE_WATCHLIST=true
ENABLE_PDF_REPORTS=true
```

---

# 26. Local Development Setup

## Prerequisites

Install:

- Git
- Python
- Docker Desktop or Docker Engine
- PostgreSQL if not using Docker
- Redis if not using Docker

## Clone

```bash
git clone <repository-url>
cd phishgraph
```

## Virtual Environment

Windows:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Linux/macOS:

```bash
python -m venv .venv
source .venv/bin/activate
```

## Install Dependencies

```bash
pip install -r requirements.txt
```

## Environment

```bash
cp .env.example .env
```

Fill API keys and Telegram token.

## Database Migration

```bash
alembic upgrade head
```

## Start Backend

```bash
uvicorn app.main:app --reload
```

## Start Bot

Depending on architecture:

```bash
python -m app.bot.bot
```

or run bot startup inside the FastAPI application lifecycle.

---

# 27. Docker Setup

Suggested services:

```text
api
bot
postgres
redis
worker (later)
```

Example development flow:

```bash
docker compose up --build
```

Health checks should exist for:

- API
- PostgreSQL
- Redis

---

# 28. Logging

Use structured logs.

Log:

- scan started
- scan completed
- provider timeout
- DNS failure
- TLS error
- risk result
- correlation count
- report generation failure

Do not log:

- Telegram bot token
- Provider API keys
- Authorization headers
- Complete raw secrets

Recommended log fields:

```text
timestamp
level
scan_id
user_id_internal
module
event
message
duration_ms
```

---

# 29. Error Handling

The bot must return understandable errors.

Examples:

```text
❌ Invalid URL
Please send a valid http:// or https:// URL.
```

```text
⚠ Partial Analysis
The domain was analyzed, but one threat-intelligence provider was unavailable.
```

```text
🛡 Request blocked
The destination resolves to an internal or restricted network address.
```

Do not expose Python tracebacks to Telegram users.

---

# 30. Testing Strategy

## Unit Tests

Test:

- URL parser
- private IP rejection
- redirect validation
- punycode handling
- entropy calculation
- brand similarity
- risk scoring
- confidence scoring
- correlation weighting

## Integration Tests

Test:

- PostgreSQL writes
- Redis cache
- Telegram handler → scan service
- mocked VirusTotal provider
- mocked URLhaus provider
- mocked RDAP response
- mocked DNS response

## Security Tests

Include explicit test cases for:

```text
http://127.0.0.1
http://localhost
http://10.0.0.1
http://169.254.169.254
IPv6 loopback
Redirect from public URL to private IP
DNS rebinding-like scenarios
Very large redirects
Malformed URLs
Extremely long URLs
Punycode edge cases
```

## Test Data

Use controlled fixtures and known public test domains where possible.

Never rely on live malicious infrastructure for automated tests.

---

# 31. Report Generation

Command:

```text
/report SCAN-2026-000123
```

Report sections:

1. Executive Summary
2. Submitted URL
3. Risk Score
4. Confidence Score
5. URL Heuristics
6. Domain Intelligence
7. DNS
8. TLS
9. Redirect Chain
10. Threat Intelligence
11. Brand Similarity
12. Infrastructure Fingerprint
13. Related Observations
14. Risk Factors
15. Analyst Notes / Disclaimer

The PDF should contain the timestamp and scan ID.

---

# 32. Future Web Dashboard

After the Telegram MVP is stable, build a dashboard.

Pages:

```text
Login
Overview
Scans
Scan Detail
Domains
Watchlist
Campaign Clusters
Infrastructure Graph
Threat Intel Status
Settings
```

Dashboard widgets:

- Total scans
- High-risk URLs
- Newly seen domains
- Top targeted brands
- Top correlated ASNs
- Top suspicious nameservers
- Risk distribution
- Scan trend
- Watchlist changes

Graph view:

```text
Domain
  │
  ├── IP
  ├── ASN
  ├── Nameserver
  ├── TLS Certificate
  ├── Favicon
  ├── Redirect Domain
  └── Related Domain
```

---

# 33. Implementation Roadmap

## Phase 0 — Project Initialization

Goal: create a clean foundation.

Tasks:

- Create repository.
- Add README.
- Add `.gitignore`.
- Create Python project.
- Configure FastAPI.
- Configure PostgreSQL.
- Configure Redis.
- Configure Alembic.
- Add Docker Compose.
- Add health endpoint.
- Add structured logging.
- Add configuration management.

Definition of Done:

```text
GET /health → 200 OK
PostgreSQL connected
Redis connected
Migrations working
Docker Compose starts successfully
```

---

## Phase 1 — Telegram MVP

Goal: accept URLs and return a basic scan result.

Implement:

- `/start`
- `/help`
- automatic URL detection
- `/analyze`
- user persistence
- scan ID generation
- progress message

Definition of Done:

```text
User sends URL
Bot acknowledges request
Scan record is created
Bot returns a structured response
```

---

## Phase 2 — Core URL Intelligence

Implement:

- URL normalization
- URL heuristic analyzer
- DNS analyzer
- RDAP/domain analyzer
- TLS analyzer
- redirect analyzer
- SSRF protection

Definition of Done:

The bot returns useful analysis without external threat-intelligence APIs.

---

## Phase 3 — Threat Intelligence

Implement providers independently:

1. VirusTotal
2. URLhaus
3. AlienVault OTX
4. Google Safe Browsing
5. AbuseIPDB for resolved public IPs

Definition of Done:

- Provider timeouts do not break scans.
- Provider responses are normalized.
- Provider evidence appears in the final report.

---

## Phase 4 — Risk and Confidence

Implement:

- risk factors table
- scoring weights
- risk engine
- confidence engine
- explainable output

Definition of Done:

Every score lists the factors that affected it.

---

## Phase 5 — Brand and Homograph Detection

Implement:

- brand dataset
- Levenshtein similarity
- Jaro-Winkler similarity
- typosquatting indicators
- punycode detection
- Unicode display safety

Definition of Done:

The bot can report potential brand similarity without overclaiming maliciousness.

---

## Phase 6 — Infrastructure Fingerprinting

Implement:

- fingerprint data model
- IP set
- ASN enrichment
- nameserver set
- registrar
- TLS fingerprint
- redirect-domain set
- favicon hash

Definition of Done:

Each completed scan produces one versioned fingerprint record.

---

## Phase 7 — Correlation Engine

Implement:

- historical fingerprint lookup
- relation types
- weighted relation scoring
- related-domain ranking
- correlation storage

Definition of Done:

A new scan can return previously observed domains sharing meaningful infrastructure indicators.

---

## Phase 8 — QR and Forwarded Message Analysis

Implement:

- image intake
- QR extraction
- URL extraction from message text
- basic urgency/lure keyword detection
- brand-name extraction
- combined message + URL report

Definition of Done:

User can forward a suspicious message or QR image and receive analysis without manually copying the URL.

---

## Phase 9 — Scan History and Reports

Implement:

- `/history`
- `/report`
- scan-detail endpoint
- HTML report
- PDF export

Definition of Done:

Historical scans are searchable by user and can be exported.

---

## Phase 10 — Watchlist and Risk Drift

Implement:

- `/watch`
- `/unwatch`
- `/watchlist`
- scheduled re-analysis
- risk-difference calculation
- change notification

Definition of Done:

The user receives a notification only when meaningful changes occur.

---

## Phase 11 — Campaign Graph

Implement:

- graph node model
- graph edge model
- graph-building service
- `/graph`
- JSON graph API

Later visualize using Cytoscape.js.

---

## Phase 12 — Production Hardening

Implement:

- rate limiting
- user quotas
- abuse protection
- API-key rotation process
- metrics
- health checks
- backups
- monitoring
- production Docker configuration
- reverse proxy
- TLS termination

---

# 34. Agent Development Instructions

This section is written specifically for an AI coding agent implementing the repository.

## General Rules

The coding agent must:

1. Work phase-by-phase.
2. Finish and test one phase before moving to the next.
3. Keep modules small and focused.
4. Use typed Python.
5. Use asynchronous I/O for network operations.
6. Add tests with every feature.
7. Never hardcode API keys.
8. Never weaken SSRF protections for convenience.
9. Never treat one heuristic as proof of maliciousness.
10. Preserve explainability for every score.
11. Avoid unnecessary dependencies.
12. Keep Telegram presentation separate from security-analysis logic.
13. Keep threat-intelligence providers replaceable.
14. Use database migrations for schema changes.
15. Update this README whenever architecture changes.

## Required Implementation Order

The agent should implement in this exact order unless a dependency forces a small adjustment:

```text
1. Configuration
2. Logging
3. Database
4. Health API
5. Telegram initialization
6. URL parsing
7. SSRF protection
8. URL heuristics
9. DNS
10. RDAP
11. TLS
12. Redirects
13. Scan orchestration
14. Persistence
15. Threat intelligence
16. Risk scoring
17. Confidence scoring
18. Brand detection
19. Fingerprinting
20. Correlation
21. QR/message analysis
22. Reports
23. Watchlist
24. Graph API
25. Production hardening
```

## Agent Completion Rule

For each feature, the agent must provide:

```text
Implementation
Tests
Error handling
Logging
Configuration
Documentation update
```

A feature is not complete if it only works in the happy path.

## Example Agent Task

```text
TASK: Implement DNS Analyzer

Requirements:
- Create app/analyzers/dns_analyzer.py
- Query A, AAAA, MX, NS, TXT, CNAME, SOA and CAA
- Use async-compatible execution
- Apply per-query timeout
- Normalize records into Pydantic schema
- Do not fail entire scan when one record type is missing
- Persist records
- Add unit tests
- Add integration test with mocked DNS responses
- Update README implementation checklist

Acceptance Criteria:
- Domain with A + MX records returns normalized result
- NXDOMAIN handled cleanly
- Timeout handled cleanly
- Missing MX is not treated as fatal
- No unhandled exception reaches Telegram
```

This pattern should be repeated for every implementation unit.

---

# 35. Suggested Development Checklist

## Foundation

- [ ] Repository initialized
- [ ] FastAPI running
- [ ] Telegram bot connected
- [ ] PostgreSQL connected
- [ ] Redis connected
- [ ] Alembic configured
- [ ] Docker Compose working
- [ ] Logging configured

## Core Analysis

- [ ] URL validation
- [ ] URL normalization
- [ ] SSRF protection
- [ ] URL heuristics
- [ ] Domain intelligence
- [ ] DNS analysis
- [ ] TLS analysis
- [ ] Redirect analysis

## Threat Intelligence

- [ ] VirusTotal
- [ ] URLhaus
- [ ] OTX
- [ ] Safe Browsing
- [ ] AbuseIPDB

## Detection

- [ ] Brand similarity
- [ ] Typosquatting
- [ ] Punycode detection
- [ ] Entropy analysis
- [ ] Risk engine
- [ ] Confidence engine

## Correlation

- [ ] Fingerprints
- [ ] Favicon hash
- [ ] Historical lookup
- [ ] Relation scoring
- [ ] Campaign clustering

## Telegram Features

- [ ] URL auto-detection
- [ ] `/analyze`
- [ ] `/domain`
- [ ] `/dns`
- [ ] `/ssl`
- [ ] `/redirects`
- [ ] `/history`
- [ ] `/report`
- [ ] QR scanner
- [ ] Forwarded-message analysis
- [ ] Watchlist

## Reporting

- [ ] Scan summary
- [ ] Detailed report
- [ ] PDF export
- [ ] Graph JSON

## Production

- [ ] Rate limiting
- [ ] API quotas
- [ ] Monitoring
- [ ] Backups
- [ ] Reverse proxy
- [ ] Production TLS
- [ ] Metrics
- [ ] CI/CD

---

# 36. Recommended Git Branch Strategy

Keep development simple:

```text
main
└── develop
    ├── feature/url-analyzer
    ├── feature/dns-analyzer
    ├── feature/tls-analyzer
    ├── feature/threat-intel
    ├── feature/risk-engine
    └── feature/correlation-engine
```

For an individual academic project, feature branches plus pull requests are enough.

Suggested commit style:

```text
feat: add asynchronous DNS analyzer
fix: block private IP redirects
feat: add VirusTotal provider adapter
test: add risk engine unit tests
docs: update correlation architecture
```

---

# 37. CI/CD

Recommended GitHub Actions pipeline:

```text
Push / Pull Request
        ↓
Lint
        ↓
Type Check
        ↓
Unit Tests
        ↓
Integration Tests
        ↓
Build Docker Image
```

Recommended tools:

- Ruff
- Black or Ruff formatter
- MyPy
- Pytest

Never run tests against live malicious websites in CI.

---

# 38. Performance Targets

Initial targets:

```text
Local heuristic analysis:       < 100 ms
DNS/RDAP/TLS phase:             usually a few seconds
Threat-intel phase:             provider-dependent
Telegram scan response target:  preferably < 15 seconds for normal scans
```

Use parallel requests where safe.

Do not sacrifice correctness or SSRF safety merely to reduce latency.

---

# 39. Rate Limiting

Rate-limit Telegram users to prevent abuse and API exhaustion.

Example policy:

```text
Anonymous/default user:
10 scans / 10 minutes

Watchlist:
10 active entries
```

Actual limits should depend on provider quotas and deployment resources.

Return:

```text
⏳ Rate limit reached.
Please try again later.
```

---

# 40. Privacy

PhishGraph processes URLs that may contain sensitive query parameters.

Recommended privacy behavior:

- Redact obvious tokens before logs.
- Avoid storing full query strings unless necessary.
- Allow a future privacy mode that stores only normalized domain-level data.
- Document retention periods.
- Allow scan deletion later.

Potential sensitive parameter names:

```text
token
access_token
auth
session
key
apikey
password
code
```

---

# 41. Limitations

PhishGraph must communicate limitations clearly.

The system cannot guarantee that a URL is safe or malicious.

Reasons include:

- Zero-day phishing infrastructure
- Newly created domains
- Delayed threat-intelligence detection
- Compromised legitimate websites
- Shared hosting
- CDN infrastructure
- Dynamic content
- Geofenced phishing pages
- Cloaking
- Provider outages

Recommended disclaimer:

```text
PhishGraph provides a security assessment based on observed indicators and available threat intelligence. Results are not a guarantee of safety or maliciousness.
```

---

# 42. Example Complete Scan

Input:

```text
https://paypa1-login.example/verify
```

Possible output:

```text
🚨 PHISHGRAPH ANALYSIS

Scan ID:
SCAN-2026-000123

URL:
https://paypa1-login.example/verify

Threat Risk:
87/100 — CRITICAL

Evidence Confidence:
79/100

────────────────────
URL INDICATORS
────────────────────
⚠ Brand-like string detected: PayPal
⚠ Suspicious keyword: login
⚠ Suspicious keyword: verify
⚠ Domain created recently

────────────────────
DOMAIN
────────────────────
Age: 3 days
Registrar: Example Registrar
Nameservers:
ns1.example-host.test
ns2.example-host.test

────────────────────
TLS
────────────────────
HTTPS: Enabled
Certificate: Valid
Issuer: Example CA
Expires in: 84 days

Note: valid TLS does not imply trustworthiness.

────────────────────
THREAT INTELLIGENCE
────────────────────
VirusTotal: suspicious detections present
URLhaus: listed
OTX: related indicators found

────────────────────
INFRASTRUCTURE
────────────────────
IP: 203.0.113.10
ASN: AS64500
Favicon fingerprint: matched historical observation

────────────────────
CAMPAIGN CORRELATION
────────────────────
3 potentially related domains found.

paypal-verify.example
• Same favicon
• Same nameserver
Correlation: 81/100

secure-paypal.example
• Same nameserver
• Same ASN
Correlation: 54/100

────────────────────
WHY THIS SCORE?
────────────────────
+30 phishing-feed evidence
+20 high brand similarity
+18 recently registered domain
+15 related suspicious infrastructure
+4 suspicious URL keywords

────────────────────
ASSESSMENT
────────────────────
High-risk indicators were observed across multiple independent categories.
Avoid submitting credentials unless the destination has been independently verified.
```

---

# 43. Final Product Vision

PhishGraph should evolve through three maturity levels.

## Level 1 — URL Security Bot

```text
Telegram
URL Analysis
DNS
TLS
Domain Age
Threat Intelligence
Risk Score
```

## Level 2 — Phishing Investigation Assistant

```text
Brand Detection
QR Analysis
Forwarded Message Analysis
Infrastructure Fingerprints
Historical Correlation
Confidence Score
PDF Reports
```

## Level 3 — Campaign Intelligence Platform

```text
Campaign Clustering
Risk Drift
Watchlists
Graph Visualization
SOC Dashboard
Analyst Workflows
Historical Infrastructure Tracking
```

The final project should therefore be presented not simply as a “Telegram phishing bot,” but as:

> **A defensive phishing intelligence and infrastructure-correlation platform with a Telegram investigation interface.**

---

# 44. Suggested Resume Description

> **PhishGraph — Phishing Infrastructure & Campaign Intelligence Platform**  
> Developed a Telegram-based defensive security platform that analyzes suspicious URLs using DNS, RDAP, TLS, redirect analysis, threat-intelligence APIs, brand-impersonation heuristics, explainable risk scoring, and evidence-confidence scoring. Built an infrastructure fingerprinting and historical-correlation engine to identify potentially related phishing domains and track risk changes over time.

---

# 45. Academic / Project Demonstration Flow

For a college demonstration:

1. Show the Telegram bot.
2. Submit a controlled test URL.
3. Show URL heuristics.
4. Show DNS/domain/TLS intelligence.
5. Show threat-intelligence aggregation.
6. Explain risk vs confidence.
7. Scan a second controlled URL with a shared test fingerprint.
8. Demonstrate correlation.
9. Show history.
10. Generate report.
11. Demonstrate QR scanning.
12. Show watchlist/risk drift using stored test data.

The demonstration should use controlled or benign test infrastructure wherever possible.

---

# 46. Definition of Done for the Full Project

PhishGraph is considered complete when:

- Telegram input works reliably.
- URL, domain, DNS, TLS, and redirect analysis are implemented.
- At least three threat-intelligence sources are integrated.
- Risk score is explainable.
- Confidence score is independent from risk.
- Brand and punycode checks work.
- Infrastructure fingerprints are stored.
- Historical correlation works.
- QR and forwarded-message analysis work.
- Scan history works.
- PDF reports work.
- Watchlist detects meaningful changes.
- SSRF protection is thoroughly tested.
- Secrets are protected.
- Docker deployment works.
- Unit and integration tests pass.
- Documentation matches implementation.

---

# 47. Final Instruction to the Coding Agent

Build PhishGraph incrementally. Do not attempt to generate the entire application in one uncontrolled step.

For every phase:

```text
Understand requirements
        ↓
Design interfaces
        ↓
Implement
        ↓
Write tests
        ↓
Run tests
        ↓
Fix errors
        ↓
Update documentation
        ↓
Commit
```

The project should prioritize:

```text
Security
Correctness
Explainability
Modularity
Testability
Usability
Performance
```

Not:

```text
Maximum number of features
Unverified “AI” classifications
Aggressive scanning
Black-box risk scores
```

PhishGraph should remain a transparent, defensive investigation tool that helps analysts understand suspicious links and relationships between observed phishing infrastructure.

---

## Project Name

**PhishGraph**

## Tagline

**Phishing Infrastructure & Campaign Intelligence Bot**

## Suggested One-Line Description

> Analyze suspicious links, explain phishing risk, and uncover related infrastructure directly from Telegram.

