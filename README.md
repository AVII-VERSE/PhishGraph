# PhishGraph

> **Phishing Infrastructure & Campaign Intelligence Telegram Bot**  
> A defensive cybersecurity project for analyzing suspicious URLs, correlating related infrastructure, detecting phishing indicators, and explaining *why* a link may be risky.

For full architectural documentation and design specifications, see [PHISHGRAPH_README.md](PHISHGRAPH_README.md).

---

## Features

- **Multi-layer Analysis**: Heuristic URL parsing, DNS resolution, RDAP domain registration intelligence, TLS certificate inspection, and safe redirect following with strict SSRF protection.
- **Threat Intelligence**: Aggregates signals from VirusTotal, URLhaus, AlienVault OTX, Google Safe Browsing, and AbuseIPDB.
- **Explainable Scoring**: Dual-score model featuring an explainable **Threat Risk Score (0–100)** and an independent **Evidence Confidence Score (0–100)** with factor-by-factor attribution.
- **Brand & Impersonation**: Levenshtein/Jaro-Winkler brand distance checks, typosquatting heuristics, and punycode/homograph detection.
- **Campaign Correlation**: Infrastructure fingerprinting linking shared IPs, ASNs, nameservers, TLS certs, and favicon hashes to uncover threat actor campaigns.
- **QR & Social Engineering**: Computer vision QR code extraction and forwarded lure message analysis detecting urgency and brand impersonation.
- **Reports & PDF Export**: Executive HTML summaries and downloadable publication-grade PDF investigation reports.
- **Watchlist & Risk Drift**: Automated periodic background re-scans alerting on infrastructure modifications, new threat feed detections, or score increases.
- **Campaign Graph**: Interactive Cytoscape.js compatible graph generation visualizing infrastructure nodes and relationship edges.
- **Production Hardened**: Token sliding-window rate limiting, user quotas, structured JSON logging, health checks, Prometheus/JSON metrics, and Nginx reverse proxy with security headers.

---

## Telegram Bot Commands

| Command | Description |
| :--- | :--- |
| `/start` | Launch bot and view security introduction |
| `/help` | Display command guide and analysis policies |
| `/analyze <url>` | Execute full multi-engine link analysis |
| `/domain <target>` | Query RDAP registration, domain age, and registrar |
| `/dns <domain>` | Inspect DNS A, AAAA, MX, TXT, and NS records |
| `/ssl <domain>` | Check TLS certificate validity, issuer, and expiry |
| `/redirects <url>` | Trace HTTP redirect hops with SSRF destination validation |
| `/history` | View your recent link scans and risk history |
| `/report <scan_id>` | Generate and download an executive PDF threat dossier |
| `/watch <url>` | Add target URL to periodic risk drift monitoring |
| `/unwatch <domain>` | Remove domain from active monitoring |
| `/watchlist` | List all monitored targets |
| `/graph <scan_id>` | Generate Cytoscape graph nodes and relationship edges |

---

## Quick Start (Local Development)

### 1. Prerequisites
- Python 3.11+
- (Optional) Docker & Docker Compose

### 2. Setup Virtual Environment
```bash
python -m venv .venv
# On Windows:
.\.venv\Scripts\Activate.ps1
# On Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt
```

### 3. Configure Environment
```bash
cp .env.example .env
```
Fill in your `TELEGRAM_BOT_TOKEN` and threat intelligence API keys.

### 4. Database Migrations
```bash
alembic upgrade head
```

### 5. Run Backend & Bot
```bash
uvicorn app.main:app --reload
```
Check health at: `http://localhost:8000/health`  
Check metrics at: `http://localhost:8000/metrics`

### 6. Run Tests
```bash
pytest -v
```

---

## Production Deployment

### Docker Compose with Nginx Reverse Proxy
```bash
docker compose -f docker-compose.prod.yml up -d --build
```
This deploys:
1. **Nginx Reverse Proxy**: Rate-limiting zones, SSL termination, CSP, and security headers.
2. **FastAPI Backend**: Multi-worker uvicorn API with rate-limiting middleware.
3. **Telegram Bot Worker**: Autonomous polling bot worker.
4. **PostgreSQL 16**: Relational storage with persistent volumes.
5. **Redis 7**: Distributed caching and sliding-window rate limiting.

### Automated Backups
```bash
python scripts/backup_db.py --retention-days 14
```
