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
- **Telegram Native**: Intuitive Telegram bot interface supporting raw links, forwarded lure messages, and QR codes.

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

### 5. Run Backend
```bash
uvicorn app.main:app --reload
```
Check health at: `http://localhost:8000/health`

### 6. Run Tests
```bash
pytest -v
```

---

## Docker Deployment

```bash
docker compose up --build
```
This launches the FastAPI service, PostgreSQL 16 database, and Redis 7 cache.
