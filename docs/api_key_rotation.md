# API Key and Secret Rotation Runbook

This document details the standard operating procedure for rotating sensitive secrets and threat intelligence API credentials in PhishGraph without service interruption.

---

## 1. Principles of Secret Rotation

- **Zero Downtime:** Services should be updated via rolling restarts or environment reload where supported.
- **Principle of Least Privilege:** Verify new keys possess only read permissions where available (e.g. read-only threat feed access).
- **Grace Period:** Never revoke the active key until the replacement key has been verified against live health checks.

---

## 2. Rotation Procedures by Service

### 2.1 Telegram Bot Token (`TELEGRAM_BOT_TOKEN`)

1. Message `@BotFather` on Telegram.
2. Run `/token` and choose your bot.
3. Select **Revoke current token**. `@BotFather` will generate a new token and invalidate the old one.
4. Update the `.env` configuration or secret store:
   ```env
   TELEGRAM_BOT_TOKEN="new-telegram-bot-token"
   ```
5. Restart the bot container:
   ```bash
   docker compose restart bot
   ```
6. Send `/start` to verify the bot responds.

---

### 2.2 VirusTotal API Key (`VIRUSTOTAL_API_KEY`)

1. Log into your VirusTotal account: [virustotal.com](https://www.virustotal.com).
2. Go to your **Profile** → **API key**.
3. Generate a new API key.
4. Update the production `.env` file or environment variables:
   ```env
   VIRUSTOTAL_API_KEY="new-virustotal-api-key"
   ```
5. Reload the API and Bot services:
   ```bash
   docker compose restart api bot
   ```
6. Verify via `/metrics` or by executing a scan on a known benign domain (e.g., `https://example.com`).

---

### 2.3 AlienVault OTX API Key (`OTX_API_KEY`)

1. Log into the AlienVault OTX console: [otx.alienvault.com](https://otx.alienvault.com).
2. Navigate to **Settings** → **API Key** and generate a new key.
3. Update `.env`:
   ```env
   OTX_API_KEY="new-otx-api-key"
   ```
4. Restart application services:
   ```bash
   docker compose restart api bot
   ```

---

### 2.4 Google Safe Browsing Key (`GOOGLE_SAFE_BROWSING_API_KEY`)

1. Open Google Cloud Console: [console.cloud.google.com](https://console.cloud.google.com).
2. Navigate to **APIs & Services** → **Credentials**.
3. Create a new API Key for **Safe Browsing API v4**.
4. Restrict key usage to your server's outbound public IP addresses.
5. Update `.env`:
   ```env
   GOOGLE_SAFE_BROWSING_API_KEY="new-google-api-key"
   ```
6. Restart services and once verified, delete the old key in Google Cloud Console.

---

### 2.5 AbuseIPDB Key (`ABUSEIPDB_API_KEY`)

1. Log into AbuseIPDB: [abuseipdb.com/account/api](https://www.abuseipdb.com/account/api).
2. Create a new API Key.
3. Update `.env`:
   ```env
   ABUSEIPDB_API_KEY="new-abuseipdb-api-key"
   ```
4. Restart services and revoke the prior key.

---

### 2.6 Database Password (`DATABASE_URL` / `POSTGRES_PASSWORD`)

1. Connect to PostgreSQL via `psql`:
   ```sql
   ALTER USER phishgraph WITH PASSWORD 'NewStrongPassword123!';
   ```
2. Update `.env`:
   ```env
   POSTGRES_PASSWORD="NewStrongPassword123!"
   DATABASE_URL="postgresql+asyncpg://phishgraph:NewStrongPassword123!@postgres:5432/phishgraph"
   ```
3. Restart containers:
   ```bash
   docker compose restart api bot
   ```
4. Query `/health` to verify `database: "connected"`.

---

## 3. Verification Checklist

After rotating any secret, execute the following verification steps:

- [ ] Check `/health` endpoint: `curl -s http://localhost:8000/health | jq`
- [ ] Inspect logs for authentication errors: `docker compose logs --tail=100 api`
- [ ] Submit a test URL in Telegram and verify report displays correctly.
