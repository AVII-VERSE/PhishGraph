#!/usr/bin/env bash
# PhishGraph PostgreSQL Automated Backup Script
set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-./backups}"
RETENTION_DAYS="${RETENTION_DAYS:-14}"
TIMESTAMP=$(date -u +"%Y%m%d_%H%M%S")
FILENAME="phishgraph_backup_${TIMESTAMP}.sql.gz"

mkdir -p "${BACKUP_DIR}"

echo "[*] Starting PhishGraph database backup..."

if [ -n "${DATABASE_URL:-}" ]; then
  pg_dump "${DATABASE_URL}" | gzip > "${BACKUP_DIR}/${FILENAME}"
else
  pg_dump -U "${POSTGRES_USER:-phishgraph}" -h "${POSTGRES_HOST:-localhost}" -p "${POSTGRES_PORT:-5432}" "${POSTGRES_DB:-phishgraph}" | gzip > "${BACKUP_DIR}/${FILENAME}"
fi

echo "[+] Backup successfully created: ${BACKUP_DIR}/${FILENAME}"

echo "[*] Cleaning up backups older than ${RETENTION_DAYS} days..."
find "${BACKUP_DIR}" -type f -name "phishgraph_backup_*.sql.gz" -mtime +"${RETENTION_DAYS}" -exec rm -f {} +

echo "[+] Backup routine complete."
