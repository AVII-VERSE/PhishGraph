"""Database backup automation script for PhishGraph (Section 27 & 35)."""

import argparse
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def backup_database(
    database_url: str,
    output_dir: Path,
    retention_days: int = 14,
) -> Path:
    """Execute pg_dump or SQLite copy and maintain retention policy."""
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    if "sqlite" in database_url.lower():
        # Handle SQLite file backup
        db_path_str = database_url.split(":///")[-1]
        db_path = Path(db_path_str)
        if not db_path.exists():
            raise FileNotFoundError(f"SQLite database file not found: {db_path}")

        target_file = output_dir / f"phishgraph_sqlite_backup_{timestamp}.db"
        import shutil

        shutil.copy2(db_path, target_file)
        print(f"SQLite backup successfully created: {target_file}")
        return target_file
    else:
        # Handle PostgreSQL backup via pg_dump
        target_file = output_dir / f"phishgraph_pg_backup_{timestamp}.sql.gz"
        cmd = f"pg_dump {database_url} | gzip > {target_file}"
        print(f"Running database backup command: {cmd}")
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if res.returncode != 0:
            raise RuntimeError(f"Database backup failed: {res.stderr}")

        print(f"PostgreSQL backup successfully created: {target_file}")

        # Enforce retention policy
        now_ts = datetime.now(timezone.utc).timestamp()
        for f in output_dir.glob("phishgraph_*_backup_*"):
            if f.is_file():
                age_days = (now_ts - f.stat().st_mtime) / 86400
                if age_days > retention_days:
                    print(f"Purging old backup: {f.name} ({age_days:.1f} days old)")
                    f.unlink()

        return target_file


def main() -> None:
    parser = argparse.ArgumentParser(description="PhishGraph database backup utility")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("./backups"),
        help="Target directory for backup archives",
    )
    parser.add_argument(
        "--retention-days",
        type=int,
        default=14,
        help="Number of days to keep backup archives",
    )
    args = parser.parse_args()

    db_url = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./phishgraph.db")
    try:
        backup_database(db_url, args.output_dir, args.retention_days)
    except Exception as exc:
        print(f"Backup failed: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
