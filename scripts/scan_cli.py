"""Command-line interface to test PhishGraph link intelligence directly without Telegram."""

import asyncio
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Ensure UTF-8 console output on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from app.bot.formatters.scan_result import format_scan_result
from app.db.session import async_session_factory, init_db
from app.services.scan_service import ScanService


async def run_cli_scan(target_url: str) -> None:
    """Execute scan and print formatted report in terminal."""
    print(f"[*] Initializing database and scanning target: {target_url} ...\n")
    await init_db()

    session_factory = async_session_factory()
    async with session_factory() as session:
        user = await ScanService.get_or_create_user(
            session=session,
            telegram_user_id=1,
            username="cli_analyst",
        )
        try:
            scan = await ScanService.create_scan(
                session=session,
                raw_url=target_url,
                user_id=user.id,
            )
        except ValueError as val_err:
            print(f"[!] Error: {val_err}")
            return

        (
            scan,
            heuristics,
            dns_res,
            rdap_res,
            tls_res,
            redir_res,
            ti_results,
            brand_res,
            puny_res,
            risk_res,
            correlation_res,
        ) = await ScanService.execute_scan(session=session, scan_id=scan.id)

        output = format_scan_result(
            scan=scan,
            heuristics=heuristics,
            dns_res=dns_res,
            rdap_res=rdap_res,
            tls_res=tls_res,
            redir_res=redir_res,
            ti_results=ti_results,
            brand_res=brand_res,
            puny_res=puny_res,
            risk_res=risk_res,
            correlation_res=correlation_res,
        )

        print(output)
        print("\n[+] Scan execution complete! Scan reference:", scan.scan_uuid)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scripts/scan_cli.py <url>")
        sys.exit(1)

    url_arg = sys.argv[1]
    asyncio.run(run_cli_scan(url_arg))
