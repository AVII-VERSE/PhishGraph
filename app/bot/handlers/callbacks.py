"""Interactive callback query handler for Telegram inline action buttons."""

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from app.db.session import async_session_factory
from app.logging import get_logger
from app.reports.report_generator import ReportGenerator
from app.services.graph_service import GraphService
from app.services.scan_service import ScanService
from app.services.watch_service import WatchService

logger = get_logger("phishgraph.bot.callbacks")


async def callback_query_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle tap events on Telegram inline keyboard buttons."""
    query = update.callback_query
    if not query or not query.data:
        return

    data = query.data
    user = query.from_user

    # 1. PDF Dossier Download: "pdf:<scan_uuid>"
    if data.startswith("pdf:"):
        scan_uuid = data.split(":", 1)[1]
        await query.answer("Generating executive PDF threat dossier...")

        session_factory = async_session_factory()
        async with session_factory() as session:
            scan_details = await ScanService.get_scan_full_details(session, scan_uuid)
            if not scan_details:
                if query.message:
                    await query.message.reply_text(f"❌ Scan `{scan_uuid}` not found.")
                return

            pdf_bytes = ReportGenerator.generate_pdf_report(scan_details)
            if query.message:
                await query.message.reply_document(
                    document=pdf_bytes,
                    filename=f"PhishGraph_Dossier_{scan_uuid}.pdf",
                    caption=(
                        f"📄 *Executive Threat Dossier*\n"
                        f"*Scan:* `{scan_uuid}`\n"
                        f"*Target:* `{scan_details['scan'].domain}`"
                    ),
                    parse_mode=ParseMode.MARKDOWN,
                )
        return

    # 2. Campaign Graph: "graph:<scan_uuid>"
    elif data.startswith("graph:"):
        scan_uuid = data.split(":", 1)[1]
        await query.answer("Building campaign correlation graph...")

        session_factory = async_session_factory()
        async with session_factory() as session:
            scan_details = await ScanService.get_scan_full_details(session, scan_uuid)
            if not scan_details:
                if query.message:
                    await query.message.reply_text(f"❌ Scan `{scan_uuid}` not found.")
                return

            graph_data = await GraphService.build_scan_graph(session, scan_details["scan"].id)
            summary = graph_data.get("summary", {})
            nodes_cnt = summary.get("total_nodes", 0)
            edges_cnt = summary.get("total_edges", 0)
            corr_cnt = summary.get("correlated_domains_count", 0)

            msg = (
                f"🕸 *CAMPAIGN GRAPH EXPLORATION*\n\n"
                f"*Root Domain:* `{scan_details['scan'].domain}`\n"
                f"*Graph Nodes:* {nodes_cnt} (Domains, IPs, ASNs, Nameservers)\n"
                f"*Correlation Edges:* {edges_cnt}\n"
                f"*Related Infrastructure Targets:* {corr_cnt}\n\n"
                f"_Graph JSON available via API at:_ `/api/v1/scans/{scan_uuid}/graph`"
            )
            if query.message:
                await query.message.reply_text(text=msg, parse_mode=ParseMode.MARKDOWN)
        return

    # 3. Watch for Drift: "watch:<domain>"
    elif data.startswith("watch:"):
        domain = data.split(":", 1)[1]
        await query.answer("Adding to watchlist...")

        session_factory = async_session_factory()
        async with session_factory() as session:
            db_user = await ScanService.get_or_create_user(
                session=session,
                telegram_user_id=user.id,
                username=user.username,
                first_name=user.first_name,
            )
            try:
                watch = await WatchService.add_watch(
                    session=session,
                    user_id=db_user.id,
                    raw_url=f"https://{domain}",
                    interval_hours=12,
                )
                if query.message:
                    await query.message.reply_text(
                        text=(
                            f"👁️ *WATCHLIST ACTIVE*\n\n"
                            f"Target `{watch.domain}` is now monitored every {watch.interval_hours}h.\n"
                            f"You will be alerted automatically if DNS, IP, risk, or threat indicators drift."
                        ),
                        parse_mode=ParseMode.MARKDOWN,
                    )
            except ValueError as e:
                if query.message:
                    await query.message.reply_text(f"⚠️ {e}")
        return

    # 4. Re-scan: "rescan:<scan_uuid>"
    elif data.startswith("rescan:"):
        scan_uuid = data.split(":", 1)[1]
        await query.answer("Initiating fresh scan...")

        from app.bot.handlers.analyze import process_target_url

        session_factory = async_session_factory()
        async with session_factory() as session:
            scan_details = await ScanService.get_scan_full_details(session, scan_uuid)
            if scan_details and query.message:
                url = scan_details["scan"].original_url
                await process_target_url(update, url)
        return

    # 5. STIX 2.1 JSON Export: "stix:<scan_uuid>"
    elif data.startswith("stix:"):
        scan_uuid = data.split(":", 1)[1]
        await query.answer("Exporting OASIS STIX 2.1 JSON bundle...")

        from app.reports.stix_exporter import export_scan_to_stix

        session_factory = async_session_factory()
        async with session_factory() as session:
            scan_details = await ScanService.get_scan_full_details(session, scan_uuid)
            if not scan_details:
                if query.message:
                    await query.message.reply_text(f"❌ Scan `{scan_uuid}` not found.")
                return

            stix_json_str = export_scan_to_stix(scan_details)
            if query.message:
                await query.message.reply_document(
                    document=stix_json_str.encode("utf-8"),
                    filename=f"PhishGraph_STIX21_{scan_uuid}.json",
                    caption=(
                        f"📦 *STIX 2.1 Threat Intelligence Bundle*\n"
                        f"*Scan ID:* `{scan_uuid}`\n"
                        f"*Target:* `{scan_details['scan'].domain}`\n"
                        f"_Standardized OASIS threat sharing bundle for SIEM / SOAR ingestion._"
                    ),
                    parse_mode=ParseMode.MARKDOWN,
                )
        return

