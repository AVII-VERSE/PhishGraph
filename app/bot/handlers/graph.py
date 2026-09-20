"""Campaign Graph Telegram command handler."""

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from app.db.session import async_session_factory
from app.logging import get_logger
from app.services.graph_service import CampaignGraphService
from app.services.scan_service import ScanService

logger = get_logger("phishgraph.bot.handlers.graph")


async def graph_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /graph <scan_id> command rendering infrastructure network connections."""
    if not update.effective_message:
        return

    args = context.args or []
    if not args:
        await update.effective_message.reply_text(
            text="ℹ️ *Usage:* `/graph <scan_id>`\n\nExample: `/graph SCAN-2026-000123`\n"
            "Use `/history` to view your recent scan IDs.",
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    scan_uuid = args[0].strip()
    session_factory = async_session_factory()
    async with session_factory() as session:
        details = await ScanService.get_scan_full_details(session, scan_uuid)

    if not details:
        await update.effective_message.reply_text(
            text=f"❌ *Scan Not Found*\n\nNo scan record found with ID `{scan_uuid}`.",
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    graph = CampaignGraphService.build_scan_graph(details)
    summary = graph["summary"]
    nodes = graph["nodes"]

    node_types: dict[str, int] = {}
    for n in nodes:
        t = n["data"]["type"]
        node_types[t] = node_types.get(t, 0) + 1

    lines = [
        "🕸 *CAMPAIGN INFRASTRUCTURE GRAPH*\n",
        f"*Target Domain:* `{summary['root_domain']}`",
        f"*Network Entities:* {summary['total_nodes']} nodes, {summary['total_edges']} relationships",
        "",
        "*Connected Infrastructure:*",
    ]

    for t, cnt in sorted(node_types.items()):
        label = t.replace("_", " ").title()
        lines.append(f"• {label}: {cnt}")

    lines.append("")
    lines.append("────────────────────")
    lines.append("🌐 *Cytoscape.js Graph JSON Endpoint:*")
    lines.append(f"`/api/v1/scans/{scan_uuid}/graph`")

    await update.effective_message.reply_text(
        text="\n".join(lines),
        parse_mode=ParseMode.MARKDOWN,
    )
