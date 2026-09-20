"""Scan investigation API endpoints."""

from typing import Any, Dict
from fastapi import APIRouter, HTTPException, Response, status
from fastapi.responses import HTMLResponse

from app.db.session import async_session_factory
from app.reports.report_generator import generate_html_report, generate_pdf_report
from app.services.scan_service import ScanService

router = APIRouter(prefix="/scans", tags=["scans"])


@router.get(
    "/{scan_uuid}",
    summary="Get Scan Details",
    description="Retrieve structured investigation findings, DNS, TLS, redirects, and correlations for a scan.",
)
async def get_scan_details(scan_uuid: str) -> Dict[str, Any]:
    session_factory = async_session_factory()
    async with session_factory() as session:
        details = await ScanService.get_scan_full_details(session, scan_uuid)
        if not details:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scan with ID '{scan_uuid}' was not found.",
            )
        return details


@router.get(
    "/{scan_uuid}/report",
    response_class=HTMLResponse,
    summary="Get HTML Investigation Report",
    description="Renders a standalone, responsive HTML investigation report for a completed scan.",
)
async def get_scan_html_report(scan_uuid: str) -> HTMLResponse:
    session_factory = async_session_factory()
    async with session_factory() as session:
        details = await ScanService.get_scan_full_details(session, scan_uuid)
        if not details:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scan with ID '{scan_uuid}' was not found.",
            )
        html_content = generate_html_report(details)
        return HTMLResponse(content=html_content)


@router.get(
    "/{scan_uuid}/pdf",
    summary="Download Investigation PDF",
    description="Generates and downloads a compiled PDF threat intelligence investigation report.",
)
async def get_scan_pdf(scan_uuid: str) -> Response:
    session_factory = async_session_factory()
    async with session_factory() as session:
        details = await ScanService.get_scan_full_details(session, scan_uuid)
        if not details:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scan with ID '{scan_uuid}' was not found.",
            )
        pdf_bytes = generate_pdf_report(details)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=PhishGraph_{scan_uuid}.pdf"},
        )


@router.get(
    "/{scan_uuid}/graph",
    summary="Get Campaign Graph JSON",
    description="Returns Cytoscape.js compatible graph nodes and edges representing infrastructure relationships.",
)
async def get_scan_graph(scan_uuid: str) -> Dict[str, Any]:
    from app.services.graph_service import CampaignGraphService

    session_factory = async_session_factory()
    async with session_factory() as session:
        details = await ScanService.get_scan_full_details(session, scan_uuid)
        if not details:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scan with ID '{scan_uuid}' was not found.",
            )
        return CampaignGraphService.build_scan_graph(details)

