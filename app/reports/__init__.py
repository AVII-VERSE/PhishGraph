"""Reports module."""

from app.reports.report_generator import generate_html_report, generate_pdf_report

__all__ = [
    "generate_html_report",
    "generate_pdf_report",
]
