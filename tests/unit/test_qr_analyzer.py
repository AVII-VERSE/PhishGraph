"""Unit tests for QR Code Analyzer."""

from unittest.mock import MagicMock
import numpy as np
from PIL import Image
import io
import pytest

from app.analyzers.qr_analyzer import QRAnalyzer


def _create_dummy_image_bytes() -> bytes:
    """Create a simple in-memory 100x100 PNG image."""
    img = Image.new("RGB", (100, 100), color=(255, 255, 255))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def test_qr_analyzer_empty_payload():
    """Verify empty bytes returns an error gracefully."""
    analyzer = QRAnalyzer()
    res = analyzer.decode_image_bytes(b"")
    assert res.has_qr is False
    assert res.error == "Empty image payload"


def test_qr_analyzer_no_qr_found():
    """Verify image without a QR code returns has_qr=False."""
    analyzer = QRAnalyzer()
    dummy_bytes = _create_dummy_image_bytes()

    res = analyzer.decode_image_bytes(dummy_bytes)
    assert res.has_qr is False
    assert "No QR code detected" in (res.error or "")


def test_qr_analyzer_valid_http_url():
    """Verify QR code containing a valid HTTP/HTTPS URL is parsed and normalized."""
    analyzer = QRAnalyzer()
    dummy_bytes = _create_dummy_image_bytes()

    # Mock OpenCV detector returning valid URL
    analyzer.detector = MagicMock()
    analyzer.detector.detectAndDecode.return_value = (
        "https://phish-secure.test/login?id=123",
        np.array([[[0, 0]]]),
        None,
    )

    res = analyzer.decode_image_bytes(dummy_bytes)
    assert res.has_qr is True
    assert res.extracted_url == "https://phish-secure.test/login?id=123"
    assert res.domain == "phish-secure.test"
    assert res.error is None


def test_qr_analyzer_rejects_dangerous_schemes():
    """Verify dangerous non-HTTP schemes are rejected according to Section 5.8."""
    analyzer = QRAnalyzer()
    dummy_bytes = _create_dummy_image_bytes()

    # file:// scheme injection attempt
    analyzer.detector = MagicMock()
    analyzer.detector.detectAndDecode.return_value = (
        "file:///etc/shadow",
        np.array([[[0, 0]]]),
        None,
    )

    res = analyzer.decode_image_bytes(dummy_bytes)
    assert res.has_qr is True
    assert res.extracted_url is None
    assert "dangerous scheme 'file://'" in (res.error or "")

    # ftp:// scheme
    analyzer.detector.detectAndDecode.return_value = (
        "ftp://evil.test/exploit",
        np.array([[[0, 0]]]),
        None,
    )

    res_ftp = analyzer.decode_image_bytes(dummy_bytes)
    assert res_ftp.has_qr is True
    assert res_ftp.extracted_url is None
    assert "dangerous scheme 'ftp://'" in (res_ftp.error or "")
