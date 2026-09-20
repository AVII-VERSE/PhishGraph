"""QR Code Analyzer module.

Extracts and validates URLs from uploaded images using OpenCV and Pillow
with strict scheme whitelisting.
"""

import io
import logging
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse
import cv2
import numpy as np
from PIL import Image

from app.services.scan_service import extract_urls_from_text, parse_and_validate_url

logger = logging.getLogger(__name__)


@dataclass
class QRCodeResult:
    """Result of QR code detection and URL extraction."""

    has_qr: bool = False
    raw_payload: Optional[str] = None
    extracted_url: Optional[str] = None
    domain: Optional[str] = None
    error: Optional[str] = None


class QRAnalyzer:
    """Detects and decodes QR codes from image data."""

    def __init__(self) -> None:
        self.detector = cv2.QRCodeDetector()

    def decode_image_bytes(self, image_bytes: bytes) -> QRCodeResult:
        """Decode image bytes and extract legitimate HTTP/HTTPS target URLs.

        Args:
            image_bytes: Raw binary image data (JPEG, PNG, WEBP, etc.)

        Returns:
            QRCodeResult with extracted URL or error explanation.
        """
        if not image_bytes:
            return QRCodeResult(error="Empty image payload")

        try:
            # 1. Open with Pillow to support all common formats safely
            pil_image = Image.open(io.BytesIO(image_bytes)).convert("RGB")
            np_image = np.array(pil_image)

            # Convert RGB to BGR for OpenCV
            cv_image = cv2.cvtColor(np_image, cv2.COLOR_RGB2BGR)

            # 2. Detect and decode QR Code
            decoded_text, points, _ = self.detector.detectAndDecode(cv_image)

            if not decoded_text or points is None:
                # Fallback: try OpenCV grayscale with contrast enhancement
                gray = cv2.cvtColor(cv_image, cv2.COLOR_BGR2GRAY)
                decoded_text, points, _ = self.detector.detectAndDecode(gray)

            if not decoded_text:
                return QRCodeResult(has_qr=False, error="No QR code detected in image")

            raw_payload = decoded_text.strip()
            logger.info("Decoded QR code payload: %s", raw_payload)

            # 3. Security Scheme Validation (Section 5.8)
            # Must reject dangerous/local schemes (file://, ftp://, javascript:, etc.)
            parsed = urlparse(raw_payload)
            if parsed.scheme and parsed.scheme.lower() not in ("http", "https"):
                return QRCodeResult(
                    has_qr=True,
                    raw_payload=raw_payload,
                    error=f"Unsupported or dangerous scheme '{parsed.scheme}://'. Only HTTP/HTTPS permitted.",
                )

            # 4. URL Extraction & Normalization
            urls = extract_urls_from_text(raw_payload)
            target_url = urls[0] if urls else raw_payload

            try:
                normalized_url, domain = parse_and_validate_url(target_url)
                return QRCodeResult(
                    has_qr=True,
                    raw_payload=raw_payload,
                    extracted_url=normalized_url,
                    domain=domain,
                )
            except ValueError:
                return QRCodeResult(
                    has_qr=True,
                    raw_payload=raw_payload,
                    error=f"QR code decoded payload is not a valid web URL: {raw_payload[:60]}",
                )

        except Exception as exc:
            logger.error("Failed to process QR image: %s", exc, exc_info=True)
            return QRCodeResult(error=f"Image processing error: {exc}")
