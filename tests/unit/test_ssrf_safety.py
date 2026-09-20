"""Unit tests for SSRF Protection and IP Safety Validation."""

import pytest
from app.security.url_safety import is_ip_allowed, validate_url_safety


def test_ip_allowed_validation():
    """Verify private, reserved, loopback, and cloud metadata IPs are rejected."""
    # Loopback
    assert is_ip_allowed("127.0.0.1") is False
    assert is_ip_allowed("127.0.0.53") is False
    assert is_ip_allowed("::1") is False

    # Private IPv4 RFC1918
    assert is_ip_allowed("10.0.0.1") is False
    assert is_ip_allowed("10.254.1.10") is False
    assert is_ip_allowed("172.16.0.1") is False
    assert is_ip_allowed("172.31.255.254") is False
    assert is_ip_allowed("192.168.1.1") is False
    assert is_ip_allowed("192.168.100.50") is False

    # Cloud Metadata (AWS / GCP / Azure)
    assert is_ip_allowed("169.254.169.254") is False
    assert is_ip_allowed("fd00:ec2::254") is False

    # Carrier-grade NAT
    assert is_ip_allowed("100.64.0.1") is False

    # Public Routable IPs
    assert is_ip_allowed("8.8.8.8") is True
    assert is_ip_allowed("1.1.1.1") is True
    assert is_ip_allowed("93.184.216.34") is True
    assert is_ip_allowed("2606:4700:4700::1111") is True


@pytest.mark.asyncio
async def test_validate_url_schemes():
    """Verify only HTTP and HTTPS schemes are allowed."""
    safe, reason, _ = await validate_url_safety("ftp://example.com/file.txt")
    assert safe is False
    assert "Unsupported scheme" in (reason or "")

    safe, reason, _ = await validate_url_safety("file:///etc/passwd")
    assert safe is False
    assert "Unsupported scheme" in (reason or "")

    safe, reason, _ = await validate_url_safety("javascript:alert(1)")
    assert safe is False


@pytest.mark.asyncio
async def test_validate_url_cloud_metadata():
    """Verify cloud metadata endpoints are immediately blocked."""
    safe, reason, _ = await validate_url_safety("http://169.254.169.254/latest/meta-data")
    assert safe is False
    assert "restricted" in (reason or "")

    safe, reason, _ = await validate_url_safety("http://metadata.google.internal/computeMetadata/v1/")
    assert safe is False
    assert "restricted hostname" in (reason or "")


@pytest.mark.asyncio
async def test_validate_url_direct_private_ip():
    """Verify direct private IP addresses are blocked."""
    safe, reason, _ = await validate_url_safety("http://192.168.1.1/admin")
    assert safe is False
    assert "private or restricted" in (reason or "")

    safe, reason, _ = await validate_url_safety("http://10.0.0.1:8080/internal")
    assert safe is False
    assert "private or restricted" in (reason or "")
