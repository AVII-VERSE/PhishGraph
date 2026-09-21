"""Unit tests for DGA, ThreatFox, and MITRE ATT&CK integration."""

import pytest
from app.analyzers.dga_analyzer import analyze_dga
from app.analyzers.url_analyzer import URLFeatures
from app.scoring.mitre_mapper import MitreMapper
from app.threat_intel.threatfox import ThreatFoxProvider


def test_dga_analyzer_normal_domain():
    """Verify legitimate brand domain is not flagged as DGA."""
    res = analyze_dga("google.com")
    assert not res.is_dga_suspected
    assert res.dga_confidence < 0.50


def test_dga_analyzer_random_botnet_domain():
    """Verify high-entropy random domain triggers DGA suspicion."""
    res = analyze_dga("xj84z91kqp93b.xyz")
    assert res.is_dga_suspected
    assert res.dga_confidence >= 0.50
    assert len(res.signals) > 0


def test_mitre_mapping_technique_extraction():
    """Verify MITRE ATT&CK techniques are mapped from indicators."""
    heuristics = URLFeatures(
        original_url="https://paypa1-security.example/login",
        hostname="paypa1-security.example",
        url_length=35,
        hostname_length=23,
        path_length=6,
        subdomain_count=0,
        query_param_count=0,
        hyphen_count=1,
        digit_count=1,
        is_ip_hostname=False,
        has_at_symbol=False,
        has_double_slash_in_path=False,
        has_punycode=False,
        path_entropy=2.1,
        query_entropy=0.0,
    )
    techniques = MitreMapper.map_indicators(heuristics=heuristics)
    tech_ids = [t.technique_id for t in techniques]

    assert "T1566.002" in tech_ids  # Spearphishing Link
    assert "T1583.001" in tech_ids  # Acquire Domains


@pytest.mark.asyncio
async def test_threatfox_provider_initialization():
    """Verify ThreatFox provider properties."""
    provider = ThreatFoxProvider()
    assert provider.name == "threatfox"
