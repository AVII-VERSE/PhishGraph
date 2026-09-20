"""Unit tests for Campaign Correlation Engine."""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession
from app.correlation.correlation_engine import (
    CorrelationEngine,
    WEIGHT_SAME_ASN,
    WEIGHT_SAME_BRAND_TARGET,
    WEIGHT_SAME_FAVICON_HASH,
    WEIGHT_SAME_GENERIC_NAMESERVER,
    WEIGHT_SAME_IP,
    WEIGHT_SAME_NAMESERVER,
    WEIGHT_SAME_REDIRECT_TARGET,
    WEIGHT_SAME_REGISTRAR,
    WEIGHT_SAME_TLS_SERIAL,
)
from app.correlation.fingerprint import FingerprintData
from app.db.models.correlation import Correlation
from app.db.models.fingerprint import Fingerprint
from app.db.models.scan import Scan


def test_compare_identical_domain_returns_none():
    """Verify engine ignores scans of the exact same domain."""
    engine = CorrelationEngine(min_score_threshold=10)
    fp1 = FingerprintData(scan_id=1, domain="evil.example")
    fp2 = FingerprintData(scan_id=2, domain="evil.example")
    assert engine.compare_fingerprints(fp1, fp2) is None


def test_compare_fingerprints_weights():
    """Verify relationship evaluation and individual weights."""
    engine = CorrelationEngine(min_score_threshold=1)

    base = FingerprintData(
        scan_id=1,
        domain="alpha.example",
        favicon_hash="mmh3:12345",
        tls_serial="ABCDEF123456",
        redirect_domain_set=["redirect-gateway.test"],
        nameserver_set=["ns1.attacker-dns.test"],
        ip_set=["198.51.100.10"],
        asn="AS65001",
        registrar="BadRegistrar Inc",
        brand_target="paypal",
    )

    # 1. Match Favicon only
    target_favicon = FingerprintData(
        scan_id=2,
        domain="beta.example",
        favicon_hash="mmh3:12345",
    )
    res = engine.compare_fingerprints(base, target_favicon)
    assert res is not None
    assert res.score == WEIGHT_SAME_FAVICON_HASH
    assert "SAME_FAVICON_HASH" in res.relations

    # 2. Match TLS Serial only
    target_tls = FingerprintData(
        scan_id=3,
        domain="gamma.example",
        tls_serial="ABCDEF123456",
    )
    res = engine.compare_fingerprints(base, target_tls)
    assert res is not None
    assert res.score == WEIGHT_SAME_TLS_SERIAL
    assert "SAME_TLS_SERIAL" in res.relations

    # 3. Match generic vs custom nameserver
    target_custom_ns = FingerprintData(
        scan_id=4,
        domain="delta.example",
        nameserver_set=["ns1.attacker-dns.test"],
    )
    res = engine.compare_fingerprints(base, target_custom_ns)
    assert res.score == WEIGHT_SAME_NAMESERVER

    # Generic NS gives lower score
    fp_generic1 = FingerprintData(scan_id=5, domain="a.test", nameserver_set=["ns1.cloudflare.com"])
    fp_generic2 = FingerprintData(scan_id=6, domain="b.test", nameserver_set=["ns1.cloudflare.com"])
    res_generic = engine.compare_fingerprints(fp_generic1, fp_generic2)
    assert res_generic.score == WEIGHT_SAME_GENERIC_NAMESERVER

    # 4. Multi-match capped at 100
    res_full = engine.compare_fingerprints(base, base.__class__(
        scan_id=99,
        domain="cluster-clone.example",
        favicon_hash=base.favicon_hash,
        tls_serial=base.tls_serial,
        redirect_domain_set=base.redirect_domain_set,
        nameserver_set=base.nameserver_set,
        ip_set=base.ip_set,
        asn=base.asn,
        registrar=base.registrar,
        brand_target=base.brand_target,
    ))
    assert res_full is not None
    assert res_full.score == 100
    assert len(res_full.relations) == 8


def test_threshold_filtering():
    """Verify matches below min_score_threshold are omitted."""
    engine = CorrelationEngine(min_score_threshold=20)
    fp1 = FingerprintData(scan_id=1, domain="d1.test", asn="AS1234")  # ASN is +5
    fp2 = FingerprintData(scan_id=2, domain="d2.test", asn="AS1234")
    # Score is 5, threshold is 20 -> should return None
    assert engine.compare_fingerprints(fp1, fp2) is None


@pytest.mark.asyncio
async def test_correlation_engine_db_workflow(db_session: AsyncSession):
    """Verify correlation engine queries historical fingerprints and persists relationships."""
    # Seed 2 previous scans
    scan1 = Scan(
        scan_uuid="SCAN-2026-000001",
        domain="first-phish.test",
        original_url="https://first-phish.test",
        normalized_url="https://first-phish.test",
        status="completed",
    )
    scan2 = Scan(
        scan_uuid="SCAN-2026-000002",
        domain="second-phish.test",
        original_url="https://second-phish.test",
        normalized_url="https://second-phish.test",
        status="completed",
    )
    db_session.add_all([scan1, scan2])
    await db_session.commit()
    await db_session.refresh(scan1)
    await db_session.refresh(scan2)

    # Historical fingerprints
    fp1 = Fingerprint(
        scan_id=scan1.id,
        domain=scan1.domain,
        ip_set=["192.0.2.1"],
        asn="AS64496",
        nameserver_set=["ns1.evil-cluster.test"],
        tls_serial="1122334455",
        favicon_hash="mmh3:999888777",
        redirect_domain_set=["landing.test"],
    )
    db_session.add(fp1)
    await db_session.commit()

    # New scan
    scan3 = Scan(
        scan_uuid="SCAN-2026-000003",
        domain="third-phish.test",
        original_url="https://third-phish.test",
        normalized_url="https://third-phish.test",
        status="completed",
    )
    db_session.add(scan3)
    await db_session.commit()
    await db_session.refresh(scan3)

    current_fp = FingerprintData(
        scan_id=scan3.id,
        domain=scan3.domain,
        ip_set=["192.0.2.1"],  # +10
        nameserver_set=["ns1.evil-cluster.test"],  # +15
        favicon_hash="mmh3:999888777",  # +25 -> Total 50
    )

    engine = CorrelationEngine(min_score_threshold=15)
    result = await engine.correlate(current=current_fp, session=db_session, persist=True)

    assert result.total_matches == 1
    match = result.matches[0]
    assert match.related_domain == "first-phish.test"
    assert match.related_scan_id == scan1.id
    assert match.score == 50
    assert "SAME_FAVICON_HASH" in match.relations
    assert "SAME_NAMESERVER" in match.relations
    assert "SAME_IP" in match.relations

    # Check that Correlation record was persisted
    from sqlalchemy import select
    corr_stmt = select(Correlation).where(Correlation.source_scan_id == scan3.id)
    corr_res = await db_session.execute(corr_stmt)
    persisted = corr_res.scalar_one_or_none()
    assert persisted is not None
    assert persisted.target_scan_id == scan1.id
    assert persisted.correlation_score == 50
    assert "SAME_FAVICON_HASH" in persisted.relationship_types
