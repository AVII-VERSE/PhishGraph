"""Scan orchestration service managing user tracking and scan lifecycles."""

import asyncio
import json
import re
import uuid
from datetime import datetime, timezone
from typing import List, Optional, Tuple
from urllib.parse import urlparse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.analyzers.brand_analyzer import BrandAnalyzer, BrandImpersonationResult
from app.analyzers.dns_analyzer import DNSAnalysisResult, analyze_dns
from app.analyzers.domain_analyzer import DomainIntelligenceResult, analyze_domain_rdap
from app.analyzers.punycode_analyzer import PunycodeAnalysisResult, analyze_punycode_and_homographs
from app.analyzers.redirect_analyzer import RedirectChainResult, trace_redirect_chain
from app.analyzers.tls_analyzer import TLSAnalysisResult, inspect_tls
from app.analyzers.url_analyzer import URLFeatures, analyze_url_heuristics
from app.db.models.dns_record import DNSRecord
from app.db.models.domain import Domain
from app.db.models.redirect import RedirectRecord
from app.db.models.risk_factor import ScanRiskFactor
from app.db.models.scan import Scan
from app.db.models.threat_intel import ThreatIntelRecord
from app.db.models.tls_record import TLSRecord
from app.db.models.user import User
from app.logging import get_logger, scan_id_ctx, user_id_ctx
from app.scoring.confidence_engine import calculate_confidence_score
from app.scoring.risk_engine import RiskAssessmentResult, calculate_risk_score
from app.security.url_safety import validate_url_safety
from app.threat_intel.aggregator import ThreatIntelAggregator
from app.threat_intel.base import ThreatIntelResult

logger = get_logger("phishgraph.scan_service")

URL_REGEX = re.compile(
    r"https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::\d+)?(?:/[^\s]*)?",
    re.IGNORECASE,
)


def extract_urls_from_text(text: str) -> list[str]:
    """Extract all HTTP/HTTPS URLs present in a given string."""
    if not text:
        return []
    return URL_REGEX.findall(text)


def parse_and_validate_url(raw_url: str) -> Tuple[str, str]:
    """
    Validate and extract normalized URL and domain.
    Returns: (normalized_url, domain)
    Raises: ValueError if URL is invalid or scheme is unsupported.
    """
    cleaned = raw_url.strip()
    if not cleaned.startswith(("http://", "https://")):
        cleaned = "https://" + cleaned

    parsed = urlparse(cleaned)
    if not parsed.netloc:
        raise ValueError(f"Invalid URL structure: {raw_url}")

    domain = parsed.hostname or parsed.netloc.split(":")[0]
    domain = domain.lower()

    if "." not in domain and domain != "localhost":
        raise ValueError(f"Invalid domain format: {domain}")

    return cleaned, domain


def generate_scan_id() -> str:
    """Generate human-readable scan ID according to PhishGraph spec (e.g., SCAN-2026-000123)."""
    current_year = datetime.now(timezone.utc).year
    short_hash = uuid.uuid4().hex[:6].upper()
    return f"SCAN-{current_year}-{short_hash}"


class ScanService:
    """Service handling scan creation, execution, and user state."""

    @staticmethod
    async def get_or_create_user(
        session: AsyncSession,
        telegram_user_id: int,
        username: Optional[str] = None,
        first_name: Optional[str] = None,
    ) -> User:
        """Retrieve existing user or register a new one upon Telegram interaction."""
        stmt = select(User).where(User.telegram_user_id == telegram_user_id)
        result = await session.execute(stmt)
        user = result.scalar_one_or_none()

        if user:
            user.last_seen_at = datetime.now(timezone.utc)
            if username:
                user.username = username
            if first_name:
                user.first_name = first_name
            await session.commit()
            return user

        user = User(
            telegram_user_id=telegram_user_id,
            username=username,
            first_name=first_name,
            created_at=datetime.now(timezone.utc),
            last_seen_at=datetime.now(timezone.utc),
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)
        logger.info(f"Registered new Telegram user {telegram_user_id} (@{username})")
        return user

    @staticmethod
    async def create_scan(
        session: AsyncSession,
        raw_url: str,
        user_id: Optional[int] = None,
    ) -> Scan:
        """Parse target URL and persist a new Scan record in 'pending' status."""
        normalized_url, domain = parse_and_validate_url(raw_url)
        scan_uuid = generate_scan_id()

        scan = Scan(
            scan_uuid=scan_uuid,
            user_id=user_id,
            original_url=raw_url,
            normalized_url=normalized_url,
            domain=domain,
            status="pending",
            created_at=datetime.now(timezone.utc),
        )
        session.add(scan)
        await session.commit()
        await session.refresh(scan)

        domain_stmt = select(Domain).where(Domain.domain == domain)
        dom_res = await session.execute(domain_stmt)
        dom_record = dom_res.scalar_one_or_none()
        if not dom_record:
            dom_record = Domain(
                domain=domain,
                punycode_domain=domain,
                unicode_domain=domain,
                first_seen_at=datetime.now(timezone.utc),
                last_seen_at=datetime.now(timezone.utc),
            )
            session.add(dom_record)
            await session.commit()

        logger.info(f"Created scan {scan_uuid} for domain {domain}")
        return scan

    @staticmethod
    async def execute_scan(
        session: AsyncSession,
        scan_id: int,
        allow_private_in_testing: bool = False,
        threat_aggregator: Optional[ThreatIntelAggregator] = None,
        brand_analyzer: Optional[BrandAnalyzer] = None,
    ) -> Tuple[
        Scan,
        URLFeatures,
        Optional[DNSAnalysisResult],
        Optional[DomainIntelligenceResult],
        Optional[TLSAnalysisResult],
        Optional[RedirectChainResult],
        List[ThreatIntelResult],
        BrandImpersonationResult,
        PunycodeAnalysisResult,
        RiskAssessmentResult,
    ]:
        """Execute Phase 4/5 full analysis, brand spoof detection, and explainable scoring."""
        stmt = select(Scan).where(Scan.id == scan_id)
        result = await session.execute(stmt)
        scan = result.scalar_one_or_none()
        if not scan:
            raise ValueError(f"Scan with id {scan_id} not found")

        token_scan = scan_id_ctx.set(scan.scan_uuid)
        token_user = user_id_ctx.set(scan.user_id)

        try:
            scan.status = "in_progress"
            await session.commit()

            # 1. URL Heuristics, Punycode & Brand Analysis
            heuristics = analyze_url_heuristics(scan.normalized_url)
            puny_res = analyze_punycode_and_homographs(scan.domain)
            brand_engine = brand_analyzer or BrandAnalyzer()
            brand_res = brand_engine.analyze_domain(scan.domain)

            # 2. SSRF Check
            is_safe, ssrf_reason, resolved_ips = await validate_url_safety(
                scan.normalized_url,
                allow_private_in_testing=allow_private_in_testing,
            )

            dns_res: Optional[DNSAnalysisResult] = None
            rdap_res: Optional[DomainIntelligenceResult] = None
            tls_res: Optional[TLSAnalysisResult] = None
            redir_res: Optional[RedirectChainResult] = None
            ti_results: List[ThreatIntelResult] = []

            if not is_safe:
                # SSRF blocked -> Immediate critical risk
                risk_res = RiskAssessmentResult(
                    risk_score=95.0,
                    risk_level="CRITICAL",
                    factors=[],
                )
                scan.risk_score = risk_res.risk_score
                scan.risk_level = risk_res.risk_level
                scan.confidence_score = 95.0
                scan.status = "completed"
                scan.completed_at = datetime.now(timezone.utc)
                await session.commit()
                return (
                    scan,
                    heuristics,
                    dns_res,
                    rdap_res,
                    tls_res,
                    redir_res,
                    ti_results,
                    brand_res,
                    puny_res,
                    risk_res,
                )

            # 3. Asynchronous Multi-Analyzer Gathering
            aggregator = threat_aggregator or ThreatIntelAggregator()

            dns_task = analyze_dns(scan.domain)
            rdap_task = analyze_domain_rdap(scan.domain)
            tls_task = inspect_tls(scan.domain)
            redir_task = trace_redirect_chain(
                scan.normalized_url,
                allow_private_in_testing=allow_private_in_testing,
            )
            ti_task = aggregator.query_all(
                url=scan.normalized_url,
                domain=scan.domain,
                resolved_ips=resolved_ips,
            )

            gathered = await asyncio.gather(
                dns_task, rdap_task, tls_task, redir_task, ti_task, return_exceptions=True
            )

            # Process DNS
            if isinstance(gathered[0], DNSAnalysisResult):
                dns_res = gathered[0]
                for rec in dns_res.records:
                    session.add(
                        DNSRecord(
                            scan_id=scan.id,
                            record_type=rec.record_type,
                            name=rec.name,
                            value=rec.value,
                            ttl=rec.ttl,
                        )
                    )

            # Process RDAP
            if isinstance(gathered[1], DomainIntelligenceResult):
                rdap_res = gathered[1]
                dom_stmt = select(Domain).where(Domain.domain == scan.domain)
                dom_result = await session.execute(dom_stmt)
                dom = dom_result.scalar_one_or_none()
                if dom:
                    dom.created_date = rdap_res.created_date
                    dom.updated_date = rdap_res.updated_date
                    dom.expires_date = rdap_res.expires_date
                    dom.registrar = rdap_res.registrar
                    dom.last_seen_at = datetime.now(timezone.utc)

            # Process TLS
            if isinstance(gathered[2], TLSAnalysisResult):
                tls_res = gathered[2]
                session.add(
                    TLSRecord(
                        scan_id=scan.id,
                        issuer=tls_res.issuer,
                        subject=tls_res.subject,
                        common_name=tls_res.common_name,
                        serial_number=tls_res.serial_number,
                        valid_from=tls_res.valid_from,
                        valid_until=tls_res.valid_until,
                        hostname_valid=tls_res.hostname_matches,
                        tls_version=tls_res.tls_version,
                    )
                )

            # Process Redirects
            if isinstance(gathered[3], RedirectChainResult):
                redir_res = gathered[3]
                for hop in redir_res.hops:
                    session.add(
                        RedirectRecord(
                            scan_id=scan.id,
                            hop_number=hop.hop_number,
                            source_url=hop.source_url,
                            destination_url=hop.destination_url,
                            status_code=hop.status_code,
                        )
                    )

            # Process Threat Intelligence
            if isinstance(gathered[4], list):
                ti_results = gathered[4]
                for ti in ti_results:
                    session.add(
                        ThreatIntelRecord(
                            scan_id=scan.id,
                            provider=ti.provider,
                            provider_status=ti.status,
                            malicious=ti.malicious,
                            suspicious=ti.suspicious,
                            provider_score=ti.score,
                            labels=", ".join(ti.labels) if ti.labels else None,
                            reference_id=ti.raw_reference,
                            raw_json=json.dumps(ti.details) if ti.details else None,
                        )
                    )

            # 4. Explainable Scoring Engine
            risk_res = calculate_risk_score(
                heuristics=heuristics,
                dns_res=dns_res,
                rdap_res=rdap_res,
                tls_res=tls_res,
                redir_res=redir_res,
                ti_results=ti_results,
                brand_res=brand_res,
                puny_res=puny_res,
            )

            confidence_score = calculate_confidence_score(
                dns_res=dns_res,
                rdap_res=rdap_res,
                tls_res=tls_res,
                redir_res=redir_res,
                ti_results=ti_results,
            )

            # Persist Risk Factors for transparency & auditability
            for f in risk_res.factors:
                session.add(
                    ScanRiskFactor(
                        scan_id=scan.id,
                        factor_code=f.factor_code,
                        factor_description=f.factor_description,
                        weight=f.weight,
                        evidence_source=f.evidence_source,
                    )
                )

            scan.risk_score = risk_res.risk_score
            scan.risk_level = risk_res.risk_level
            scan.confidence_score = confidence_score
            scan.status = "completed"
            scan.completed_at = datetime.now(timezone.utc)

            await session.commit()
            await session.refresh(scan)
            logger.info(
                f"Scan {scan.scan_uuid} complete: risk={scan.risk_score} ({scan.risk_level}), "
                f"confidence={scan.confidence_score}, factors={len(risk_res.factors)}"
            )

            return (
                scan,
                heuristics,
                dns_res,
                rdap_res,
                tls_res,
                redir_res,
                ti_results,
                brand_res,
                puny_res,
                risk_res,
            )

        except Exception as exc:
            scan.status = "failed"
            await session.commit()
            logger.error(f"Scan {scan.scan_uuid} failed: {exc}", exc_info=True)
            raise
        finally:
            scan_id_ctx.reset(token_scan)
            user_id_ctx.reset(token_user)

    execute_mvp_scan = execute_scan
