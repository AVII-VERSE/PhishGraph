"""RDAP Domain Intelligence Analyzer."""

import json
from datetime import datetime, timezone
from typing import List, Optional
import httpx
from pydantic import BaseModel, Field
from app.cache import get_cache
from app.logging import get_logger

logger = get_logger("phishgraph.analyzers.domain")

RDAP_BOOTSTRAP_URL = "https://rdap.org/domain"


class DomainIntelligenceResult(BaseModel):
    """Normalized domain registration intelligence."""

    domain: str
    created_date: Optional[datetime] = None
    updated_date: Optional[datetime] = None
    expires_date: Optional[datetime] = None
    domain_age_days: Optional[int] = None
    expires_in_days: Optional[int] = None
    recently_registered: bool = False
    recently_updated: bool = False
    registrar: Optional[str] = None
    status: List[str] = Field(default_factory=list)
    nameservers: List[str] = Field(default_factory=list)
    signals: List[str] = Field(default_factory=list)


def parse_rdap_event_date(events: list[dict], action_type: str) -> Optional[datetime]:
    """Extract and parse an event action date from RDAP JSON."""
    for event in events:
        if event.get("eventAction") == action_type:
            raw_date = event.get("eventDate")
            if raw_date:
                try:
                    # Clean ISO format e.g. "2024-01-15T10:00:00Z"
                    cleaned = raw_date.replace("Z", "+00:00")
                    return datetime.fromisoformat(cleaned)
                except Exception:
                    pass
    return None


def calculate_age_and_signals(
    created_date: Optional[datetime],
    updated_date: Optional[datetime],
    expires_date: Optional[datetime],
) -> tuple[Optional[int], Optional[int], bool, bool, List[str]]:
    """Calculate age metrics and suspicious domain-age signals."""
    now = datetime.now(timezone.utc)
    age_days: Optional[int] = None
    expires_days: Optional[int] = None
    recently_registered = False
    recently_updated = False
    signals: List[str] = []

    if created_date:
        age_days = (now - created_date).days
        if age_days < 7:
            recently_registered = True
            signals.append(f"Domain registered very recently ({age_days} days ago — HIGH RISK indicator)")
        elif age_days < 30:
            recently_registered = True
            signals.append(f"Domain registered recently ({age_days} days ago — MODERATE signal)")
        elif age_days < 90:
            signals.append(f"Domain is relatively new ({age_days} days old)")

    if updated_date:
        update_days = (now - updated_date).days
        if update_days < 7:
            recently_updated = True
            signals.append("Domain registration was recently updated (<7 days ago)")

    if expires_date:
        expires_days = (expires_date - now).days
        if expires_days < 30:
            signals.append(f"Domain expiration date is near ({expires_days} days remaining)")

    return age_days, expires_days, recently_registered, recently_updated, signals


async def analyze_domain_rdap(
    domain: str,
    timeout: float = 4.0,
    http_client: Optional[httpx.AsyncClient] = None,
) -> DomainIntelligenceResult:
    """Query RDAP for domain registration data with Redis caching."""
    cache = await get_cache()
    cache_key = f"phishgraph:rdap:{domain.lower()}"

    # Check cache
    cached_data = await cache.get(cache_key)
    if cached_data:
        try:
            return DomainIntelligenceResult.model_validate_json(cached_data)
        except Exception:
            pass

    client = http_client or httpx.AsyncClient(timeout=timeout, follow_redirects=True)
    created: Optional[datetime] = None
    updated: Optional[datetime] = None
    expires: Optional[datetime] = None
    registrar: Optional[str] = None
    status_list: List[str] = []
    nameservers: List[str] = []

    try:
        url = f"{RDAP_BOOTSTRAP_URL}/{domain.lower()}"
        resp = await client.get(url, headers={"Accept": "application/rdap+json"})

        if resp.status_code == 200:
            data = resp.json()
            events = data.get("events", [])
            created = parse_rdap_event_date(events, "registration")
            updated = parse_rdap_event_date(events, "last changed")
            expires = parse_rdap_event_date(events, "expiration")

            status_list = data.get("status", [])

            # Extract registrar entity
            for entity in data.get("entities", []):
                roles = entity.get("roles", [])
                if "registrar" in roles:
                    vcard = entity.get("vcardArray", [])
                    if len(vcard) > 1:
                        for entry in vcard[1]:
                            if entry[0] == "fn" and len(entry) > 3:
                                registrar = entry[3]
                                break

            # Nameservers
            for ns in data.get("nameservers", []):
                ldh = ns.get("ldhName")
                if ldh:
                    nameservers.append(ldh.lower())

    except Exception as exc:
        logger.debug(f"RDAP query failed for domain {domain}: {exc}")
    finally:
        if http_client is None:
            await client.aclose()

    age_days, expires_days, recently_reg, recently_upd, signals = calculate_age_and_signals(
        created, updated, expires
    )

    result = DomainIntelligenceResult(
        domain=domain,
        created_date=created,
        updated_date=updated,
        expires_date=expires,
        domain_age_days=age_days,
        expires_in_days=expires_days,
        recently_registered=recently_reg,
        recently_updated=recently_upd,
        registrar=registrar,
        status=status_list,
        nameservers=nameservers,
        signals=signals,
    )

    # Cache for 12 hours
    try:
        await cache.set(cache_key, result.model_dump_json(), expire_seconds=43200)
    except Exception:
        pass

    return result
