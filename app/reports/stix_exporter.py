"""STIX 2.1 Threat Intelligence Exporter.

Converts PhishGraph scan observations, IOCs, and MITRE ATT&CK mappings
into OASIS STIX 2.1 compliant JSON bundles for SOC/SIEM integration.
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List


def export_scan_to_stix(scan_data: Dict[str, Any]) -> str:
    """Generate a valid OASIS STIX 2.1 JSON bundle from a scan object."""
    scan = scan_data.get("scan")
    if not scan:
        raise ValueError("Scan record is required to generate STIX 2.1 bundle.")

    scan_uuid = getattr(scan, "scan_uuid", "SCAN-UNKNOWN")
    domain = getattr(scan, "domain", "unknown.test")
    normalized_url = getattr(scan, "normalized_url", "") or getattr(scan, "original_url", "")
    risk_score = float(getattr(scan, "risk_score", 0.0) or 0.0)
    created_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    bundle_id = f"bundle--{uuid.uuid4()}"
    objects: List[Dict[str, Any]] = []

    # 1. STIX 2.1 Indicator (URL)
    url_indicator_id = f"indicator--{uuid.uuid4()}"
    objects.append({
        "type": "indicator",
        "spec_version": "2.1",
        "id": url_indicator_id,
        "created": created_at,
        "modified": created_at,
        "name": f"Malicious URL Indicator - {scan_uuid}",
        "description": f"PhishGraph detected URL with threat risk score {risk_score}/100",
        "indicator_types": ["malicious-activity", "phishing"],
        "pattern": f"[url:value = '{normalized_url}']",
        "pattern_type": "stix",
        "valid_from": created_at,
        "confidence": int(float(getattr(scan, "confidence_score", 80.0) or 80.0)),
    })

    # 2. STIX 2.1 Infrastructure (Domain)
    infra_id = f"infrastructure--{uuid.uuid4()}"
    objects.append({
        "type": "infrastructure",
        "spec_version": "2.1",
        "id": infra_id,
        "created": created_at,
        "modified": created_at,
        "name": domain,
        "description": f"Domain hosting suspected phishing infrastructure",
        "infrastructure_types": ["phishing", "domain"],
    })

    # 3. STIX 2.1 Attack Pattern (MITRE ATT&CK T1566.002)
    attack_id = f"attack-pattern--{uuid.uuid4()}"
    objects.append({
        "type": "attack-pattern",
        "spec_version": "2.1",
        "id": attack_id,
        "created": created_at,
        "modified": created_at,
        "name": "Spearphishing Link",
        "description": "Adversaries send malicious links to entice targets to visit a malicious website.",
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": "T1566.002",
                "url": "https://attack.mitre.org/techniques/T1566/002/",
            }
        ],
    })

    # 4. STIX 2.1 Relationship: Indicator indicates Infrastructure
    rel_id = f"relationship--{uuid.uuid4()}"
    objects.append({
        "type": "relationship",
        "spec_version": "2.1",
        "id": rel_id,
        "created": created_at,
        "modified": created_at,
        "relationship_type": "indicates",
        "source_ref": url_indicator_id,
        "target_ref": infra_id,
    })

    bundle = {
        "type": "bundle",
        "id": bundle_id,
        "objects": objects,
    }

    return json.dumps(bundle, indent=2)
