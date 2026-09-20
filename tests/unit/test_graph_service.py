"""Unit tests for CampaignGraphService."""

from app.services.graph_service import CampaignGraphService


def test_build_scan_graph():
    """Verify Cytoscape graph node and edge generation."""
    sample_scan_details = {
        "scan": {
            "domain": "phish-network.test",
            "risk_score": 82.0,
            "risk_level": "HIGH",
        },
        "dns_records": [
            {"record_type": "A", "value": "198.51.100.12"},
            {"record_type": "NS", "value": "ns1.bulletproof-dns.test."},
        ],
        "tls_record": {
            "serial_number": "9876543210FEDCBA",
        },
        "fingerprint": {
            "asn": "AS64512",
            "favicon_hash": "mmh3:554433",
        },
        "correlations": [
            {"target_scan_id": 42, "correlation_score": 68, "relationship_types": ["SAME_FAVICON_HASH", "SAME_IP"]}
        ],
    }

    graph = CampaignGraphService.build_scan_graph(sample_scan_details)

    assert "nodes" in graph
    assert "edges" in graph
    assert "summary" in graph

    summary = graph["summary"]
    assert summary["root_domain"] == "phish-network.test"
    assert summary["total_nodes"] == 7  # root + ip + ns + asn + favicon + cert + corr_scan
    assert summary["total_edges"] == 6

    node_ids = [n["data"]["id"] for n in graph["nodes"]]
    assert "domain:phish-network.test" in node_ids
    assert "ip:198.51.100.12" in node_ids
    assert "ns:ns1.bulletproof-dns.test" in node_ids
    assert "asn:AS64512" in node_ids
    assert "favicon:mmh3:554433" in node_ids
    assert "cert:9876543210FEDCBA" in node_ids
    assert "scan:42" in node_ids

    edge_labels = [e["data"]["label"] for e in graph["edges"]]
    assert "RESOLVES_TO" in edge_labels
    assert "SERVICED_BY" in edge_labels
    assert "HOSTED_IN" in edge_labels
    assert "SHARES_FAVICON" in edge_labels
    assert "USES_CERTIFICATE" in edge_labels
    assert any("CORRELATED (68/100)" in lbl for lbl in edge_labels)
