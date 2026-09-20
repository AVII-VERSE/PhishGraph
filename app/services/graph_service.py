"""Campaign Infrastructure Graph Service.

Constructs Cytoscape.js compatible node and edge models representing
infrastructure correlations, domain clustering, and threat pivots.
"""

from typing import Any, Dict, List
from app.logging import get_logger

logger = get_logger("phishgraph.graph_service")


class CampaignGraphService:
    """Builds interactive graph networks linking domains, IPs, ASNs, and certificates."""

    @staticmethod
    def build_scan_graph(scan_details: Dict[str, Any]) -> Dict[str, Any]:
        """Convert a scan investigation dictionary into Cytoscape.js JSON structure."""
        scan = scan_details.get("scan", {})
        root_domain = scan.get("domain", "unknown")
        root_node_id = f"domain:{root_domain}"

        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []
        seen_nodes: set[str] = set()

        def add_node(node_id: str, label: str, node_type: str, extra: Dict[str, Any] = None) -> None:
            if node_id not in seen_nodes:
                seen_nodes.add(node_id)
                data = {"id": node_id, "label": label, "type": node_type}
                if extra:
                    data.update(extra)
                nodes.append({"data": data})

        def add_edge(source: str, target: str, label: str) -> None:
            edge_id = f"{source}->{target}:{label}"
            edges.append({"data": {"id": edge_id, "source": source, "target": target, "label": label}})

        # 1. Root Domain Node
        add_node(
            root_node_id,
            root_domain,
            "root_domain",
            {"risk_score": scan.get("risk_score"), "risk_level": scan.get("risk_level")},
        )

        # 2. IP Nodes and Edges
        for r in scan_details.get("dns_records", []):
            if r.get("record_type") in ("A", "AAAA") and r.get("value"):
                ip_id = f"ip:{r['value']}"
                add_node(ip_id, r["value"], "ip")
                add_edge(root_node_id, ip_id, "RESOLVES_TO")

        # 3. Nameserver Nodes and Edges
        for r in scan_details.get("dns_records", []):
            if r.get("record_type") == "NS" and r.get("value"):
                ns_clean = r["value"].rstrip(".").lower()
                ns_id = f"ns:{ns_clean}"
                add_node(ns_id, ns_clean, "nameserver")
                add_edge(root_node_id, ns_id, "SERVICED_BY")

        # 4. ASN Node
        fp = scan_details.get("fingerprint")
        if fp and fp.get("asn"):
            asn_val = fp["asn"]
            asn_id = f"asn:{asn_val}"
            add_node(asn_id, asn_val, "asn")
            add_edge(root_node_id, asn_id, "HOSTED_IN")

        # 5. Favicon Hash Node
        if fp and fp.get("favicon_hash"):
            fav_val = fp["favicon_hash"]
            fav_id = f"favicon:{fav_val}"
            add_node(fav_id, fav_val, "favicon")
            add_edge(root_node_id, fav_id, "SHARES_FAVICON")

        # 6. TLS Serial Node
        tls = scan_details.get("tls_record")
        if tls and tls.get("serial_number"):
            serial = tls["serial_number"]
            cert_id = f"cert:{serial}"
            add_node(cert_id, f"Cert #{serial[:12]}...", "certificate")
            add_edge(root_node_id, cert_id, "USES_CERTIFICATE")

        # 7. Correlated Domains
        for corr in scan_details.get("correlations", []):
            target_id = f"scan:{corr.get('target_scan_id')}"
            score = corr.get("correlation_score", 0)
            relations = ", ".join(corr.get("relationship_types", []))
            add_node(target_id, f"Related Scan #{corr.get('target_scan_id')}", "correlated_scan", {"correlation_score": score})
            add_edge(root_node_id, target_id, f"CORRELATED ({score}/100)")

        return {
            "nodes": nodes,
            "edges": edges,
            "summary": {
                "root_domain": root_domain,
                "total_nodes": len(nodes),
                "total_edges": len(edges),
            },
        }
