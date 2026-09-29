from secretmap.model import Consumer, Manifest
from secretmap.neo4j_sync import build_statements, prune_statements


def _sample_manifest() -> Manifest:
    m = Manifest("unused.json")
    m.add_secret("google-sa-receipts", backend="vaultwarden",
                 location="Google Service Account — rotes-receipts", rotation_period_days=90)
    m.add_consumer("google-sa-receipts", Consumer(
        host="LXC 414 (192.168.2.24)", path="/opt/agent/google-credentials.json",
        service="receipt-daily-report.timer", restart_required=False,
    ))
    m.mark_rotated("google-sa-receipts", "2026-09-28")
    return m


def test_build_statements_covers_secret_and_consumer():
    m = _sample_manifest()
    statements = build_statements(m)

    secret_stmts = [s for s in statements if s["statement"].startswith("MERGE (s:SecretmapSecret")]
    assert len(secret_stmts) == 1
    assert secret_stmts[0]["parameters"]["id"] == "google-sa-receipts"
    assert secret_stmts[0]["parameters"]["backend"] == "vaultwarden"

    edge_stmts = [s for s in statements if "CONSUMES" in s["statement"] and "MERGE" in s["statement"]]
    assert len(edge_stmts) == 1
    assert edge_stmts[0]["parameters"]["host"] == "LXC 414 (192.168.2.24)"
    assert edge_stmts[0]["parameters"]["path"] == "/opt/agent/google-credentials.json"
    assert edge_stmts[0]["parameters"]["service"] == "receipt-daily-report.timer"


def test_build_statements_empty_manifest_still_has_root():
    m = Manifest("unused.json")
    statements = build_statements(m)
    assert any("SecretmapRoot" in s["statement"] for s in statements)
    assert not any("SecretmapSecret" in s["statement"] for s in statements)


def test_prune_statements_reference_current_known_ids():
    m = _sample_manifest()
    statements = prune_statements(m)
    edge_prune = next(s for s in statements if "DELETE r" in s["statement"])
    assert ["LXC 414 (192.168.2.24)", "google-sa-receipts", "/opt/agent/google-credentials.json"] \
        in edge_prune["parameters"]["known_edges"]

    secret_prune = next(s for s in statements if "DETACH DELETE s" in s["statement"])
    assert "google-sa-receipts" in secret_prune["parameters"]["known_ids"]


def test_prune_statements_on_empty_manifest_keeps_nothing():
    m = Manifest("unused.json")
    statements = prune_statements(m)
    edge_prune = next(s for s in statements if "DELETE r" in s["statement"])
    assert edge_prune["parameters"]["known_edges"] == []
    secret_prune = next(s for s in statements if "DETACH DELETE s" in s["statement"])
    assert secret_prune["parameters"]["known_ids"] == []
