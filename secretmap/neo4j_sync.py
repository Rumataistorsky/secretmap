"""Optional Neo4j graph sync for secretmap.

secretmap's core is a flat JSON manifest on purpose (see README: "not a
database"). But once a homelab/fleet has enough secrets and hosts that
questions like "what breaks if I take down this whole host" matter, a flat
file stops being fun to query by hand. This module pushes the same manifest
into an existing Neo4j instance as a graph, using ONLY Neo4j's HTTP
transactional Cypher endpoint via the standard library — no `neo4j` driver
dependency, so the zero-dependency install story stays intact.

Every node/relationship this module writes is namespaced with a
`Secretmap*` label so it never collides with unrelated data already living
in a shared Neo4j instance (e.g. a knowledge graph used for something else
entirely). The sync is idempotent: re-running it after manifest changes
converges the graph to match, via MERGE, without duplicating nodes.

Graph shape:

    (:SecretmapSecret {id, backend, location, rotation_period_days, last_rotated})
    (:SecretmapHost {name})
    (:SecretmapHost)-[:CONSUMES {path, service, restart_required, last_verified}]->(:SecretmapSecret)

Example queries once synced:

    // What breaks if I delete/rotate this secret?
    MATCH (h:SecretmapHost)-[c:CONSUMES]->(s:SecretmapSecret {id: "google-sa-receipts"})
    RETURN h.name, c.path, c.service

    // What breaks if this whole host goes down?
    MATCH (h:SecretmapHost {name: "LXC 414 (192.168.2.24)"})-[:CONSUMES]->(s:SecretmapSecret)
    RETURN s.id, s.backend, s.location

    // Secrets nobody has verified in the last 30 days
    MATCH (h:SecretmapHost)-[c:CONSUMES]->(s:SecretmapSecret)
    WHERE c.last_verified IS NULL OR date(c.last_verified) < date() - duration('P30D')
    RETURN s.id, h.name, c.path
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from base64 import b64encode

from .model import Manifest


class Neo4jSyncError(Exception):
    pass


def _run_statements(http_url: str, user: str, password: str, statements: list[dict]) -> dict:
    """POST a list of {statement, parameters} to Neo4j's HTTP tx/commit endpoint."""
    body = json.dumps({"statements": statements}).encode("utf-8")
    auth = b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
    req = urllib.request.Request(
        http_url.rstrip("/") + "/db/neo4j/tx/commit",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Basic {auth}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            result = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raise Neo4jSyncError(f"Neo4j HTTP {e.code}: {e.read().decode('utf-8', 'replace')}") from e
    except urllib.error.URLError as e:
        raise Neo4jSyncError(f"could not reach Neo4j at {http_url}: {e.reason}") from e

    if result.get("errors"):
        raise Neo4jSyncError(f"Neo4j reported errors: {result['errors']}")
    return result


def build_statements(manifest: Manifest) -> list[dict]:
    """Build the idempotent MERGE statements for the whole manifest."""
    statements: list[dict] = [
        {
            "statement": "MERGE (:SecretmapRoot {id: 'secretmap'})",
            "parameters": {},
        }
    ]

    for secret_id, s in manifest.secrets.items():
        statements.append({
            "statement": (
                "MERGE (s:SecretmapSecret {id: $id}) "
                "SET s.backend = $backend, s.location = $location, "
                "s.rotation_period_days = $rotation_period_days, s.last_rotated = $last_rotated"
            ),
            "parameters": {
                "id": secret_id,
                "backend": s.backend,
                "location": s.location,
                "rotation_period_days": s.rotation_period_days,
                "last_rotated": s.last_rotated,
            },
        })
        for c in s.consumers:
            statements.append({
                "statement": (
                    "MERGE (h:SecretmapHost {name: $host}) "
                    "MERGE (s:SecretmapSecret {id: $id}) "
                    "MERGE (h)-[r:CONSUMES {path: $path}]->(s) "
                    "SET r.service = $service, r.restart_required = $restart_required, "
                    "r.last_verified = $last_verified, r.notes = $notes"
                ),
                "parameters": {
                    "host": c.host,
                    "id": secret_id,
                    "path": c.path,
                    "service": c.service,
                    "restart_required": c.restart_required,
                    "last_verified": c.last_verified,
                    "notes": c.notes,
                },
            })
    return statements


def prune_statements(manifest: Manifest) -> list[dict]:
    """Remove CONSUMES edges/hosts/secrets no longer present in the manifest.

    Keeps the graph converged with the manifest even after entries are
    removed from the JSON (not just added).
    """
    known_secret_ids = list(manifest.secrets.keys())
    known_edges = [
        (c.host, secret_id, c.path)
        for secret_id, s in manifest.secrets.items()
        for c in s.consumers
    ]
    return [
        {
            "statement": (
                "MATCH (h:SecretmapHost)-[r:CONSUMES]->(s:SecretmapSecret) "
                "WHERE NOT [h.name, s.id, r.path] IN $known_edges "
                "DELETE r"
            ),
            "parameters": {"known_edges": [list(e) for e in known_edges]},
        },
        {
            "statement": (
                "MATCH (s:SecretmapSecret) WHERE NOT s.id IN $known_ids DETACH DELETE s"
            ),
            "parameters": {"known_ids": known_secret_ids},
        },
        {
            "statement": (
                "MATCH (h:SecretmapHost) WHERE NOT (h)-[:CONSUMES]->() DETACH DELETE h"
            ),
            "parameters": {},
        },
    ]


def sync(manifest: Manifest, http_url: str, user: str, password: str) -> int:
    """Push the manifest into Neo4j. Returns the number of statements executed."""
    statements = build_statements(manifest) + prune_statements(manifest)
    _run_statements(http_url, user, password, statements)
    return len(statements)
