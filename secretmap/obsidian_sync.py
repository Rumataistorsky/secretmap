"""Optional Obsidian vault export for secretmap.

Renders the manifest as a folder of plain Markdown notes with Obsidian-style
`[[wikilinks]]` between secrets and the hosts that consume them. This is a
second, independent view of the exact same data that `neo4j_sync` pushes
into a graph database — intentionally so a human can compare which one
answers "what breaks if..." questions faster/more clearly for their own
workflow. Both are generated FROM the same `secretmap.json`; neither is the
source of truth, and this module never reads a vault back into the
manifest (one-way, generated-content folder — don't hand-edit these files,
edit the manifest and regenerate).

Layout:

    <vault>/
      secrets/<secret-id>.md   — one per secret, frontmatter + consumer links
      hosts/<host-slug>.md     — one per host, links back to what it consumes

Regeneration is destructive-but-scoped: only files under secrets/ and
hosts/ that this tool itself would have generated are removed before
writing the current set, so stale notes for since-deleted manifest entries
don't linger silently.
"""
from __future__ import annotations

import os
import re

from .model import Manifest

GENERATED_MARKER = "<!-- secretmap:generated — do not hand-edit, regenerate from secretmap.json -->"


def _slugify(name: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", name.strip().lower()).strip("-")
    return slug or "unnamed"


def _secret_note(secret_id: str, s, host_slugs: dict[str, str]) -> str:
    lines = [
        GENERATED_MARKER,
        "---",
        f"secret_id: {secret_id}",
        f"backend: {s.backend}",
        f"location: \"{s.location}\"",
    ]
    if s.rotation_period_days is not None:
        lines.append(f"rotation_period_days: {s.rotation_period_days}")
    if s.last_rotated:
        lines.append(f"last_rotated: {s.last_rotated}")
    lines += ["tags: [secretmap, secret]", "---", "", f"# {secret_id}", ""]
    lines.append(f"- **Backend:** {s.backend}")
    lines.append(f"- **Location:** {s.location}")
    if s.rotation_period_days is not None:
        lines.append(f"- **Rotation period:** every {s.rotation_period_days} days")
    lines.append(f"- **Last rotated:** {s.last_rotated or '_never recorded_'}")
    lines.append("")
    lines.append("## Consumers")
    if not s.consumers:
        lines.append("")
        lines.append("_No registered consumers. Either genuinely unused, or nobody "
                      "registered them yet — do not treat this as \"safe to delete\" "
                      "without checking._")
    else:
        lines.append("")
        for c in s.consumers:
            host_slug = host_slugs[c.host]
            svc = f", service `{c.service}`" if c.service else ""
            restart = ", **restart required**" if c.restart_required else ""
            verified = f", last verified {c.last_verified}" if c.last_verified else ", _never verified_"
            lines.append(f"- [[../hosts/{host_slug}|{c.host}]]: `{c.path}`{svc}{restart}{verified}")
            if c.notes:
                lines.append(f"  - {c.notes}")
    return "\n".join(lines) + "\n"


def _host_note(host: str, entries: list[tuple[str, object]]) -> str:
    lines = [
        GENERATED_MARKER,
        "---",
        f"host: \"{host}\"",
        "tags: [secretmap, host]",
        "---",
        "",
        f"# {host}",
        "",
        "## Secrets this host consumes",
        "",
    ]
    for secret_id, c in entries:
        svc = f", service `{c.service}`" if c.service else ""
        lines.append(f"- [[../secrets/{secret_id}|{secret_id}]]: `{c.path}`{svc}")
    if not entries:
        lines.append("_none registered_")
    return "\n".join(lines) + "\n"


def _clear_generated(dir_path: str) -> None:
    if not os.path.isdir(dir_path):
        return
    for name in os.listdir(dir_path):
        full = os.path.join(dir_path, name)
        if not full.endswith(".md"):
            continue
        try:
            with open(full, "r", encoding="utf-8") as f:
                first_line = f.readline().strip()
        except OSError:
            continue
        if first_line == GENERATED_MARKER:
            os.remove(full)


def export_vault(manifest: Manifest, vault_path: str) -> tuple[int, int]:
    """Render the manifest into an Obsidian-compatible folder of notes.

    Returns (secret_note_count, host_note_count).
    """
    secrets_dir = os.path.join(vault_path, "secrets")
    hosts_dir = os.path.join(vault_path, "hosts")
    os.makedirs(secrets_dir, exist_ok=True)
    os.makedirs(hosts_dir, exist_ok=True)

    _clear_generated(secrets_dir)
    _clear_generated(hosts_dir)

    host_slugs = {
        host: _slugify(host)
        for s in manifest.secrets.values()
        for host in {c.host for c in s.consumers}
    }

    host_entries: dict[str, list[tuple[str, object]]] = {}
    for secret_id, s in manifest.secrets.items():
        note = _secret_note(secret_id, s, host_slugs)
        with open(os.path.join(secrets_dir, f"{secret_id}.md"), "w", encoding="utf-8") as f:
            f.write(note)
        for c in s.consumers:
            host_entries.setdefault(c.host, []).append((secret_id, c))

    for host, entries in host_entries.items():
        slug = host_slugs[host]
        note = _host_note(host, entries)
        with open(os.path.join(hosts_dir, f"{slug}.md"), "w", encoding="utf-8") as f:
            f.write(note)

    return len(manifest.secrets), len(host_entries)
