"""Command-line interface for secretmap."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import date, datetime

from .model import (
    Consumer,
    DEFAULT_MANIFEST_PATH,
    Manifest,
    SecretmapError,
)


def _load(args) -> Manifest:
    return Manifest.load(args.manifest)


def cmd_init(args) -> int:
    m = Manifest(args.manifest)
    m.save()
    print(f"initialized empty manifest at {args.manifest}")
    return 0


def cmd_add(args) -> int:
    m = _load(args)
    try:
        m.add_secret(args.secret_id, backend=args.backend, location=args.location,
                     rotation_period_days=args.rotation_days)
    except SecretmapError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    m.save()
    print(f"registered secret '{args.secret_id}' ({args.backend}: {args.location})")
    return 0


def cmd_consumer_add(args) -> int:
    m = _load(args)
    consumer = Consumer(
        host=args.host,
        path=args.path,
        service=args.service,
        restart_required=args.restart_required,
        notes=args.notes,
        last_verified=date.today().isoformat() if args.verified_now else None,
    )
    try:
        m.add_consumer(args.secret_id, consumer)
    except SecretmapError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    m.save()
    print(f"added consumer {args.host}:{args.path} for '{args.secret_id}'")
    return 0


def cmd_consumer_rm(args) -> int:
    m = _load(args)
    try:
        removed = m.remove_consumer(args.secret_id, args.host, args.path)
    except SecretmapError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    if not removed:
        print(f"no consumer {args.host}:{args.path} found for '{args.secret_id}'", file=sys.stderr)
        return 1
    m.save()
    print(f"removed consumer {args.host}:{args.path} from '{args.secret_id}'")
    return 0


def cmd_touch(args) -> int:
    m = _load(args)
    try:
        m.touch_consumer(args.secret_id, args.host, args.path)
    except SecretmapError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    m.save()
    print(f"marked {args.host}:{args.path} as verified today for '{args.secret_id}'")
    return 0


def cmd_rotate(args) -> int:
    m = _load(args)
    try:
        when = m.mark_rotated(args.secret_id, args.date)
        s = m.get_secret(args.secret_id)
    except SecretmapError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    m.save()
    print(f"'{args.secret_id}' marked rotated on {when}.")
    if s.consumers:
        print("Redeploy checklist — every one of these needs the new value:")
        for c in s.consumers:
            flag = " (restart required)" if c.restart_required else ""
            svc = f" [{c.service}]" if c.service else ""
            print(f"  - {c.host}: {c.path}{svc}{flag}")
    else:
        print("No consumers registered for this secret yet — nothing to redeploy, "
              "or the manifest is incomplete. Consider `secretmap consumer add`.")
    return 0


def cmd_check(args) -> int:
    """Exit 0 = safe to delete/revoke (no known consumers). Exit 1 = NOT safe."""
    m = _load(args)
    try:
        s = m.get_secret(args.secret_id)
    except SecretmapError as e:
        print(f"error: {e}", file=sys.stderr)
        print("(unknown secrets are NOT proven safe — this is a gap in the manifest, "
              "not a green light. Investigate before deleting.)", file=sys.stderr)
        return 2
    if not s.consumers:
        print(f"'{args.secret_id}': no registered consumers. Safe to delete/revoke "
              f"as far as this manifest knows.")
        return 0
    print(f"'{args.secret_id}': {len(s.consumers)} registered consumer(s) — "
          f"deleting/revoking this WILL break something:", file=sys.stderr)
    for c in s.consumers:
        svc = f" [{c.service}]" if c.service else ""
        print(f"  - {c.host}: {c.path}{svc}", file=sys.stderr)
    return 1


def cmd_list(args) -> int:
    m = _load(args)
    if args.json:
        raw = {sid: s.to_dict() for sid, s in sorted(m.secrets.items())}
        print(json.dumps(raw, indent=2, ensure_ascii=False))
        return 0
    if not m.secrets:
        print("(empty manifest)")
        return 0
    for sid, s in sorted(m.secrets.items()):
        rot = f", rotated {s.last_rotated}" if s.last_rotated else ""
        print(f"{sid}  [{s.backend}: {s.location}{rot}]")
        for c in s.consumers:
            svc = f" [{c.service}]" if c.service else ""
            verified = f", verified {c.last_verified}" if c.last_verified else ", never verified"
            print(f"    -> {c.host}: {c.path}{svc}{verified}")
    return 0


def _bw_item_names() -> list[str]:
    out = subprocess.run(["bw", "list", "items"], capture_output=True, text=True, check=True)
    items = json.loads(out.stdout)
    return [i["name"] for i in items]


def cmd_audit(args) -> int:
    m = _load(args)
    problems = 0

    if args.bw:
        try:
            bw_names = set(_bw_item_names())
        except FileNotFoundError:
            print("error: `bw` CLI not found on PATH — install/unlock Bitwarden CLI for --bw audit",
                  file=sys.stderr)
            return 2
        except subprocess.CalledProcessError as e:
            print(f"error: `bw list items` failed: {e.stderr.strip()}", file=sys.stderr)
            return 2

        for sid, s in sorted(m.secrets.items()):
            if s.backend.lower() in ("vaultwarden", "bitwarden") and s.location not in bw_names:
                print(f"DRIFT: manifest secret '{sid}' points at Vaultwarden item "
                      f"'{s.location}', which no longer exists in the vault.")
                problems += 1

        manifest_locations = {
            s.location for s in m.secrets.values()
            if s.backend.lower() in ("vaultwarden", "bitwarden")
        }
        for name in sorted(bw_names - manifest_locations):
            pass  # Intentionally not flagged as a problem: not every vault item is
            # infra-relevant (personal logins etc.) — this would be too noisy by
            # default. Use `secretmap audit --bw --strict` in future versions to
            # surface these too if that's ever wanted.

    for sid, s in sorted(m.secrets.items()):
        if not s.consumers:
            print(f"WARN: '{sid}' has zero registered consumers. Either it's genuinely "
                  f"unused (candidate for cleanup) or nobody registered its consumers yet.")
            problems += 1
        if s.rotation_period_days and s.last_rotated:
            last = datetime.fromisoformat(s.last_rotated).date()
            age_days = (date.today() - last).days
            if age_days > s.rotation_period_days:
                print(f"OVERDUE: '{sid}' was last rotated {age_days} days ago "
                      f"(policy: every {s.rotation_period_days} days).")
                problems += 1

    if problems == 0:
        print("audit clean: no drift, no unrotated-overdue secrets, no unconsumed entries.")
        return 0
    return 1


def cmd_sync_neo4j(args) -> int:
    m = _load(args)
    password = args.password
    if password is None:
        env_var = args.password_env or "SECRETMAP_NEO4J_PASSWORD"
        password = os.environ.get(env_var)
    if not password:
        print(f"error: no Neo4j password given (use --password, or set ${args.password_env or 'SECRETMAP_NEO4J_PASSWORD'})",
              file=sys.stderr)
        return 2

    from .neo4j_sync import Neo4jSyncError, sync  # lazy import: keeps `neo4j` extras optional

    try:
        n = sync(m, http_url=args.url, user=args.user, password=password)
    except Neo4jSyncError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(f"synced {len(m.secrets)} secret(s) to {args.url} ({n} statements executed).")
    print("Try, e.g.: MATCH (h:SecretmapHost)-[:CONSUMES]->(s:SecretmapSecret) RETURN h.name, s.id")
    return 0


def cmd_sync_obsidian(args) -> int:
    m = _load(args)
    from .obsidian_sync import export_vault  # lazy import, stdlib-only but keeps sync/* symmetric

    n_secrets, n_hosts = export_vault(m, args.vault_path)
    print(f"wrote {n_secrets} secret note(s) and {n_hosts} host note(s) to {args.vault_path}")
    print("Open that folder as an Obsidian vault (or a subfolder of one already synced "
          "via Nextcloud) — notes regenerate on every sync, don't hand-edit them.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="secretmap",
        description="Backend-agnostic secret consumer/lineage manifest. "
                     "Answers 'what breaks if I delete/rotate this?' before you act.",
    )
    p.add_argument("--manifest", default=DEFAULT_MANIFEST_PATH,
                   help=f"path to manifest file (default: {DEFAULT_MANIFEST_PATH})")
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("init", help="create an empty manifest")
    sp.set_defaults(func=cmd_init)

    sp = sub.add_parser("add", help="register a secret's canonical location")
    sp.add_argument("secret_id")
    sp.add_argument("--backend", required=True, help="e.g. vaultwarden, vault, 1password, file, env")
    sp.add_argument("--location", required=True, help="e.g. a Vaultwarden item name, a Vault path")
    sp.add_argument("--rotation-days", type=int, default=None,
                     help="expected rotation period in days, for overdue-audit")
    sp.set_defaults(func=cmd_add)

    sp = sub.add_parser("consumer", help="manage consumers of a secret")
    consumer_sub = sp.add_subparsers(dest="consumer_command", required=True)

    csp = consumer_sub.add_parser("add", help="register a consumer")
    csp.add_argument("secret_id")
    csp.add_argument("--host", required=True, help="e.g. 'LXC 414 (192.168.2.24)'")
    csp.add_argument("--path", required=True, help="file path or env var name on that host")
    csp.add_argument("--service", default=None, help="systemd unit / process / script name")
    csp.add_argument("--restart-required", action="store_true",
                      help="does this consumer need a restart after the file is updated?")
    csp.add_argument("--notes", default=None)
    csp.add_argument("--verified-now", action="store_true",
                      help="mark this consumer as verified-working today")
    csp.set_defaults(func=cmd_consumer_add)

    csp = consumer_sub.add_parser("rm", help="remove a consumer")
    csp.add_argument("secret_id")
    csp.add_argument("--host", required=True)
    csp.add_argument("--path", required=True)
    csp.set_defaults(func=cmd_consumer_rm)

    sp = sub.add_parser("touch", help="mark a consumer as verified-working today")
    sp.add_argument("secret_id")
    sp.add_argument("--host", required=True)
    sp.add_argument("--path", required=True)
    sp.set_defaults(func=cmd_touch)

    sp = sub.add_parser("rotate", help="record a rotation and print the redeploy checklist")
    sp.add_argument("secret_id")
    sp.add_argument("--date", default=None, help="ISO date, defaults to today")
    sp.set_defaults(func=cmd_rotate)

    sp = sub.add_parser("check", help="pre-delete/pre-rotate safety gate (exit 1 if consumers exist)")
    sp.add_argument("secret_id")
    sp.set_defaults(func=cmd_check)

    sp = sub.add_parser("list", help="print the full graph")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_list)

    sp = sub.add_parser("audit", help="find drift, overdue rotations, and unconsumed secrets")
    sp.add_argument("--bw", action="store_true", help="cross-check vaultwarden/bitwarden backends via `bw` CLI")
    sp.set_defaults(func=cmd_audit)

    sp = sub.add_parser("sync", help="push the manifest into a graph backend for cross-host queries")
    sync_sub = sp.add_subparsers(dest="sync_command", required=True)

    nsp = sync_sub.add_parser("neo4j", help="sync into an existing Neo4j instance over its HTTP endpoint "
                                             "(no `neo4j` driver dependency required)")
    nsp.add_argument("--url", required=True, help="Neo4j HTTP endpoint, e.g. http://192.168.2.50:7474")
    nsp.add_argument("--user", default="neo4j")
    nsp.add_argument("--password", default=None,
                      help="Neo4j password (prefer --password-env to avoid shell history exposure)")
    nsp.add_argument("--password-env", default=None,
                      help="env var to read the password from (default: SECRETMAP_NEO4J_PASSWORD)")
    nsp.set_defaults(func=cmd_sync_neo4j)

    osp = sync_sub.add_parser("obsidian", help="render the manifest as an Obsidian-compatible "
                                                "folder of Markdown notes with [[wikilinks]]")
    osp.add_argument("--vault-path", required=True,
                      help="directory to write secrets/ and hosts/ subfolders into")
    osp.set_defaults(func=cmd_sync_obsidian)

    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
