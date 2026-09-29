# secretmap

A backend-agnostic secret **consumer / lineage manifest**.

Secret managers (Vaultwarden, Bitwarden, 1Password, HashiCorp Vault, ...)
answer *"where is this secret stored?"* very well. None of them answer the
question that actually causes outages:

> **If I delete, revoke, or rotate this secret right now, what breaks?**

`secretmap` doesn't store secret values at all — it stores a small,
git-friendly JSON manifest mapping each secret to every place that actually
consumes it (host, file path, service/systemd unit), so a human or an
automation script can check *before* acting, not discover the blast radius
after something pages you.

## The problem this solves

Two real incidents that motivated this tool:

1. **Silent staleness.** A credential was rotated in its source-of-truth
   console. Nobody re-deployed the new value to the one host that actually
   used it. The old value kept "working" locally (cached on disk) for two
   months until it finally failed, with zero warning in between.
2. **Blind deletion.** During a credential cleanup pass, a file that looked
   like an orphaned secret was deleted from a host without checking (a)
   whether anything still read it, or (b) whether a canonical copy existed
   anywhere else. It was still in use. The service that broke spammed 1000+
   failure notifications before anyone noticed the actual cause.

Neither incident was a "the vault got hacked" problem. Both were "nobody had
a map" problems. `secretmap` is that map.

## What it is not

- Not a secrets manager. It never stores a secret *value* — only metadata
  (backend name, a human-readable location string, and a list of
  consumers). Point it at Vaultwarden, Vault, 1Password, a plain
  `~/.secrets/` file, whatever you already use.
- Not a daemon, not a Kubernetes operator, not a database. It's a single
  JSON file plus a CLI, meant to be committed to your infra repo like any
  other piece of documentation-as-code.
- Not a replacement for good rotation hygiene — it's the missing checklist
  that makes rotation hygiene actually reliable instead of "remembered by
  one person."

## Install

```bash
pip install .
# or, for local dev with tests:
pip install -e ".[dev]"
```

## Quickstart

```bash
secretmap init

secretmap add google-sa-receipts \
  --backend vaultwarden \
  --location "Google Service Account — rotes-receipts" \
  --rotation-days 90

secretmap consumer add google-sa-receipts \
  --host "LXC 414 (192.168.2.24)" \
  --path /opt/agent/google-credentials.json \
  --service receipt-daily-report.timer \
  --restart-required \
  --verified-now

# Before deleting/revoking anything, ask first:
secretmap check google-sa-receipts
# exit 0  = no known consumers, safe as far as the manifest knows
# exit 1  = known consumers exist, printed to stderr — do NOT delete blindly
# exit 2  = secret isn't even in the manifest — that's a gap, not a green light

# After rotating in the source of truth, get the redeploy checklist:
secretmap rotate google-sa-receipts
#   -> LXC 414 (192.168.2.24): /opt/agent/google-credentials.json [receipt-daily-report.timer] (restart required)

# Periodic health check — drift, overdue rotations, unconsumed secrets:
secretmap audit --bw   # cross-checks Vaultwarden/Bitwarden-backed entries via the `bw` CLI
```

## Suggested workflow

- Commit `secretmap.json` alongside your other infra docs (it contains no
  secret material — just IDs, hostnames, paths, and dates).
- Whenever you wire a new credential into a service: `secretmap add` +
  `secretmap consumer add`, same PR as the actual change.
- Whenever you rotate a credential: `secretmap rotate <id>`, then work
  through the printed checklist, then `secretmap touch` each consumer once
  verified.
- Before deleting/revoking anything that looks unused: `secretmap check
  <id>` first. Wire it into your rotation/cleanup scripts as a gate —
  a non-zero exit should stop the script.
- Run `secretmap audit` on a schedule (cron/CI) to catch overdue rotations
  and secrets nobody ever registered consumers for.

## Manifest format

```json
{
  "version": 1,
  "secrets": {
    "google-sa-receipts": {
      "backend": "vaultwarden",
      "location": "Google Service Account — rotes-receipts",
      "rotation_period_days": 90,
      "last_rotated": "2026-09-28",
      "consumers": [
        {
          "host": "LXC 414 (192.168.2.24)",
          "path": "/opt/agent/google-credentials.json",
          "service": "receipt-daily-report.timer",
          "restart_required": true,
          "last_verified": "2026-09-28"
        }
      ]
    }
  }
}
```

Human-readable, diffable, mergeable — no special tooling required to read
it even if you never install `secretmap` itself.

## License

MIT
