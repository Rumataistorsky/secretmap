"""secretmap: a backend-agnostic secret consumer/lineage manifest.

secretmap does not store secret *values*. It stores a small, git-friendly
manifest that answers two questions no mainstream secrets manager answers:

  1. "If I delete or rotate this secret right now, what breaks?"
  2. "Is the copy deployed on host X still the current value, or stale?"

It works alongside any secret store (Vaultwarden, Bitwarden, 1Password,
HashiCorp Vault, plain env files, whatever) — secretmap only tracks the
*graph*: secret -> consumers, plus optional last-verified/rotation metadata.
"""

__version__ = "0.1.0"
