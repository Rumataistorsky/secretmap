"""Manifest data model and persistence for secretmap."""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import date
from typing import Optional

SCHEMA_VERSION = 1
DEFAULT_MANIFEST_PATH = "secretmap.json"


class SecretmapError(Exception):
    """Base error for secretmap operations."""


class SecretNotFound(SecretmapError):
    def __init__(self, secret_id: str):
        super().__init__(f"secret '{secret_id}' is not registered in the manifest")
        self.secret_id = secret_id


class SecretAlreadyExists(SecretmapError):
    def __init__(self, secret_id: str):
        super().__init__(f"secret '{secret_id}' is already registered")
        self.secret_id = secret_id


@dataclass
class Consumer:
    host: str
    path: str
    service: Optional[str] = None
    restart_required: bool = False
    last_verified: Optional[str] = None
    notes: Optional[str] = None

    def key(self) -> tuple:
        return (self.host, self.path)

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v not in (None, False) or k == "restart_required"}

    @staticmethod
    def from_dict(d: dict) -> "Consumer":
        return Consumer(
            host=d["host"],
            path=d["path"],
            service=d.get("service"),
            restart_required=bool(d.get("restart_required", False)),
            last_verified=d.get("last_verified"),
            notes=d.get("notes"),
        )


@dataclass
class Secret:
    backend: str
    location: str
    rotation_period_days: Optional[int] = None
    last_rotated: Optional[str] = None
    consumers: list = field(default_factory=list)

    def to_dict(self) -> dict:
        d = {
            "backend": self.backend,
            "location": self.location,
        }
        if self.rotation_period_days is not None:
            d["rotation_period_days"] = self.rotation_period_days
        if self.last_rotated is not None:
            d["last_rotated"] = self.last_rotated
        d["consumers"] = [c.to_dict() for c in self.consumers]
        return d

    @staticmethod
    def from_dict(d: dict) -> "Secret":
        return Secret(
            backend=d["backend"],
            location=d["location"],
            rotation_period_days=d.get("rotation_period_days"),
            last_rotated=d.get("last_rotated"),
            consumers=[Consumer.from_dict(c) for c in d.get("consumers", [])],
        )


class Manifest:
    def __init__(self, path: str = DEFAULT_MANIFEST_PATH):
        self.path = path
        self.secrets: dict[str, Secret] = {}

    @classmethod
    def load(cls, path: str = DEFAULT_MANIFEST_PATH) -> "Manifest":
        m = cls(path)
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                raw = json.load(f)
            for secret_id, sdict in raw.get("secrets", {}).items():
                m.secrets[secret_id] = Secret.from_dict(sdict)
        return m

    def save(self) -> None:
        raw = {
            "version": SCHEMA_VERSION,
            "secrets": {sid: s.to_dict() for sid, s in sorted(self.secrets.items())},
        }
        tmp_path = f"{self.path}.tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(raw, f, indent=2, ensure_ascii=False, sort_keys=False)
            f.write("\n")
        os.replace(tmp_path, self.path)

    def add_secret(self, secret_id: str, backend: str, location: str,
                   rotation_period_days: Optional[int] = None) -> Secret:
        if secret_id in self.secrets:
            raise SecretAlreadyExists(secret_id)
        s = Secret(backend=backend, location=location, rotation_period_days=rotation_period_days)
        self.secrets[secret_id] = s
        return s

    def get_secret(self, secret_id: str) -> Secret:
        if secret_id not in self.secrets:
            raise SecretNotFound(secret_id)
        return self.secrets[secret_id]

    def add_consumer(self, secret_id: str, consumer: Consumer) -> None:
        s = self.get_secret(secret_id)
        for existing in s.consumers:
            if existing.key() == consumer.key():
                raise SecretmapError(
                    f"consumer {consumer.host}:{consumer.path} already registered for '{secret_id}'"
                )
        s.consumers.append(consumer)

    def remove_consumer(self, secret_id: str, host: str, path: str) -> bool:
        s = self.get_secret(secret_id)
        before = len(s.consumers)
        s.consumers = [c for c in s.consumers if c.key() != (host, path)]
        return len(s.consumers) < before

    def mark_rotated(self, secret_id: str, when: Optional[str] = None) -> str:
        s = self.get_secret(secret_id)
        s.last_rotated = when or date.today().isoformat()
        return s.last_rotated

    def touch_consumer(self, secret_id: str, host: str, path: str, when: Optional[str] = None) -> None:
        s = self.get_secret(secret_id)
        for c in s.consumers:
            if c.key() == (host, path):
                c.last_verified = when or date.today().isoformat()
                return
        raise SecretmapError(f"no such consumer {host}:{path} for '{secret_id}'")
