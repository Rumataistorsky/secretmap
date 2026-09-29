import os
import tempfile

import pytest

from secretmap.model import Consumer, Manifest, SecretAlreadyExists, SecretmapError, SecretNotFound


@pytest.fixture
def tmp_manifest_path():
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    os.remove(path)
    yield path
    if os.path.exists(path):
        os.remove(path)


def test_add_and_get_secret(tmp_manifest_path):
    m = Manifest(tmp_manifest_path)
    m.add_secret("google-sa-receipts", backend="vaultwarden", location="Google Service Account — rotes-receipts")
    s = m.get_secret("google-sa-receipts")
    assert s.backend == "vaultwarden"
    assert s.consumers == []


def test_add_secret_duplicate_raises(tmp_manifest_path):
    m = Manifest(tmp_manifest_path)
    m.add_secret("x", backend="file", location="/root/.secrets/x")
    with pytest.raises(SecretAlreadyExists):
        m.add_secret("x", backend="file", location="/root/.secrets/x")


def test_get_missing_secret_raises(tmp_manifest_path):
    m = Manifest(tmp_manifest_path)
    with pytest.raises(SecretNotFound):
        m.get_secret("nope")


def test_add_consumer_and_check(tmp_manifest_path):
    m = Manifest(tmp_manifest_path)
    m.add_secret("x", backend="file", location="/root/.secrets/x")
    m.add_consumer("x", Consumer(host="LXC 414", path="/opt/agent/x.json", service="receipt-bot"))
    s = m.get_secret("x")
    assert len(s.consumers) == 1
    assert s.consumers[0].host == "LXC 414"


def test_add_duplicate_consumer_raises(tmp_manifest_path):
    m = Manifest(tmp_manifest_path)
    m.add_secret("x", backend="file", location="/root/.secrets/x")
    m.add_consumer("x", Consumer(host="h", path="/p"))
    with pytest.raises(SecretmapError):
        m.add_consumer("x", Consumer(host="h", path="/p"))


def test_remove_consumer(tmp_manifest_path):
    m = Manifest(tmp_manifest_path)
    m.add_secret("x", backend="file", location="/x")
    m.add_consumer("x", Consumer(host="h", path="/p"))
    assert m.remove_consumer("x", "h", "/p") is True
    assert m.get_secret("x").consumers == []
    assert m.remove_consumer("x", "h", "/p") is False


def test_save_and_load_roundtrip(tmp_manifest_path):
    m = Manifest(tmp_manifest_path)
    m.add_secret("x", backend="vaultwarden", location="Item Name", rotation_period_days=90)
    m.add_consumer("x", Consumer(host="LXC 414", path="/opt/agent/x.json", service="timer.service",
                                  restart_required=True, notes="one-shot job"))
    m.mark_rotated("x", "2026-09-28")
    m.save()

    reloaded = Manifest.load(tmp_manifest_path)
    s = reloaded.get_secret("x")
    assert s.backend == "vaultwarden"
    assert s.rotation_period_days == 90
    assert s.last_rotated == "2026-09-28"
    assert len(s.consumers) == 1
    c = s.consumers[0]
    assert c.host == "LXC 414"
    assert c.service == "timer.service"
    assert c.restart_required is True
    assert c.notes == "one-shot job"


def test_touch_consumer_sets_last_verified(tmp_manifest_path):
    m = Manifest(tmp_manifest_path)
    m.add_secret("x", backend="file", location="/x")
    m.add_consumer("x", Consumer(host="h", path="/p"))
    m.touch_consumer("x", "h", "/p", when="2026-01-01")
    assert m.get_secret("x").consumers[0].last_verified == "2026-01-01"


def test_touch_missing_consumer_raises(tmp_manifest_path):
    m = Manifest(tmp_manifest_path)
    m.add_secret("x", backend="file", location="/x")
    with pytest.raises(SecretmapError):
        m.touch_consumer("x", "nope", "/nope")


def test_load_missing_file_returns_empty_manifest(tmp_manifest_path):
    m = Manifest.load(tmp_manifest_path)
    assert m.secrets == {}
