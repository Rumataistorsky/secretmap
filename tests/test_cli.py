import os
import tempfile
from unittest import mock

import pytest

from secretmap.cli import main


@pytest.fixture
def manifest_path():
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    os.remove(path)
    yield path
    if os.path.exists(path):
        os.remove(path)


def run(manifest_path, *args):
    return main(["--manifest", manifest_path, *args])


def test_init_creates_file(manifest_path, capsys):
    rc = run(manifest_path, "init")
    assert rc == 0
    assert os.path.exists(manifest_path)


def test_add_then_list(manifest_path, capsys):
    run(manifest_path, "init")
    rc = run(manifest_path, "add", "google-sa", "--backend", "vaultwarden", "--location", "SA Key")
    assert rc == 0
    rc = run(manifest_path, "list")
    assert rc == 0
    out = capsys.readouterr().out
    assert "google-sa" in out
    assert "vaultwarden" in out


def test_check_no_consumers_is_safe(manifest_path):
    run(manifest_path, "init")
    run(manifest_path, "add", "x", "--backend", "file", "--location", "/x")
    rc = run(manifest_path, "check", "x")
    assert rc == 0


def test_check_with_consumers_blocks(manifest_path, capsys):
    run(manifest_path, "init")
    run(manifest_path, "add", "x", "--backend", "file", "--location", "/x")
    run(manifest_path, "consumer", "add", "x", "--host", "LXC 414", "--path", "/opt/agent/x.json",
        "--service", "receipt-bot")
    rc = run(manifest_path, "check", "x")
    assert rc == 1
    err = capsys.readouterr().err
    assert "LXC 414" in err
    assert "receipt-bot" in err


def test_check_unknown_secret_is_not_a_green_light(manifest_path):
    run(manifest_path, "init")
    rc = run(manifest_path, "check", "does-not-exist")
    assert rc == 2


def test_rotate_prints_checklist(manifest_path, capsys):
    run(manifest_path, "init")
    run(manifest_path, "add", "x", "--backend", "file", "--location", "/x")
    run(manifest_path, "consumer", "add", "x", "--host", "LXC 414", "--path", "/opt/agent/x.json",
        "--restart-required")
    capsys.readouterr()
    rc = run(manifest_path, "rotate", "x", "--date", "2026-09-28")
    assert rc == 0
    out = capsys.readouterr().out
    assert "LXC 414" in out
    assert "restart required" in out


def test_audit_flags_unconsumed_secret(manifest_path, capsys):
    run(manifest_path, "init")
    run(manifest_path, "add", "orphan", "--backend", "file", "--location", "/orphan")
    capsys.readouterr()
    rc = run(manifest_path, "audit")
    assert rc == 1
    out = capsys.readouterr().out
    assert "orphan" in out
    assert "zero registered consumers" in out


def test_audit_flags_overdue_rotation(manifest_path, capsys):
    run(manifest_path, "init")
    run(manifest_path, "add", "x", "--backend", "file", "--location", "/x", "--rotation-days", "1")
    run(manifest_path, "consumer", "add", "x", "--host", "h", "--path", "/p")
    run(manifest_path, "rotate", "x", "--date", "2020-01-01")
    capsys.readouterr()
    rc = run(manifest_path, "audit")
    assert rc == 1
    out = capsys.readouterr().out
    assert "OVERDUE" in out


def test_audit_clean(manifest_path, capsys):
    run(manifest_path, "init")
    run(manifest_path, "add", "x", "--backend", "file", "--location", "/x")
    run(manifest_path, "consumer", "add", "x", "--host", "h", "--path", "/p")
    capsys.readouterr()
    rc = run(manifest_path, "audit")
    assert rc == 0


def test_sync_neo4j_requires_password(manifest_path, capsys):
    run(manifest_path, "init")
    capsys.readouterr()
    rc = run(manifest_path, "sync", "neo4j", "--url", "http://localhost:7474")
    assert rc == 2
    assert "no Neo4j password" in capsys.readouterr().err


def test_sync_neo4j_calls_sync_with_manifest(manifest_path, capsys):
    run(manifest_path, "init")
    run(manifest_path, "add", "x", "--backend", "file", "--location", "/x")
    capsys.readouterr()
    with mock.patch("secretmap.neo4j_sync.sync", return_value=3) as mocked:
        rc = run(manifest_path, "sync", "neo4j", "--url", "http://localhost:7474",
                  "--user", "neo4j", "--password", "secret")
    assert rc == 0
    mocked.assert_called_once()
    _, kwargs = mocked.call_args
    assert kwargs["http_url"] == "http://localhost:7474"
    assert kwargs["user"] == "neo4j"
    assert kwargs["password"] == "secret"
    assert "x" in mocked.call_args[0][0].secrets


def test_sync_neo4j_reads_password_from_env(manifest_path, monkeypatch):
    run(manifest_path, "init")
    monkeypatch.setenv("SECRETMAP_NEO4J_PASSWORD", "from-env")
    with mock.patch("secretmap.neo4j_sync.sync", return_value=1) as mocked:
        rc = run(manifest_path, "sync", "neo4j", "--url", "http://localhost:7474")
    assert rc == 0
    assert mocked.call_args.kwargs["password"] == "from-env"
