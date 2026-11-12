"""Optional-dependency failure contract.

A base install (no [mcp] / [api] extras) must still fail cleanly when an
optional surface is invoked: JSON error envelope / clean stderr, exit 3,
never an import traceback. Import blockers simulate the missing extras in
any environment, including CI where the extras are installed.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
SRC = ROOT / "src"


def run_blocked(module: str, *args, blocker: Path):
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(blocker), str(SRC)])
    return subprocess.run(
        [sys.executable, "-m", module, *args],
        capture_output=True, text=True, env=env, timeout=60)


def make_blocker(tmp_path: Path, package: str) -> Path:
    blocker = tmp_path / f"block_{package}"
    blocker.mkdir()
    (blocker / f"{package}.py").write_text(
        f"raise ImportError('blocked for test: {package}')\n")
    return blocker


def test_cli_serve_without_fastapi_is_clean_dependency_error(tmp_path):
    blocker = make_blocker(tmp_path, "fastapi")
    r = run_blocked("rea_disassembler", "serve", "--port", "8765", blocker=blocker)
    assert "Traceback" not in r.stderr, r.stderr
    assert r.returncode == 3, (r.returncode, r.stdout, r.stderr)
    err = json.loads(r.stderr)
    assert err["error"]["code"] == "dependency_missing"
    assert "fastapi" in err["error"]["message"]


def test_mcp_server_without_sdk_is_clean_dependency_error(tmp_path):
    blocker = make_blocker(tmp_path, "mcp")
    r = run_blocked("rea_disassembler.mcp_server", blocker=blocker)
    assert "Traceback" not in r.stderr, r.stderr
    assert r.returncode == 3, (r.returncode, r.stdout, r.stderr)
    assert r.stdout == ""
    err = json.loads(r.stderr)
    assert err["error"]["code"] == "dependency_missing"
    assert "mcp" in err["error"]["message"]
