"""Agent-surface contract tests: stable JSON, pagination, error envelope,
MCP over stdio, HTTP API, and the npm wrapper.  These were written before
the surface existed (TDD); they define what `go` had to build."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
BENCH = ROOT / "bench"
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))


def run_cli(*args, expect=0):
    env = dict(os.environ, PYTHONPATH=str(SRC))
    r = subprocess.run([sys.executable, "-m", "rea_disassembler", *args],
                       capture_output=True, text=True, env=env, timeout=120)
    assert r.returncode == expect, f"{args}: rc={r.returncode}\n{r.stdout}\n{r.stderr}"
    return r


def test_info_json_has_schema_version():
    r = run_cli("info", str(BENCH / "corpus_arm64"), "--json")
    doc = json.loads(r.stdout)
    assert doc["schema_version"] == "1"
    assert doc["format"] == "mach-o" and doc["counts"]["functions"] == 10


def test_functions_pagination_json():
    r = run_cli("functions", str(BENCH / "corpus_arm64"), "--json",
                "--limit", "3", "--offset", "2")
    page = json.loads(r.stdout)
    assert page["schema_version"] == "1"
    assert page["total"] == 10 and page["limit"] == 3 and page["offset"] == 2
    assert len(page["items"]) == 3
    assert page["items"][0]["addr"]  # stable, address-ordered items


def test_strings_pagination_json():
    r = run_cli("strings", str(BENCH / "corpus_arm64"), "--json", "--limit", "2")
    page = json.loads(r.stdout)
    assert page["total"] == 3 and len(page["items"]) == 2
    assert "string-xref-target-12345" in {i["value"] for i in
                                          json.loads(run_cli(
                                              "strings", str(BENCH / "corpus_arm64"),
                                              "--json").stdout)["items"]}


def test_error_envelope_and_exit_code(tmp_path):
    bad = tmp_path / "nope.bin"
    bad.write_bytes(b"\x00" * 32)
    r = run_cli("info", str(bad), "--json", expect=3)
    err = json.loads(r.stderr)
    assert err["error"]["code"] and err["error"]["message"]


def test_mcp_stdio_tools():
    try:
        import mcp  # noqa: F401
    except ImportError:
        pytest.skip("mcp SDK not installed (pip install 'rea-disassembler[mcp]')")
    env = dict(os.environ, PYTHONPATH=str(SRC))
    proc = subprocess.Popen(
        [sys.executable, "-m", "rea_disassembler.mcp_server"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=env)
    def rpc(payload):
        proc.stdin.write((json.dumps(payload) + "\n").encode())
        proc.stdin.flush()
        line = proc.stdout.readline()
        assert line, "MCP server closed stdout without a response"
        assert line.strip().startswith(b"{"), f"non-JSON on stdout: {line[:80]}"
        return json.loads(line)
    try:
        init = rpc({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {"protocolVersion": "2024-11-05",
                               "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}})
        assert init["result"]["serverInfo"]["name"]
        proc.stdin.write(b'{"jsonrpc": "2.0", "method": "notifications/initialized"}\n')
        proc.stdin.flush()  # notifications get no response; never read one
        tools = rpc({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        names = {t["name"] for t in tools["result"]["tools"]}
        assert {"binary_overview", "list_functions", "disassemble_function",
                "decompile_function", "list_strings"} <= names
        call = rpc({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                    "params": {"name": "binary_overview",
                               "arguments": {"path": str(BENCH / "corpus_arm64")}}})
        text = call["result"]["content"][0]["text"]
        assert json.loads(text)["counts"]["functions"] == 10
        bad = rpc({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                   "params": {"name": "no_such_tool", "arguments": {}}})
        assert "error" in bad or bad["result"].get("isError")
    finally:
        proc.terminate()


def test_http_api():
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from rea_disassembler.http_api import create_app
    client = TestClient(create_app())
    h = client.get("/health")
    assert h.status_code == 200 and h.json()["status"] == "ok"
    r = client.get("/v1/info", params={"path": str(BENCH / "corpus_arm64")})
    assert r.status_code == 200
    assert r.json()["counts"]["functions"] == 10
    pg = client.get("/v1/functions", params={"path": str(BENCH / "corpus_arm64"),
                                             "limit": 2, "offset": 1})
    assert pg.status_code == 200 and len(pg.json()["items"]) == 2
    bad = client.get("/v1/info", params={"path": "/nonexistent.bin"})
    assert bad.status_code in (400, 404)
    assert "error" in bad.json()
    # patch is guarded: no write tools unless the app enables them
    pw = client.post("/v1/patch", json={"path": str(BENCH / "corpus_arm64"),
                                        "address": "0x1000004b0",
                                        "asm": "nop", "out": "/tmp/x"})
    assert pw.status_code in (403, 400)


def test_npm_wrapper_files_exist():
    pkg = ROOT / "package.json"
    assert pkg.exists(), "npm package metadata missing"
    meta = json.loads(pkg.read_text())
    assert meta["bin"], "package.json must declare a bin entry"
    for rel in meta["bin"].values():
        assert (ROOT / rel).exists(), f"bin target {rel} missing"


def _mcp_tool_names(env_extra):
    env = dict(os.environ, PYTHONPATH=str(SRC))
    env.pop("READIS_MCP_ENABLE_WRITE", None)
    env.pop("READIS_MCP_ENABLE_DEBUG", None)
    env.update(env_extra)
    proc = subprocess.Popen(
        [sys.executable, "-m", "rea_disassembler.mcp_server"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=env)
    try:
        def rpc(payload):
            proc.stdin.write((json.dumps(payload) + "\n").encode())
            proc.stdin.flush()
            return json.loads(proc.stdout.readline())
        rpc({"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                        "clientInfo": {"name": "t", "version": "1"}}})
        proc.stdin.write(b'{"jsonrpc": "2.0", "method": "notifications/initialized"}\n')
        proc.stdin.flush()
        tools = rpc({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        return {t["name"] for t in tools["result"]["tools"]}
    finally:
        proc.terminate()


def test_mcp_write_debug_tools_are_opt_in_only():
    try:
        import mcp  # noqa: F401
    except ImportError:
        pytest.skip("mcp SDK not installed")
    default = _mcp_tool_names({})
    assert "assemble_and_patch" not in default
    assert "debug_run" not in default
    with_write = _mcp_tool_names({"READIS_MCP_ENABLE_WRITE": "1"})
    assert "assemble_and_patch" in with_write
    assert "debug_run" not in with_write
