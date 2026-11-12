"""Negative/failure-case matrix for CLI, HTTP API, and MCP surfaces.

Contract derived from current code: CLI analysis failures are a JSON
{"error": {"code", "message"}} envelope on stderr with exit 3
(cli.main); argparse usage errors exit 2; unresolved function in
decompile/cfg/pseudo prints "no function ..." and exits 2
(cli._resolve_fn). Service layer clamps pagination limits to >= 0
(service.functions_page/strings_page), so negative limits yield an
empty page; offsets past the end yield empty items with true total.
HTTP maps FileNotFoundError -> 404 not_found and ValueError -> 400
invalid_input (http_api.create_app); patch is 403 write_disabled
unless write enabled. MCP tool failures surface as result.isError,
unknown JSON-RPC methods as a protocol error.
"""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
BENCH = ROOT / "bench"
SRC = ROOT / "src"
CORPUS = str(BENCH / "corpus_arm64")
sys.path.insert(0, str(SRC))


def run_cli(*args):
    env = dict(os.environ, PYTHONPATH=str(SRC))
    return subprocess.run(
        [sys.executable, "-m", "rea_disassembler", *args],
        capture_output=True, text=True, env=env, timeout=120)


def assert_cli_envelope(r, code, rc=3):
    assert r.returncode == rc, f"rc={r.returncode}\n{r.stdout}\n{r.stderr}"
    err = json.loads(r.stderr)
    assert err["error"]["code"] == code
    assert err["error"]["message"]


def assert_usage_error(r):
    assert r.returncode == 2, f"rc={r.returncode}\n{r.stdout}\n{r.stderr}"
    assert r.stdout == ""
    assert "usage:" in r.stderr and "error" in r.stderr


@pytest.mark.parametrize("cmd", ["info", "functions", "strings", "disasm"])
def test_cli_missing_file_is_not_found_envelope(cmd):
    assert_cli_envelope(run_cli(cmd, "/nonexistent_rea_nope.bin"), "not_found")


def test_cli_bench_missing_file_is_not_found_envelope():
    assert_cli_envelope(run_cli("bench", "/nonexistent_rea_nope.bin"), "not_found")


@pytest.mark.parametrize("data", [b"\xde\xad\xbe\xef" * 16, b"",
                                  b"\x7fELF" + b"\x00" * 8,
                                  b"plain text, not a binary\n" * 4])
def test_cli_malformed_binary_is_invalid_input(tmp_path, data):
    bad = tmp_path / "bad.bin"
    bad.write_bytes(data)
    assert_cli_envelope(run_cli("info", str(bad), "--json"), "invalid_input")


def test_cli_raw_without_arch_is_invalid_input(tmp_path):
    raw = tmp_path / "raw.bin"
    raw.write_bytes(b"\xff\xff\xff\xff" * 4)
    assert_cli_envelope(run_cli("info", str(raw), "--raw"), "invalid_input")


def test_cli_raw_unsupported_arch_is_invalid_input(tmp_path):
    raw = tmp_path / "raw.bin"
    raw.write_bytes(b"\xff\xff\xff\xff" * 4)
    r = run_cli("info", str(raw), "--raw", "--arch", "sparc")
    assert_cli_envelope(r, "invalid_input")
    assert "unsupported architecture" in r.stderr


def test_cli_unknown_command_is_usage_error():
    assert_usage_error(run_cli("nosuchcmd", CORPUS))


def test_cli_missing_file_argument_is_usage_error():
    assert_usage_error(run_cli("info"))


def test_cli_unknown_flag_is_usage_error():
    assert_usage_error(run_cli("info", CORPUS, "--bogus-flag"))


def test_cli_missing_required_patch_out_is_usage_error():
    assert_usage_error(run_cli("patch", CORPUS, "0x1000004b0", "nop"))


def test_cli_non_integer_limit_is_usage_error():
    assert_usage_error(run_cli("functions", CORPUS, "--json", "--limit", "abc"))


def test_cli_no_command_is_usage_error():
    assert_usage_error(run_cli())


@pytest.mark.parametrize("cmd", ["decompile", "pseudo", "cfg"])
@pytest.mark.parametrize("target", ["no_such_fn_xyz", "0xdeadbeef", "not-an-address!!"])
def test_cli_unknown_function_exits_2_with_plain_message(cmd, target):
    r = run_cli(cmd, CORPUS, target)
    assert r.returncode == 2, f"rc={r.returncode}\n{r.stdout}\n{r.stderr}"
    assert f"no function {target!r}" in r.stderr


@pytest.mark.parametrize("args", [
    ("disasm", CORPUS, "--function", "nothex"),
    ("assemble", CORPUS, "nothex", "nop"),
    ("patch", CORPUS, "nothex", "nop", "-o", "out.bin"),
])
def test_cli_invalid_address_syntax_is_invalid_input(args, tmp_path):
    args = tuple(str(tmp_path / a) if a == "out.bin" else a for a in args)
    assert_cli_envelope(run_cli(*args), "invalid_input")


def test_cli_disasm_unknown_address_lists_no_function():
    r = run_cli("disasm", CORPUS, "--function", "0xdeadbeef")
    assert r.returncode == 0
    assert r.stdout.startswith("no function at 0xdeadbeef")


def test_cli_functions_offset_beyond_end_is_empty_page():
    r = run_cli("functions", CORPUS, "--json", "--offset", "99999")
    assert r.returncode == 0
    page = json.loads(r.stdout)
    assert page["total"] == 10 and page["offset"] == 99999 and page["items"] == []


def test_cli_strings_offset_beyond_end_is_empty_page():
    r = run_cli("strings", CORPUS, "--json", "--offset", "99999")
    assert r.returncode == 0
    page = json.loads(r.stdout)
    assert page["total"] == 3 and page["items"] == []


def test_cli_functions_zero_limit_is_empty_page():
    r = run_cli("functions", CORPUS, "--json", "--limit", "0")
    assert r.returncode == 0
    page = json.loads(r.stdout)
    assert page["total"] == 10 and page["items"] == []


def test_cli_assemble_invalid_instruction_is_invalid_input():
    r = run_cli("assemble", CORPUS, "0x1000004b0", "this is not an instruction xyz")
    assert_cli_envelope(r, "invalid_input")
    assert "cannot assemble" in r.stderr


def test_cli_patch_unmapped_address_is_invalid_input(tmp_path):
    r = run_cli("patch", CORPUS, "0xdeadbeef", "nop", "-o", str(tmp_path / "out.bin"))
    assert_cli_envelope(r, "invalid_input")
    assert "not mapped" in r.stderr


def test_cli_patch_output_in_missing_directory_is_not_found(tmp_path):
    r = run_cli("patch", CORPUS, "0x1000004b0", "nop", "-o", str(tmp_path / "no_such_dir" / "out.bin"))
    assert_cli_envelope(r, "not_found")


def test_cli_debug_missing_target_reports_not_ok():
    if not shutil.which("lldb"):
        pytest.skip("lldb required")
    r = run_cli("debug", "/nonexistent_rea_nope.bin")
    assert r.returncode == 0, f"rc={r.returncode}\n{r.stdout}\n{r.stderr}"
    doc = json.loads(r.stdout)
    assert doc["ok"] is False
    assert doc["stop_reason"] is None and doc["frames"] == []


def test_service_negative_limit_is_clamped_to_empty_page():
    from rea_disassembler import service
    page = service.functions_page(CORPUS, limit=-1)
    assert page["total"] == 10 and page["limit"] == 0 and page["items"] == []
    spage = service.strings_page(CORPUS, limit=-5, offset=99999)
    assert spage["total"] == 3 and spage["limit"] == 0 and spage["items"] == []


def test_service_offset_beyond_end_is_empty_page():
    from rea_disassembler import service
    page = service.functions_page(CORPUS, offset=99999)
    assert page["total"] == 10 and page["items"] == []


@pytest.mark.parametrize("fn_name", ["disassemble", "decompile"])
def test_service_unknown_function_raises_value_error(fn_name):
    from rea_disassembler import service
    with pytest.raises(ValueError, match="no function"):
        getattr(service, fn_name)(CORPUS, "no_such_fn_xyz")


def test_service_missing_file_raises_not_found():
    from rea_disassembler import service
    with pytest.raises(FileNotFoundError):
        service.overview("/nonexistent_rea_nope.bin")


@pytest.fixture(scope="module")
def client():
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from rea_disassembler.http_api import create_app
    return TestClient(create_app(), raise_server_exceptions=False)


@pytest.fixture(scope="module")
def write_client():
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from rea_disassembler.http_api import create_app
    return TestClient(create_app(enable_write=True), raise_server_exceptions=False)


def test_http_missing_path_param_is_422(client):
    for route in ("/v1/info", "/v1/functions", "/v1/strings"):
        r = client.get(route)
        assert r.status_code == 422, (route, r.text)
        assert r.json()["detail"]


def test_http_missing_target_param_is_422(client):
    for route in ("/v1/disassemble", "/v1/decompile"):
        r = client.get(route, params={"path": CORPUS})
        assert r.status_code == 422, (route, r.text)


def test_http_invalid_limit_type_is_422(client):
    r = client.get("/v1/functions", params={"path": CORPUS, "limit": "abc"})
    assert r.status_code == 422


def test_http_missing_file_is_404_envelope(client):
    r = client.get("/v1/info", params={"path": "/nonexistent_rea_nope.bin"})
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "not_found"


def test_http_malformed_file_is_400_envelope(client, tmp_path):
    bad = tmp_path / "bad.bin"
    bad.write_bytes(b"\xde\xad\xbe\xef" * 16)
    r = client.get("/v1/info", params={"path": str(bad)})
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "invalid_input"


@pytest.mark.parametrize("route", ["/v1/disassemble", "/v1/decompile"])
@pytest.mark.parametrize("target", ["no_such_fn_xyz", "0xdeadbeef", "not-an-address!!"])
def test_http_unknown_function_is_400_envelope(client, route, target):
    r = client.get(route, params={"path": CORPUS, "target": target})
    assert r.status_code == 400, r.text
    assert r.json()["error"]["code"] == "invalid_input"
    assert "no function" in r.json()["error"]["message"]


def test_http_negative_limit_is_clamped_to_empty_page(client):
    r = client.get("/v1/functions", params={"path": CORPUS, "limit": -1})
    assert r.status_code == 200
    assert r.json()["limit"] == 0 and r.json()["items"] == [] and r.json()["total"] == 10


def test_http_offset_beyond_end_is_empty_page(client):
    r = client.get("/v1/functions", params={"path": CORPUS, "offset": 99999})
    assert r.status_code == 200
    assert r.json()["total"] == 10 and r.json()["items"] == []


def test_http_unknown_route_is_404(client):
    assert client.get("/v1/nope").status_code == 404


def test_http_patch_disabled_is_403_write_disabled(client):
    r = client.post("/v1/patch", json={"path": CORPUS, "address": "0x1000004b0", "asm": "nop", "out": "/tmp/x"})
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "write_disabled"


def test_http_patch_missing_fields_is_422(client):
    assert client.post("/v1/patch", json={"path": CORPUS}).status_code == 422


def test_http_patch_enabled_unmapped_address_is_400(write_client, tmp_path):
    r = write_client.post("/v1/patch", json={"path": CORPUS, "address": "0xdeadbeef", "asm": "nop", "out": str(tmp_path / "out.bin")})
    assert r.status_code == 400 and r.json()["error"]["code"] == "invalid_input"


def test_http_patch_enabled_invalid_address_syntax_is_400(write_client, tmp_path):
    r = write_client.post("/v1/patch", json={"path": CORPUS, "address": "nothex", "asm": "nop", "out": str(tmp_path / "out.bin")})
    assert r.status_code == 400 and r.json()["error"]["code"] == "invalid_input"


def test_http_patch_enabled_missing_file_is_404(write_client, tmp_path):
    r = write_client.post("/v1/patch", json={"path": "/nonexistent_rea_nope.bin", "address": "0x1000004b0", "asm": "nop", "out": str(tmp_path / "out.bin")})
    assert r.status_code == 404 and r.json()["error"]["code"] == "not_found"


def test_http_patch_enabled_output_in_missing_dir_is_404(write_client, tmp_path):
    r = write_client.post("/v1/patch", json={"path": CORPUS, "address": "0x1000004b0", "asm": "nop", "out": str(tmp_path / "no_such_dir" / "out.bin")})
    assert r.status_code == 404 and r.json()["error"]["code"] == "not_found"


def test_http_patch_enabled_invalid_asm_is_400(write_client, tmp_path):
    r = write_client.post("/v1/patch", json={"path": CORPUS, "address": "0x1000004b0", "asm": "this is not an instruction xyz", "out": str(tmp_path / "out.bin")})
    assert r.status_code == 400 and r.json()["error"]["code"] == "invalid_input"


def test_mcp_failure_matrix():
    try:
        import mcp  # noqa: F401
    except ImportError:
        pytest.skip("mcp SDK not installed (pip install 'rea-disassembler[mcp]')")
    env = dict(os.environ, PYTHONPATH=str(SRC))
    proc = subprocess.Popen([sys.executable, "-m", "rea_disassembler.mcp_server"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)

    def rpc(payload):
        proc.stdin.write((json.dumps(payload) + "\n").encode())
        proc.stdin.flush()
        line = proc.stdout.readline()
        assert line, "MCP server closed stdout without a response"
        return json.loads(line)

    def call(id_, name, arguments):
        return rpc({"jsonrpc": "2.0", "id": id_, "method": "tools/call", "params": {"name": name, "arguments": arguments}})

    try:
        init = rpc({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}})
        assert init["result"]["serverInfo"]["name"]
        proc.stdin.write(b'{"jsonrpc": "2.0", "method": "notifications/initialized"}\n')
        proc.stdin.flush()
        unknown = call(2, "no_such_tool", {})
        assert unknown["result"].get("isError") is True
        assert "Unknown tool" in unknown["result"]["content"][0]["text"]
        assert call(3, "binary_overview", {})["result"].get("isError") is True
        assert call(4, "binary_overview", {"path": 123})["result"].get("isError") is True
        assert call(5, "list_functions", {"path": CORPUS, "limit": "abc"})["result"].get("isError") is True
        assert call(6, "binary_overview", {"path": "/nonexistent_rea_nope.bin"})["result"].get("isError") is True
        assert call(7, "disassemble_function", {"path": CORPUS, "target": "no_such_fn_xyz"})["result"].get("isError") is True
        clamped = call(8, "list_functions", {"path": CORPUS, "limit": -1, "offset": 99999})
        assert clamped["result"].get("isError") is False
        page = json.loads(clamped["result"]["content"][0]["text"])
        assert page["total"] == 10 and page["limit"] == 0 and page["items"] == []
        bad_method = rpc({"jsonrpc": "2.0", "id": 9, "method": "no_such_method", "params": {}})
        assert "error" in bad_method
    finally:
        proc.terminate()
