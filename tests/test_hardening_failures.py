"""Hardening failure-case tests (new cases not in test_failure_matrix).

Contract (README + cli.main docstring + http_api docstring):
- CLI runtime/analysis failures: JSON {"error": {"code", "message"}}
  envelope on stderr, exit 3, never a raw traceback. Usage errors: exit 2.
- HTTP runtime/input failures: same shared envelope, a 4xx status,
  never an unhandled 500.
- Pagination: a clamped contract. Negative limit/offset are clamped
  to >= 0, the reported limit/offset reflect the clamping, and items
  are exactly the page that clamped values produce. In particular a
  negative offset must NOT yield Python's negative-index tail slice.
- Patch must not overwrite an existing output file (no data loss):
  an existing sentinel file or directory at `out` is left untouched
  and the failure is reported cleanly.
- Optional/external-tool failures (lldb missing) and invalid serve
  ports fail cleanly, without tracebacks and without starting a server.

Ambiguity note: docs do not spell out negative-pagination or
patch-overwrite semantics; the safer clamping / no-overwrite
expectations above are encoded deliberately.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
BENCH = ROOT / "bench"
SRC = ROOT / "src"
CORPUS = str(BENCH / "corpus_arm64")
PATCH_ADDR = "0x1000004b0"
SENTINEL = b"SENTINEL-DO-NOT-OVERWRITE\x00\x01\x02"
sys.path.insert(0, str(SRC))


def run_cli(*args, env_extra=None, timeout=60):
    env = dict(os.environ, PYTHONPATH=str(SRC))
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, "-m", "rea_disassembler", *args],
        capture_output=True, text=True, env=env, timeout=timeout)


def assert_no_traceback(r):
    stderr = getattr(r, "stderr", "") or ""
    stdout = getattr(r, "stdout", None)
    if stdout is None:
        stdout = getattr(r, "text", "") or ""
    assert "Traceback" not in stderr, stderr
    assert "Traceback" not in stdout, stdout


def assert_cli_error_envelope(r, rc=3):
    assert_no_traceback(r)
    assert r.returncode == rc, f"rc={r.returncode}\n{r.stdout}\n{r.stderr}"
    err = json.loads(r.stderr)
    assert err["error"]["code"]
    assert err["error"]["message"]


def assert_http_error_envelope(r):
    assert_no_traceback(r)
    assert r.status_code != 500, r.text
    assert 400 <= r.status_code < 500, (r.status_code, r.text)
    body = r.json()
    assert body["error"]["code"]
    assert body["error"]["message"]


def assert_clamped_page(page, reference_items):
    assert page["limit"] >= 0, page
    assert page["offset"] >= 0, page
    assert page["items"] == reference_items, page


def test_cli_info_directory_is_clean_envelope_not_traceback(tmp_path):
    r = run_cli("info", str(tmp_path), "--json")
    assert_cli_error_envelope(r, rc=3)


def test_cli_info_directory_plain_mode_is_clean_envelope(tmp_path):
    r = run_cli("info", str(tmp_path))
    assert_cli_error_envelope(r, rc=3)


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
    return TestClient(create_app(enable_write=True),
                      raise_server_exceptions=False)


def test_http_info_directory_is_error_envelope_not_500(client, tmp_path):
    r = client.get("/v1/info", params={"path": str(tmp_path)})
    assert_http_error_envelope(r)


def test_http_functions_directory_is_error_envelope_not_500(client, tmp_path):
    r = client.get("/v1/functions", params={"path": str(tmp_path)})
    assert_http_error_envelope(r)


def test_service_functions_negative_offset_is_clamped_not_tail():
    from rea_disassembler import service
    expected = service.functions_page(CORPUS, limit=2, offset=0)
    page = service.functions_page(CORPUS, limit=2, offset=-1)
    assert_clamped_page(page, expected["items"])
    assert page["offset"] == 0
    all_items = service.functions_page(CORPUS, limit=5000, offset=0)["items"]
    assert page["items"] != all_items[-1:]


def test_service_strings_negative_offset_is_clamped_not_tail():
    from rea_disassembler import service
    expected = service.strings_page(CORPUS, limit=2, offset=0)
    page = service.strings_page(CORPUS, limit=2, offset=-2)
    assert_clamped_page(page, expected["items"])
    assert page["offset"] == 0


def test_service_negative_limit_is_clamped():
    from rea_disassembler import service
    for page in (service.functions_page(CORPUS, limit=-3),
                 service.strings_page(CORPUS, limit=-3)):
        assert page["limit"] == 0 and page["items"] == []
        assert page["offset"] >= 0


def test_service_negative_limit_and_offset_together():
    from rea_disassembler import service
    page = service.functions_page(CORPUS, limit=-3, offset=-3)
    assert page["limit"] == 0 and page["offset"] == 0 and page["items"] == []


@pytest.mark.parametrize("route", ["/v1/functions", "/v1/strings"])
def test_http_negative_offset_is_clamped_not_tail(client, route):
    ref = client.get(route, params={"path": CORPUS, "limit": 2, "offset": 0})
    assert ref.status_code == 200
    r = client.get(route, params={"path": CORPUS, "limit": 2, "offset": -1})
    assert r.status_code == 200, r.text
    assert_clamped_page(r.json(), ref.json()["items"])
    assert r.json()["offset"] == 0


@pytest.mark.parametrize("route", ["/v1/functions", "/v1/strings"])
def test_http_negative_limit_is_clamped(client, route):
    r = client.get(route, params={"path": CORPUS, "limit": -3})
    assert r.status_code == 200, r.text
    assert r.json()["limit"] == 0 and r.json()["items"] == []
    assert r.json()["offset"] >= 0


@pytest.mark.parametrize("cmd", ["functions", "strings"])
def test_cli_json_negative_offset_is_clamped_not_tail(cmd):
    ref = run_cli(cmd, CORPUS, "--json", "--limit", "2", "--offset", "0")
    assert ref.returncode == 0, ref.stderr
    r = run_cli(cmd, CORPUS, "--json", "--limit", "2", "--offset", "-1")
    assert_no_traceback(r)
    assert r.returncode == 0, f"rc={r.returncode}\n{r.stderr}"
    page = json.loads(r.stdout)
    assert_clamped_page(page, json.loads(ref.stdout)["items"])
    assert page["offset"] == 0


@pytest.mark.parametrize("cmd", ["functions", "strings"])
def test_cli_json_negative_limit_is_clamped(cmd):
    r = run_cli(cmd, CORPUS, "--json", "--limit", "-3")
    assert_no_traceback(r)
    assert r.returncode == 0, f"rc={r.returncode}\n{r.stderr}"
    page = json.loads(r.stdout)
    assert page["limit"] == 0 and page["items"] == []
    assert page["offset"] >= 0


def test_http_patch_out_is_existing_directory_is_clean_error(write_client, tmp_path):
    out_dir = tmp_path / "existing_dir"
    out_dir.mkdir()
    r = write_client.post("/v1/patch", json={
        "path": CORPUS, "address": PATCH_ADDR, "asm": "nop",
        "out": str(out_dir)})
    assert_http_error_envelope(r)
    assert out_dir.is_dir()
    assert list(out_dir.iterdir()) == []


def test_http_patch_out_existing_sentinel_file_is_not_overwritten(write_client, tmp_path):
    sentinel = tmp_path / "patched_out"
    sentinel.write_bytes(SENTINEL)
    r = write_client.post("/v1/patch", json={
        "path": CORPUS, "address": PATCH_ADDR, "asm": "nop",
        "out": str(sentinel)})
    assert_http_error_envelope(r)
    assert sentinel.read_bytes() == SENTINEL


def test_cli_patch_existing_sentinel_file_is_not_overwritten(tmp_path):
    sentinel = tmp_path / "patched_out"
    sentinel.write_bytes(SENTINEL)
    r = run_cli("patch", CORPUS, PATCH_ADDR, "nop", "-o", str(sentinel))
    assert_cli_error_envelope(r, rc=3)
    assert sentinel.read_bytes() == SENTINEL


def test_cli_patch_out_is_existing_directory_is_clean_envelope(tmp_path):
    out_dir = tmp_path / "existing_dir"
    out_dir.mkdir()
    r = run_cli("patch", CORPUS, PATCH_ADDR, "nop", "-o", str(out_dir))
    assert_cli_error_envelope(r, rc=3)
    assert out_dir.is_dir()
    assert list(out_dir.iterdir()) == []


def test_cli_debug_without_lldb_on_path_is_clean_failure():
    r = run_cli("debug", CORPUS, "--break", "_fib",
                env_extra={"PATH": "/nonexistent"}, timeout=60)
    assert_cli_error_envelope(r, rc=3)


def test_cli_serve_invalid_port_fails_cleanly_without_starting():
    env = dict(os.environ, PYTHONPATH=str(SRC))
    proc = subprocess.Popen(
        [sys.executable, "-m", "rea_disassembler", "serve", "--port", "99999"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
    try:
        _, stderr = proc.communicate(timeout=20)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        pytest.fail("serve with port 99999 did not exit (server started?)")
    assert proc.returncode != 0
    assert proc.returncode in (2, 3), (proc.returncode, stderr)
    assert "Traceback" not in stderr, stderr
    lowered = stderr.lower()
    assert any(w in lowered for w in ("usage", "error", "port", "invalid", "overflow", "range")), stderr
