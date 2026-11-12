// Launcher contract tests: argv/stdout/stderr/exit-code forwarding and
// the first-run error paths.  A fake engine venv stands in for pip.
"use strict";

const { test } = require("node:test");
const assert = require("node:assert");
const { spawnSync } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

const LAUNCHER = path.join(__dirname, "..", "bin", "readis.js");

function fakeCache() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "readis-cache-"));
  const bin = path.join(dir, "venv", "bin");
  fs.mkdirSync(bin, { recursive: true });
  const py = path.join(bin, "python");
  fs.writeFileSync(
    py,
    [
      "#!/bin/sh",
      'echo "engine-args: $@"',
      'echo "engine-stderr" 1>&2',
      'for a in "$@"; do if [ "$a" = "fail" ]; then exit 7; fi; done',
      "exit 0",
      "",
    ].join("\n"),
    { mode: 0o755 }
  );
  fs.writeFileSync(path.join(dir, ".ready"), "fake\n");
  return dir;
}

function runLauncher(args, env = {}) {
  return spawnSync(process.execPath, [LAUNCHER, ...args], {
    encoding: "utf8",
    env: { ...process.env, READIS_CACHE_DIR: fakeCache(), ...env },
  });
}

test("forwards argv and stdout to the engine module", () => {
  const r = runLauncher(["info", "/bin/ls", "--json"]);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /-m rea_disassembler info \/bin\/ls --json/);
});

test("forwards stderr and exit code", () => {
  const r = runLauncher(["fail"]);
  assert.equal(r.status, 7);
  assert.match(r.stderr, /engine-stderr/);
});

test("mcp subcommand launches the MCP server module", () => {
  const r = runLauncher(["mcp"]);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /-m rea_disassembler\.mcp_server/);
  assert.doesNotMatch(r.stdout, /\bmcp\b.*rea_disassembler /);
});

test("missing python >= 3.11 is a clear exit-3 error", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "readis-nopy-"));
  const r = spawnSync(process.execPath, [LAUNCHER, "info", "x"], {
    encoding: "utf8",
    env: { PATH: "/nonexistent", HOME: os.homedir(), READIS_CACHE_DIR: dir },
  });
  assert.equal(r.status, 3);
  assert.match(r.stderr, /Python >= 3\.11/);
});
