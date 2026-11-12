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

function tmpDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function runLauncherIn(dir, args, env = {}) {
  return spawnSync(process.execPath, [LAUNCHER, ...args], {
    encoding: "utf8",
    env: { ...process.env, READIS_CACHE_DIR: dir, ...env },
  });
}

function nodeScript(body) {
  return `#!${process.execPath}\n"use strict";\n${body}\n`;
}

function writeExec(file, content, mode = 0o755) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, content, { mode });
  return file;
}

// Fake venv interpreter: pip/mcp probes are configurable, anything else is
// treated as an engine launch and echoed.
function engineScript({ pipStatus = 0, mcpStatus = 0 } = {}) {
  return nodeScript(`
const a = process.argv.slice(2);
if (a[0] === "-c" && String(a[1]).includes("import mcp")) process.exit(${mcpStatus});
if (a[0] === "-c") process.exit(0);
if (a[0] === "-m" && a[1] === "pip") { console.error("fake-pip-output"); process.exit(${pipStatus}); }
console.log("engine-args: " + a.join(" "));
console.error("engine-stderr");
if (a.includes("exit42")) process.exit(42);
if (a.includes("sigterm")) process.kill(process.pid, "SIGTERM");
process.exit(0);
`);
}

function cachedCache({ engine = engineScript(), marker = true, mode = 0o755, dir = tmpDir("readis-cached-") } = {}) {
  const py = writeExec(path.join(dir, "venv", "bin", "python"), engine, mode);
  if (marker) fs.writeFileSync(path.join(dir, ".ready"), "fake\n");
  return { dir, py };
}

// Fake system interpreter used via READIS_PYTHON. Handles the version probe
// (-c) and "-m venv <dir>", optionally materialising a venv python.
function externalPython({
  versionStatus = 0,
  venvStatus = 0,
  engine = engineScript(),
  createVenvPython = true,
  venvMode = 0o755,
} = {}) {
  const file = path.join(tmpDir("readis-extpy-"), "python");
  return writeExec(
    file,
    nodeScript(`
const fs = require("fs");
const path = require("path");
const a = process.argv.slice(2);
if (a[0] === "-c") process.exit(${versionStatus});
if (a[0] === "-m" && a[1] === "venv") {
  if (${venvStatus} !== 0) process.exit(${venvStatus});
  if (${createVenvPython}) {
    const bin = path.join(a[2], "bin");
    fs.mkdirSync(bin, { recursive: true });
    fs.writeFileSync(path.join(bin, "python"), ${JSON.stringify(engine)}, { mode: ${venvMode} });
  }
  process.exit(0);
}
process.exit(0);
`)
  );
}

function assertCleanExit3(r, pattern) {
  assert.equal(r.status, 3, `stderr was: ${r.stderr}`);
  assert.match(r.stderr, pattern);
  assert.match(r.stderr, /rea-disassembler:/);
  assert.doesNotMatch(r.stderr, /\n\s+at\s+\S+/); // no uncaught stack trace
  assert.doesNotMatch(r.stderr, /node:internal/);
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

test("marker present but venv python missing triggers clean reprovisioning", () => {
  const dir = tmpDir("readis-reprovision-");
  fs.writeFileSync(path.join(dir, ".ready"), "stale\n");
  const py = externalPython();
  const r = runLauncherIn(dir, ["info", "x"], {
    READIS_PYTHON: py,
    READIS_PIP_PACKAGE: "fake-engine==0",
  });
  assert.equal(r.status, 0, `stderr was: ${r.stderr}`);
  assert.match(r.stdout, /engine-args: -m rea_disassembler info x/);
  assert.equal(fs.readFileSync(path.join(dir, ".ready"), "utf8"), "fake-engine==0\n");
});

test("reprovisioning fails cleanly when venv creation fails", () => {
  const dir = tmpDir("readis-venvfail-");
  fs.writeFileSync(path.join(dir, ".ready"), "stale\n");
  const r = runLauncherIn(dir, ["info", "x"], {
    READIS_PYTHON: externalPython({ venvStatus: 1 }),
  });
  assertCleanExit3(r, /failed to create a virtual environment/);
  assert.equal(fs.readFileSync(path.join(dir, ".ready"), "utf8"), "stale\n");
});

test("pip install failure after fake venv creation is exit 3 and writes no marker", () => {
  const dir = tmpDir("readis-pipfail-");
  const r = runLauncherIn(dir, ["info", "x"], {
    READIS_PYTHON: externalPython({ engine: engineScript({ pipStatus: 2 }) }),
  });
  assertCleanExit3(r, /engine installation failed/);
  assert.match(r.stderr, /fake-pip-output/);
  assert.equal(fs.existsSync(path.join(dir, ".ready")), false);
});

test("provisioning with a venv python that pip cannot spawn is a clean exit 3", () => {
  const dir = tmpDir("readis-pipspawn-");
  const r = runLauncherIn(dir, ["info", "x"], {
    READIS_PYTHON: externalPython({ createVenvPython: false }),
  });
  // bin/readis.js run() throws spawnSync's ENOENT instead of exiting 3.
  assertCleanExit3(r, /rea-disassembler:/);
});

test("READIS_PYTHON too old with restricted PATH is a clean exit 3", () => {
  const dir = tmpDir("readis-oldpy-");
  const r = runLauncherIn(dir, ["info", "x"], {
    PATH: "/nonexistent",
    READIS_PYTHON: externalPython({ versionStatus: 1 }),
  });
  assertCleanExit3(r, /no Python >= 3\.11 found/);
});

test("READIS_PYTHON pointing at a missing interpreter with restricted PATH is exit 3", () => {
  const dir = tmpDir("readis-nopyfile-");
  const r = runLauncherIn(dir, ["info", "x"], {
    PATH: "/nonexistent",
    READIS_PYTHON: path.join(dir, "no-such-python"),
  });
  assertCleanExit3(r, /no Python >= 3\.11 found/);
});

test("cache dir that is an existing file is a clean exit 3, not a stack trace", () => {
  const dir = tmpDir("readis-cachefile-");
  const file = path.join(dir, "cache-as-file");
  fs.writeFileSync(file, "not a directory\n");
  const r = runLauncherIn(file, ["info", "x"], {
    READIS_PYTHON: externalPython(),
  });
  // bin/readis.js fs.mkdirSync() throws uncaught here instead of exiting 3.
  assertCleanExit3(r, /rea-disassembler:/);
});

test("cache path containing spaces provisions and forwards", () => {
  const parent = tmpDir("readis-space-");
  const dir = path.join(parent, "cache with spaces");
  fs.mkdirSync(dir, { recursive: true });
  const r = runLauncherIn(dir, ["info", "a b"], {
    READIS_PYTHON: externalPython(),
    READIS_PIP_PACKAGE: "fake-engine==0",
  });
  assert.equal(r.status, 0, `stderr was: ${r.stderr}`);
  assert.match(r.stdout, /engine-args: -m rea_disassembler info a b/);
});

test("cached engine under a cache path containing spaces forwards", () => {
  const parent = tmpDir("readis-space2-");
  const dir = path.join(parent, "cache with spaces");
  const { py } = cachedCache({ dir });
  assert.ok(py.includes(" "));
  const r = runLauncherIn(dir, ["info", "x"]);
  assert.equal(r.status, 0, `stderr was: ${r.stderr}`);
  assert.match(r.stdout, /engine-args: -m rea_disassembler info x/);
});

test("arguments with spaces and shell metacharacters are data, never shell", () => {
  const sentinelDir = tmpDir("readis-sentinel-");
  const sentinel = path.join(sentinelDir, "pwned");
  const payloads = [
    "a b",
    `; touch ${sentinel}`,
    `$(touch ${sentinel})`,
    "`touch " + sentinel + "`",
    `x > ${sentinel}`,
    "*",
    "it's",
    '"quoted"',
  ];
  const r = runLauncher(["info", ...payloads]);
  assert.equal(r.status, 0, `stderr was: ${r.stderr}`);
  for (const p of payloads) assert.ok(r.stdout.includes(p), `stdout missing ${p}: ${r.stdout}`);
  assert.equal(fs.existsSync(sentinel), false);
});

test("cached engine non-zero exit code is forwarded exactly (42)", () => {
  const { dir } = cachedCache();
  const r = runLauncherIn(dir, ["exit42"]);
  assert.equal(r.status, 42);
  assert.match(r.stderr, /engine-stderr/);
});

test("cached engine killed by SIGTERM kills the launcher with the same signal", () => {
  const { dir } = cachedCache();
  const r = runLauncherIn(dir, ["sigterm"]);
  assert.equal(r.status, null);
  assert.equal(r.signal, "SIGTERM");
});

test("non-executable cached venv python is a clean failed-to-launch exit 3", () => {
  const { dir } = cachedCache({ mode: 0o644 });
  const r = runLauncherIn(dir, ["info", "x"]);
  assertCleanExit3(r, /failed to launch engine/);
});

test("cached venv python with a missing interpreter is a clean failed-to-launch exit 3", () => {
  const { dir } = cachedCache({ engine: "#!/nonexistent/readis-python\nexit 0\n" });
  const r = runLauncherIn(dir, ["info", "x"]);
  assertCleanExit3(r, /failed to launch engine/);
});

test("mcp mode: failed mcp probe plus failed pip install is a clean exit 3", () => {
  const { dir } = cachedCache({ engine: engineScript({ mcpStatus: 1, pipStatus: 1 }) });
  const r = runLauncherIn(dir, ["mcp"]);
  assertCleanExit3(r, /failed to install the MCP extra/);
  assert.match(r.stderr, /installing MCP extra/);
  assert.doesNotMatch(r.stdout, /engine-args/);
});

test("mcp mode: failed mcp probe plus successful pip install launches the MCP server", () => {
  const { dir } = cachedCache({ engine: engineScript({ mcpStatus: 1, pipStatus: 0 }) });
  const r = runLauncherIn(dir, ["mcp"]);
  assert.equal(r.status, 0, `stderr was: ${r.stderr}`);
  assert.match(r.stdout, /engine-args: -m rea_disassembler\.mcp_server/);
});

