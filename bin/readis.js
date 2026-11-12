#!/usr/bin/env node
// rea-disassembler launcher: forwards to the Python engine, byte-exact.
//
// The engine is distributed on PyPI as `rea-disassembler`.  This shim
// keeps a managed virtualenv in the user cache
//   READIS_CACHE_DIR  (default: $XDG_CACHE_HOME/rea-disassembler/<ver>
//                      or ~/.cache/rea-disassembler/<ver>)
// and installs the pinned engine there on first run.  Afterwards it is a
// pure spawn: argv, stdout, stderr, and the exit code are the engine's.
//
// Overrides:
//   READIS_PYTHON        python >= 3.11 interpreter to use
//   READIS_PIP_PACKAGE   pip requirement to install (e.g. a local wheel
//                        path, for pre-release testing)
//   READIS_CACHE_DIR     where the managed venv lives
"use strict";

const { spawnSync, spawn } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

const VERSION = require("../package.json").version;

function cacheDir() {
  if (process.env.READIS_CACHE_DIR) return process.env.READIS_CACHE_DIR;
  const base =
    process.env.XDG_CACHE_HOME || path.join(os.homedir(), ".cache");
  return path.join(base, "rea-disassembler", VERSION);
}

function pythonOk(candidate) {
  const r = spawnSync(
    candidate,
    ["-c", "import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)"],
    { stdio: "ignore" }
  );
  return r.status === 0;
}

function findPython() {
  const candidates = [
    process.env.READIS_PYTHON,
    "python3.13",
    "python3.12",
    "python3.11",
    "python3",
    process.platform === "win32" ? "python" : null,
    process.platform === "win32" ? "py" : null,
  ].filter(Boolean);
  for (const c of candidates) {
    if (pythonOk(c)) return c;
  }
  return null;
}

function run(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { stdio: "inherit", ...opts });
  // A command that cannot be spawned at all is a provisioning failure,
  // handled by callers' clean exit-3 paths, not an uncaught exception.
  if (r.error) return 127;
  return r.status ?? 127;
}

function cleanExit3(message) {
  console.error(`rea-disassembler: ${message}`);
  process.exit(3);
}

function trySetupFs(operation, fn) {
  try {
    return fn();
  } catch (e) {
    return cleanExit3(`${operation}: ${e.message}`);
  }
}

function ensureEngine(dir, needMcp = false) {
  const marker = path.join(dir, ".ready");
  const venvPy =
    process.platform === "win32"
      ? path.join(dir, "venv", "Scripts", "python.exe")
      : path.join(dir, "venv", "bin", "python");
  if (fs.existsSync(marker) && fs.existsSync(venvPy)) {
    if (needMcp) {
      const probe = spawnSync(venvPy, ["-c", "import mcp"], { stdio: "ignore" });
      if (probe.status !== 0) {
        console.error("rea-disassembler: installing MCP extra ...");
        if (run(venvPy, ["-m", "pip", "install", "--quiet", "mcp>=1.2"]) !== 0) {
          console.error("rea-disassembler: failed to install the MCP extra.");
          process.exit(3);
        }
      }
    }
    return venvPy;
  }

  const python = findPython();
  if (!python) {
    console.error(
      "rea-disassembler: no Python >= 3.11 found on PATH. " +
        "Install Python 3.11+ or set READIS_PYTHON."
    );
    process.exit(3);
  }
  trySetupFs("failed to prepare the engine cache directory", () => {
    fs.mkdirSync(dir, { recursive: true });
  });
  const venv = path.join(dir, "venv");
  if (!fs.existsSync(venvPy)) {
    if (run(python, ["-m", "venv", venv]) !== 0) {
      console.error(
        "rea-disassembler: failed to create a virtual environment. " +
          "On Debian/Ubuntu install python3-venv; do not use --break-system-packages."
      );
      process.exit(3);
    }
  }
  const requirement =
    process.env.READIS_PIP_PACKAGE || `rea-disassembler[mcp,api]==${VERSION}`;
  console.error(`rea-disassembler: installing engine (${requirement}) …`);
  if (
    run(venvPy, ["-m", "pip", "install", "--quiet", requirement]) !== 0
  ) {
    console.error(
      "rea-disassembler: engine installation failed (see pip output above)."
    );
    process.exit(3);
  }
  trySetupFs("failed to record the installed engine", () => {
    fs.writeFileSync(marker, requirement + "\n");
  });
  if (needMcp) {
    const probe = spawnSync(venvPy, ["-c", "import mcp"], { stdio: "ignore" });
    if (probe.status !== 0) {
      if (run(venvPy, ["-m", "pip", "install", "--quiet", "mcp>=1.2"]) !== 0) {
        console.error("rea-disassembler: failed to install the MCP extra.");
        process.exit(3);
      }
    }
  }
  return venvPy;
}

function main() {
  const args = process.argv.slice(2);
  const mcp = args[0] === "mcp";
  const venvPy = ensureEngine(cacheDir(), mcp);
  const engineArgs = mcp
    ? ["-m", "rea_disassembler.mcp_server"]
    : ["-m", "rea_disassembler", ...args];
  const child = spawn(venvPy, engineArgs, { stdio: "inherit" });
  child.on("error", (e) => {
    console.error(`rea-disassembler: failed to launch engine: ${e.message}`);
    process.exit(3);
  });
  child.on("close", (code, signal) => {
    if (signal) {
      process.kill(process.pid, signal);
    } else {
      process.exit(code ?? 3);
    }
  });
}

main();
