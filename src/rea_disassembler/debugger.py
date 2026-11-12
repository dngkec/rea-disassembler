"""Debugger: the native target is run under the system LLDB (batch mode).

A debug plan is a list of LLDB commands built from declared breakpoints;
output is captured verbatim and also summarised (stop reason, registers,
backtrace frames) so callers and tests assert on structure, not on a
terminal.  This launches the target exactly as declared — nothing more.
"""
from __future__ import annotations

import re
import subprocess


def lldb_path() -> str | None:
    import shutil
    return shutil.which("lldb")


def debug_run(target: str, breakpoints: list[str] | None = None,
              commands: list[str] | None = None, timeout: int = 120) -> dict:
    """Run `target` under LLDB: set breakpoints, run, backtrace, registers.

    breakpoints: addresses (`0x…`), function names, or `file:line`.
    Returns {ok, output, stop_reason, frames, registers}.
    """
    exe = lldb_path()
    if exe is None:
        raise RuntimeError("lldb not found on PATH")
    script = [f"target create {target}"]
    for bp in breakpoints or ["main"]:
        if bp.startswith("0x"):
            script.append(f"breakpoint set --address {bp}")
        elif ":" in bp and not bp.startswith("/"):
            f, _, line = bp.rpartition(":")
            script.append(f"breakpoint set --file {f} --line {line}")
        else:
            # Mach-O symbols carry a leading underscore that LLDB names
            # do not: _fib in the file is `fib` to the debugger.
            script.append(f"breakpoint set --name {bp.lstrip('_')}")
    script += ["run", "thread backtrace", "register read"]
    script += list(commands or [])
    script += ["kill", "quit"]
    argv = [exe, "-b"]
    for cmd in script:
        argv += ["-o", cmd]
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        out = r.stdout + r.stderr
        ok = r.returncode == 0
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or b"").decode("utf-8", "replace") if isinstance(e.stdout, bytes) \
            else (e.stdout or "")
        ok = False
    stop = None
    m = re.search(r"stop reason = ([^\n]+)", out)
    if m:
        stop = m.group(1).strip()
    frames = re.findall(r"frame #\d+: [^\n]*?`([^\n]+)", out)
    regs = dict(re.findall(r"\b(x\d+|rax|rbx|rcx|rdx|rsi|rdi|rsp|rbp|rip|pc|sp)\s+=\s+(0x[0-9a-fA-F]+)", out))
    return {"ok": ok, "output": out, "stop_reason": stop,
            "frames": frames[:20], "registers": regs}
