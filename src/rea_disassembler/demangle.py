"""Symbol demangling: Itanium C++ via c++filt, Swift via `swift demangle`
when present.  Absence of a tool is a no-op, never an error."""
from __future__ import annotations

import shutil
import subprocess


def demangle(name: str) -> str:
    if name.startswith("_Z") or name.startswith("__Z"):
        tool = shutil.which("c++filt")
        if tool:
            try:
                out = subprocess.run([tool, "-n", name], capture_output=True,
                                     text=True, timeout=5)
                if out.returncode == 0 and out.stdout.strip():
                    return out.stdout.strip()
            except (OSError, subprocess.SubprocessError):
                pass
    if name.startswith(("$s", "$S", "_$s", "__$s")) or "Mn" in name[:6]:
        tool = shutil.which("swift")
        if tool:
            try:
                out = subprocess.run([tool, "demangle", name], capture_output=True,
                                     text=True, timeout=5)
                if out.returncode == 0 and " ---> " in out.stdout:
                    return out.stdout.split(" ---> ", 1)[1].strip()
            except (OSError, subprocess.SubprocessError):
                pass
    return name
