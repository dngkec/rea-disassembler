"""Native GUI launcher: build (once) and open ReaDisassembler.app."""
from __future__ import annotations

import subprocess
from pathlib import Path


def launch_gui() -> int:
    root = Path(__file__).resolve().parent.parent.parent
    app = root / "gui" / "ReaDisassembler.app"
    if not (app / "Contents" / "MacOS" / "ReaDisassembler").exists():
        r = subprocess.run(["sh", str(root / "gui" / "build_app.sh")],
                           capture_output=True, text=True, timeout=600)
        print(r.stdout)
        if r.returncode != 0:
            print(r.stderr)
            return r.returncode
    r = subprocess.run(["open", str(app)], capture_output=True, text=True)
    if r.returncode == 0:
        print(f"opened {app}")
    else:
        print(f"built {app} (could not open: {r.stderr.strip()})")
    return r.returncode
