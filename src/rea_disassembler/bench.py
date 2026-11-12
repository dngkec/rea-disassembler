"""Benchmark harness: rea-disassembler vs. the system objdump (LLVM) on
identical inputs.  Ground truth for instruction boundaries is objdump's own
decoded address set; we report precision/recall of our address set, wall
time, functions and strings — the same table BENCHMARK.md publishes.
"""
from __future__ import annotations

import re
import subprocess
import time
from pathlib import Path

from .analysis import analyse
from .formats import load_binary

_OBJ_LINE = re.compile(r"^\s*([0-9a-f]+):\s")


def objdump_addresses(path: str, arch: str | None = None) -> tuple[set[int], float]:
    """Ground truth = objdump's *valid* instruction addresses.

    Lines objdump itself marks `<unknown>` are data bytes it could not
    decode; they are not instructions and are excluded, on both sides of
    the comparison, by construction of this set.
    """
    t0 = time.perf_counter()
    cmd = ["objdump", "-d", path]
    if arch:  # restrict fat binaries to the slice we actually analysed
        cmd = ["objdump", "-d", f"--arch-name={arch}", path]
    # Stream through a file: on a 200 MB binary objdump emits gigabytes
    # of text, and holding it in RAM gets the harness killed (exit 137).
    import tempfile
    from pathlib import Path as _P
    with tempfile.NamedTemporaryFile(delete=False, suffix=".objdump") as tf:
        subprocess.run(cmd, stdout=tf, stderr=subprocess.DEVNULL, timeout=1200)
        tmp_name = tf.name
    dt = time.perf_counter() - t0
    addrs: set[int] = set()
    with open(tmp_name, errors="replace") as fh:
        for line in fh:
            m = _OBJ_LINE.match(line)
            if m and "<unknown>" not in line:
                addrs.add(int(m.group(1), 16))
    _P(tmp_name).unlink(missing_ok=True)
    return addrs, dt


def bench_one(path: str, arch: str | None = None) -> dict:
    t0 = time.perf_counter()
    img = load_binary(path, raw_arch=arch)
    result = analyse(img)
    ours_t = time.perf_counter() - t0
    ours = {i.addr for i in result["instructions"]}
    obj_path = path
    tmp = None
    if img.arch_slices:  # fat: give objdump exactly the slice we analysed
        import tempfile
        sl = next((s for s in img.arch_slices if s["offset"] == img.slice_offset),
                  img.arch_slices[0])
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".thin")
        tmp.write(img.data[sl["offset"]:sl["offset"] + sl["size"]])
        tmp.close()
        obj_path = tmp.name
    try:
        truth, obj_t = objdump_addresses(obj_path)
    except (OSError, subprocess.SubprocessError):
        truth, obj_t = set(), float("nan")
    finally:
        if tmp is not None:
            Path(tmp.name).unlink(missing_ok=True)
    # Restrict truth to code sections: objdump force-decodes some data
    # sections (e.g. __tp_const) that are not instructions at all.
    if truth and img.sections:
        code_secs = [s for s in img.sections if s.is_code]
        if code_secs:
            truth = {a for a in truth
                     if any(s.addr <= a < s.end for s in code_secs)} or truth
    both = ours & truth
    return {
        "file": str(path), "format": img.format, "arch": img.arch,
        "our_instructions": len(ours), "objdump_instructions": len(truth),
        "matched": len(both),
        "precision": round(len(both) / len(ours), 4) if ours else 0.0,
        "recall": round(len(both) / len(truth), 4) if truth else 0.0,
        "our_functions": len(result["functions"]),
        "our_strings": len(result["strings"]),
        "coverage": round(result["coverage"], 4),
        "our_seconds": round(ours_t, 3), "objdump_seconds": round(obj_t, 3),
    }


def run_bench(paths: list[str]) -> list[dict]:
    return [bench_one(p) for p in paths]
