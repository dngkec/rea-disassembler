"""Structured pseudocode: a CFG-shaped C-like lift, not a fake decompiler.

Every block becomes a labelled region; calls name their target (symbol when
known, sub_<addr> otherwise); string references become literals; conditional
branches become `if (...) goto`.  What we do not know stays visible as the
raw instruction in a comment — a decompiler that invents variables lies.
"""
from __future__ import annotations

from .models import BinaryImage, Function


def lift_function(img: BinaryImage, fn: Function) -> str:
    name_by_addr = {s.addr: s.name for s in img.symbols}
    name_by_addr.update({i.addr: f"{i.name}" for i in img.imports})
    lines = [f"void {fn.name}() {{"]
    if fn.is_import_stub:
        lines.append("    // import stub")
    for block in fn.blocks:
        lines.append(f"  block_{block.start:x}:")
        for ins in block.instructions:
            note = f'  // "{ins.string_ref}"' if ins.string_ref else ""
            if ins.is_call:
                tgt = ins.call_target
                nm = name_by_addr.get(tgt, f"sub_{tgt:x}" if tgt is not None else "indirect")
                lines.append(f"    {nm}();{note}")
            elif ins.is_cond_branch:
                lines.append(f"    if (cond) goto block_{ins.branch_target:x};  // {ins.text}")
            elif ins.is_branch and not ins.is_cond_branch:
                tgt = ins.branch_target
                lines.append(f"    goto block_{tgt:x};" if tgt is not None
                             else f"    // indirect jump: {ins.text}")
            elif ins.is_ret:
                lines.append("    return;")
            elif ins.mnemonic in ("mov", "movq", "movl", "movw", "movb", "lea", "leaq"):
                lines.append(f"    /* {ins.text} */{note}")
            else:
                lines.append(f"    /* {ins.text} */{note}")
    lines.append("}")
    return "\n".join(lines)
