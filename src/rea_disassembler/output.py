"""Renderers: human text and stable, diff-able JSON (sorted, hex as 0x…)."""
from __future__ import annotations

import hashlib
import json

from .demangle import demangle
from .models import BinaryImage


SCHEMA_VERSION = "1"


def page(items: list, total: int, limit: int, offset: int) -> dict:
    """One paginated envelope — the agent contract for list surfaces."""
    return {"schema_version": SCHEMA_VERSION, "total": total,
            "limit": limit, "offset": offset, "items": items}


def image_to_dict(img: BinaryImage, result: dict) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "file": img.path,
        "sha256": hashlib.sha256(img.data).hexdigest(),
        "format": img.format, "arch": img.arch, "bits": img.bits,
        "endian": img.endian, "entry": hex(img.entry),
        "image_base": hex(img.image_base),
        "arch_slices": img.arch_slices,
        "segments": [{"name": s.name, "addr": hex(s.addr), "size": s.size,
                      "offset": s.offset} for s in img.segments],
        "sections": [{"name": s.name, "addr": hex(s.addr), "size": s.size,
                      "offset": s.offset, "code": s.is_code} for s in img.sections],
        "symbols": [{"name": s.name, "demangled": demangle(s.name.lstrip("_"))
                     if s.name.startswith(("_Z", "__Z")) else demangle(s.name),
                     "addr": hex(s.addr), "kind": s.kind} for s in img.symbols],
        "imports": [{"name": s.name, "addr": hex(s.addr)} for s in img.imports],
        "counts": {
            "functions": len(result["functions"]),
            "instructions": len(result["instructions"]),
            "strings": len(result["strings"]),
            "reachable_instructions": len(result["reachable"]),
            "code_coverage": round(result["coverage"], 4),
        },
        "functions": [{
            "name": f.name, "addr": hex(f.addr), "end": hex(f.end), "size": f.size,
            "source": f.source, "import_stub": f.is_import_stub,
            "blocks": len(f.blocks),
            "callees": [hex(c) for c in f.callees],
            "callers": [hex(c) for c in f.callers],
        } for f in result["functions"]],
        "strings": [{"addr": hex(s.addr), "value": s.value, "encoding": s.encoding,
                     "xrefs": [hex(x) for x in s.xrefs]} for s in result["strings"]],
    }


def to_json(img: BinaryImage, result: dict, indent: int = 2) -> str:
    return json.dumps(image_to_dict(img, result), indent=indent, sort_keys=False)


def listing(img: BinaryImage, result: dict, func_addr: int | None = None) -> str:
    names = {s.addr: s.name for s in img.symbols}
    lines: list[str] = []
    ins_list = result["instructions"]
    if func_addr is not None:
        fn = next((f for f in result["functions"] if f.addr == func_addr), None)
        if fn is None:
            return f"no function at {func_addr:#x}\n"
        ins_list = [i for b in fn.blocks for i in b.instructions]
        lines.append(f"; {fn.name}  {fn.addr:#x}..{fn.end:#x}")
    for ins in ins_list:
        label = f"{names[ins.addr]}:\n" if ins.addr in names else ""
        cmt = f"  ; \"{ins.string_ref}\"" if ins.string_ref else ""
        if ins.call_target is not None and ins.call_target in names:
            cmt += f"  ; call {names[ins.call_target]}"
        lines.append(f"{label}{ins.addr:012x}  {ins.bytes_hex:<24} {ins.text}{cmt}")
    return "\n".join(lines) + "\n"
