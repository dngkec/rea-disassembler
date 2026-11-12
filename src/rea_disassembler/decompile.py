"""Structured decompiler: registers become expressions, stack slots
become named locals, calls take arguments, conditional branches become
`if`, and back-edges are marked as loops.

Deliberately small but real: within a block, expressions propagate to
their uses; loads/stores through sp/fp name a `var_N`; the comparison
feeding a branch becomes its condition; the return register at `ret`
becomes the return value.  Across blocks, live expressions materialise
as `r_<reg>`.  Unknown instructions surface as comments, never as
invented variables.
"""
from __future__ import annotations

import re

from .models import BinaryImage, Function
from .objc import discover_objc_methods

_ARGS = {"arm64": ["x0", "x1", "x2"], "x86_64": ["rdi", "rsi", "rdx"], "x86": []}
_RET = {"arm64": "x0", "arm64_32": "x0", "x86_64": "rax", "x86": "eax"}
_COND = {"eq": "==", "ne": "!=", "lt": "<", "le": "<=", "gt": ">", "ge": ">=",
         "lo": "<", "hs": ">=", "ls": "<=", "hi": ">"}
_BINOP = {"add": "+", "sub": "-", "and": "&", "orr": "|", "eor": "^",
          "mul": "*", "lsl": "<<", "lsr": ">>", "asr": ">>"}


def _reg(r: str, arch: str) -> str:
    if arch == "arm64":
        m = re.fullmatch(r"[wx](\d+)", r)
        if m:
            return f"x{m.group(1)}"
        return {"sp": "sp", "wsp": "sp", "xzr": "0", "wzr": "0",
                "x29": "fp", "x30": "lr"}.get(r, r)
    return {"rsp": "sp", "rbp": "fp"}.get(r, r)


def _slot(op: str) -> str | None:
    m = re.search(r"\[(?:sp|x29|fp|rbp)[,\s]*#?(-?0x[0-9a-fA-F]+|-?\d+)?\]", op)
    if not m:
        return None
    d = int(m.group(1), 0) if m.group(1) else 0
    return f"var_{d & 0xFF:x}" if d <= 0 else f"arg_{d:x}"


def decompile_function(img: BinaryImage, fn: Function) -> str:
    arch = img.arch
    names = {s.addr: s.name for s in img.symbols}
    names.update(discover_objc_methods(img))
    back_edge = {i.branch_target for b in fn.blocks for i in b.instructions
                 if i.branch_target is not None and i.branch_target <= i.addr}
    body: list[str] = []
    locals_: set[str] = set()
    for b in fn.blocks:
        env: dict[str, str] = {}
        last_cmp: tuple[str, str] | None = None
        lines: list[str] = []

        def expr(v: str) -> str:
            v = v.strip().strip(",")
            if v.startswith("#"):
                v = v[1:]
            r = _reg(v, arch)
            if r in env:
                return env[r]
            return v if re.fullmatch(r"-?(0x[0-9a-fA-F]+|\d+)", v) else r

        for ins in b.instructions:
            parts = [p.strip() for p in ins.op_str.split(",")] if ins.op_str else []
            dst = _reg(parts[0], arch) if parts else ""
            slot = _slot(ins.op_str)
            m = ins.mnemonic
            if m.startswith("mov") and len(parts) >= 2 and slot is None:
                env[dst] = expr(parts[1])
            elif m in _BINOP and len(parts) >= 3 and slot is None:
                env[dst] = f"({expr(parts[1])} {_BINOP[m]} {expr(parts[2])})"
            elif m == "madd" and len(parts) == 4:
                env[dst] = f"({expr(parts[1])} * {expr(parts[2])} + {expr(parts[3])})"
            elif m.startswith(("ldr", "ldur")) and slot is not None:
                env[dst] = slot
                locals_.add(slot)
            elif m.startswith(("str", "stur", "stp")) and slot is not None:
                lines.append(f"{slot} = {expr(parts[0])};")
                locals_.add(slot)
            elif m in ("cmp", "cmn", "subs", "cmpl", "test") and len(parts) >= 2:
                last_cmp = (expr(parts[-2] if m != "cmp" else parts[0]),
                            expr(parts[-1]))
                if m == "subs" and len(parts) >= 3:
                    env[dst] = f"({last_cmp[0]} - {last_cmp[1]})"
                    last_cmp = (dst, last_cmp[1])
            elif m.startswith("cs") and len(parts) >= 4:
                sym = _COND.get(parts[3], "!=")
                a, bb = last_cmp or ("cond", "0")
                env[dst] = f"(({a} {sym} {bb}) ? {expr(parts[1])} : {expr(parts[2])})"
            elif ins.is_call:
                tgt = ins.call_target
                nm = names.get(tgt, f"sub_{tgt:x}" if tgt is not None else "indirect")
                args = ", ".join(expr(r) for r in _ARGS.get(arch, []) if r in env)
                ret = _RET.get(arch, "x0")
                # Materialise the result: inlining a call expression at
                # every later use would claim the call happens repeatedly.
                lines.append(f"r_{ret} = {nm}({args});" + (f' /* "{ins.string_ref}" */'
                                                           if ins.string_ref else ""))
                env[ret] = f"r_{ret}"
            elif ins.is_ret:
                v = expr(_RET.get(arch, "x0"))
                lines.append(f"return {v};" if v != _RET.get(arch, "x0") else "return;")
            elif ins.string_ref:
                lines.append(f'/* "{ins.string_ref}" */')
        for reg, val in env.items():
            if val != reg and re.search(r"[+\-*/&|^<>]|\(|", val) and " " in val:
                lines.append(f"r_{reg} = {val};")
        tag = "loop header, " if b.start in back_edge else ""
        body.append(f"  block_{b.start:x}:  /* {tag}{len(b.instructions)} ins */")
        body += [f"    {ln}" for ln in lines]
        last = b.instructions[-1] if b.instructions else None
        if last is not None and last.is_cond_branch and last.branch_target is not None:
            sym = next((v for k, v in _COND.items()
                        if last.mnemonic.endswith(k) or last.mnemonic.endswith("." + k)
                        or last.mnemonic[1:] == k), "!=")
            a, bb = last_cmp or ("cond", "0")
            body.append(f"    if ({a} {sym} {bb}) goto block_{last.branch_target:x};")
        elif last is not None and last.is_branch and last.branch_target is not None:
            body.append(f"    goto block_{last.branch_target:x};")
    head = [f"long {fn.name}(long arg0, long arg1, long arg2) {{"]
    head += [f"    long {v};" for v in sorted(locals_)]
    tail = [] if any("return" in ln for ln in body) else ["    return 0;"]
    return "\n".join(head + body + tail + ["}"])
