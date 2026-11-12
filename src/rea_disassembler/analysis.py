"""Whole-image analysis: recursive-descent disassembly, CFG, call graph,
cross-references, string recovery and string-xrefs, function discovery.

Why hybrid?  Pure linear sweep (objdump -d) decodes data-in-code as garbage;
pure recursive descent misses indirect-only code.  We do recursive descent
from every trustworthy seed (entry, function symbols, exported symbols,
stub table), then a *validated* linear sweep of still-uncovered code bytes:
a sweep instruction is accepted only if it does not start mid-instruction.
Result: coverage is measured and reported, never assumed.
"""
from __future__ import annotations

import re
from collections import deque

from . import engine
from .models import BasicBlock, BinaryImage, Function, Instruction, StringRef

_PRINTABLE = re.compile(rb"[\x20-\x7e]{4,}")


def extract_strings(img: BinaryImage, min_len: int = 4) -> list[StringRef]:
    out: list[StringRef] = []
    for sec in img.sections:
        if sec.is_code or sec.size == 0:
            continue
        if any(t in sec.name for t in ("debug", "comment", "symtab", "strtab", ".note", "eh_frame", "__tp_const")):
            continue
        blob = img.data[sec.offset:sec.offset + sec.size]
        if "__cstring" in sec.name or sec.name.endswith(".rodata"):
            # Dedicated C-string section: every NUL-terminated token is a
            # string, including 1-2 char entries in string tables and
            # literals containing \n / \x1b that a printable-run regex cuts.
            pos = 0
            for chunk in blob.split(b"\x00"):
                if chunk and all(0x09 <= b <= 0x0D or b == 0x1B or 0x20 <= b <= 0x7E
                                 for b in chunk):
                    out.append(StringRef(addr=sec.addr + pos,
                                         value=chunk.decode("ascii"),
                                         encoding="ascii", length=len(chunk)))
                pos += len(chunk) + 1
            continue
        for m in re.finditer(rb"[\x20-\x7e]{%d,}" % min_len, blob):
            out.append(StringRef(addr=sec.addr + m.start(),
                                 value=m.group().decode("ascii"),
                                 encoding="ascii", length=len(m.group())))
        # UTF-16LE: printable char followed by NUL, at least min_len chars
        for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len, blob):
            try:
                val = m.group().decode("utf-16le")
            except UnicodeDecodeError:
                continue
            out.append(StringRef(addr=sec.addr + m.start(), value=val,
                                 encoding="utf16le", length=len(m.group())))
    out.sort(key=lambda s: s.addr)
    return out


def _lc_function_starts(img: BinaryImage) -> list[int]:
    """LC_FUNCTION_STARTS: ULEB128 deltas from the __text section start,
    terminated by a zero byte.  This is the linker's own function list —
    the closest thing to ground truth a stripped Mach-O carries."""
    if img.function_starts_blob is None:
        return []
    off, size = img.function_starts_blob
    blob = img.data[off:off + size]
    if not any(s.name.endswith("__text") for s in img.sections):
        return []
    # Deltas are from the image base (__TEXT vmaddr), not the section start
    out, addr, i = [], img.image_base, 0
    while i < len(blob):
        delta, shift = 0, 0
        while i < len(blob):
            b = blob[i]
            i += 1
            delta |= (b & 0x7F) << shift
            shift += 7
            if not (b & 0x80):
                break
        if delta == 0:
            break
        addr += delta
        out.append(addr)
    return out


def _unwind_starts(img: BinaryImage) -> list[int]:
    """Function starts from __unwind_info (compact unwind), Mach-O only.

    Layout (libunwind / mach-o compact_unwind_encoding.h): a 7-word header,
    then an index of {functionOffset, secondLevelPageOffset, lsdaOffset};
    each second-level page is REGULAR (kind 2, 8-byte entries, absolute
    offsets) or COMPRESSED (kind 3, 4-byte entries, delta from page start).
    Malformed tables yield [] — heuristics still apply, nothing crashes.
    """
    import struct as _st
    sec = next((s for s in img.sections if s.name.endswith("__unwind_info")), None)
    if sec is None or sec.size < 28:
        return []
    blob = img.data[sec.offset:sec.offset + sec.size]
    try:
        _ver, _co, _cc, _po, _pc, idx_off, idx_count = _st.unpack_from("<7I", blob, 0)
        out: list[int] = []
        for i in range(min(idx_count, 4096)):
            fo, page_off, _lsda = _st.unpack_from("<III", blob, idx_off + i * 12)
            if page_off == 0:
                continue
            out.append(img.image_base + fo)
            kind, = _st.unpack_from("<I", blob, page_off)
            _nxt, count = _st.unpack_from("<HH", blob, page_off + 4)
            if kind == 3:  # COMPRESSED (12-byte header incl. reserved word)
                for j in range(min(count, 8192)):
                    e, = _st.unpack_from("<I", blob, page_off + 12 + j * 4)
                    out.append(img.image_base + fo + (e & 0xFFFFFF))
            elif kind == 2:  # REGULAR
                for j in range(min(count, 8192)):
                    f_off, _enc = _st.unpack_from("<II", blob, page_off + 8 + j * 8)
                    out.append(img.image_base + f_off)
        return sorted(set(out))
    except Exception:
        return []


def _data_pointer_seeds(img: BinaryImage, seeds: dict[int, str],
                        decoded_addrs: set[int] | None = None,
                        term_follow: set[int] | None = None) -> None:
    """Seed functions from pointers stored in data sections.

    A stored pointer whose value lands on a decoded instruction in a code
    section is a function-pointer table entry.  arm64e may carry pointer
    authentication bits in the high half, so masked variants are tried too.
    """
    import struct as _st
    word = 8 if img.bits == 64 else 4
    fmt = "<Q" if word == 8 else "<I"
    for sec in img.sections:
        if sec.is_code or sec.size < word:
            continue
        if any(t in sec.name for t in ("debug", "symtab", "strtab")):
            continue
        blob = img.data[sec.offset:sec.offset + sec.size]
        for off in range(0, len(blob) - word + 1, word):
            (v,) = _st.unpack_from(fmt, blob, off)
            for cand in (v, v & 0x0000_FFFF_FFFF_FFFF, v & 0x0000_00FF_FFFF_FFFF):
                s = img.section_at(cand)
                if s is not None and s.is_code and \
                        (decoded_addrs is None or cand in decoded_addrs) and \
                        (term_follow is None or cand in term_follow or cand in seeds):
                    seeds.setdefault(cand, "data-ptr")
                    break


def _resolve_adrp_pairs(instrs: list[Instruction], img: BinaryImage) -> None:
    """AArch64: adrp Xd, page ; add Xd, Xd, #off  ->  full address in refs."""
    page_by_reg: dict[str, int] = {}
    for ins in instrs:
        if ins.mnemonic == "adrp":
            parts = [p.strip() for p in ins.op_str.split(",")]
            if len(parts) == 2 and ins.refs:
                page_by_reg[parts[0]] = ins.refs[0]
        elif ins.mnemonic in ("add", "ldr", "ldrsw", "str") and page_by_reg:
            parts = [p.strip() for p in ins.op_str.split(",")]
            for p in parts[1:]:
                m = re.match(r"^(\w+)$", p)
                if m and m.group(1) in page_by_reg and "#" in ins.op_str:
                    imm = ins.op_str.rsplit("#", 1)[-1].strip().strip("]").strip()
                    try:
                        off = int(imm, 0)
                    except ValueError:
                        continue
                    ins.refs = ins.refs + (page_by_reg[m.group(1)] + off,)


def analyse(img: BinaryImage) -> dict:
    md = engine.make_decoder(img.arch, big_endian=(img.endian == "big"))
    exec_secs = [s for s in img.sections if s.is_code and s.size] or \
        [s for s in img.sections if s.is_code]
    decoded: dict[int, Instruction] = {}
    for sec in exec_secs:
        blob = img.data[sec.offset:sec.offset + sec.size]
        for ins in engine.decode_linear(img, md, sec.addr, blob):
            decoded[ins.addr] = ins
    flat = [decoded[a] for a in sorted(decoded)]
    _resolve_adrp_pairs(flat, img)

    # --- function seeds -------------------------------------------------
    seeds: dict[int, str] = {}
    if img.entry:
        seeds[img.entry] = "entry"
    for sym in img.symbols:
        if img.section_at(sym.addr) is not None and img.section_at(sym.addr).is_code:
            seeds.setdefault(sym.addr, "symbol")
    for sym in img.exports:
        if sym.addr:
            seeds.setdefault(sym.addr, "symbol")
    # Objective-C methods: IMPs named from method lists (class/category/
    # standalone), plus __objc_stubs entries (32-byte arm64 trampolines).
    from .objc import discover_objc_methods
    objc_names = discover_objc_methods(img)
    for a in objc_names:
        if a in decoded:
            seeds.setdefault(a, "objc-method")
    for sec in exec_secs:
        if sec.name.endswith("__objc_stubs"):
            step = 32 if img.arch in ("arm64", "arm64_32") else 16
            for a in range(sec.addr, sec.end - step + 1, step):
                if a in decoded:
                    seeds.setdefault(a, "objc-stub")
    for a in _lc_function_starts(img):
        if a in decoded:
            seeds.setdefault(a, "function-starts")
    for a in _unwind_starts(img):
        seeds.setdefault(a, "unwind")
    # Prologue heuristic: catches callback / function-pointer-only functions
    # that no direct call reaches (Hopper finds these via unwind data).
    prev = None
    for idx, ins in enumerate(flat):
        sec = img.section_at(ins.addr)
        in_text = sec is not None and sec.name.endswith("__text")
        after_end = prev is None or prev.is_ret or (prev.is_branch and not prev.is_cond_branch)
        # Entry patterns: pointer-auth sign (pacibsp) is entry-only anywhere.
        # Pre-index stack push and frame setup (sub sp, then add/stp x29
        # within 8 insns) count only after a control transfer — mid-function
        # alloca / register saves fall through from arithmetic, entries don't.
        after_xfer = after_end or (prev is not None and (prev.is_branch or prev.is_call))
        nxt = " ".join(i.text for i in flat[idx:idx + 9])
        frame_setup = "add x29, sp" in nxt or "stp x29, x30" in nxt
        entry_pat = ins.mnemonic in ("pacibsp", "paciasp") or \
            (after_end and ins.mnemonic == "stp" and "[sp, #-" in ins.op_str and "]!" in ins.op_str) or \
            (after_xfer and ins.mnemonic == "sub" and "sp, sp" in ins.op_str and frame_setup)
        if in_text and (entry_pat
                        or (after_end and ins.mnemonic == "stp" and "x29, x30" in ins.op_str)
                        or (after_end and ins.mnemonic in ("push", "sub")
                            and ("rbp" in ins.op_str or "sp, sp" in ins.op_str))):
            seeds.setdefault(ins.addr, "prologue")
        prev = ins
    # Every direct call target in the sweep is a function, reachable or not
    # (recursive descent alone misses targets called only from dead paths).
    for ins in flat:
        if ins.call_target is not None and ins.call_target in decoded:
            seeds.setdefault(ins.call_target, "call-target")
    # Data-reference discovery: a code address materialised as data — an
    # adrp+add / lea that loads a function pointer (qsort comparators,
    # callbacks, handlers), or a pointer stored in a data section (vtables,
    # dispatch tables) — is a function start even when nothing calls or
    # branches to it.  This is the class pure recursive descent cannot see.
    # Guard: the target must follow a terminator (ret / unconditional
    # branch) or a section start — a reference to a mid-function label
    # (jump-table base, local callback entry) is not a function start.
    term_follow = {ins.end for ins in flat
                   if ins.is_ret or (ins.is_branch and not ins.is_cond_branch)}
    term_follow |= {s.addr for s in exec_secs}
    flat_idx = {ins.addr: k for k, ins in enumerate(flat)}
    for ins in flat:
        if ins.mnemonic == "adrp":
            continue  # page base only; the paired add/ldr carries the exact ref
        # Jump-table bases (adr/add feeding an indirect br within 3 insns)
        # point at case labels inside a function, not at function entries.
        k = flat_idx[ins.addr]
        if any(n.is_branch and n.branch_target is None
               for n in flat[k:k + 4]):
            continue
        for r in ins.refs:
            sec = img.section_at(r)
            if sec is not None and sec.is_code and r in decoded \
                    and (r in term_follow or r in seeds):
                seeds.setdefault(r, "data-ref")
    _data_pointer_seeds(img, seeds, set(decoded), term_follow)
    # When the linker published LC_FUNCTION_STARTS, it is authoritative for
    # function boundaries: purely heuristic seeds (prologue/data-ref) that
    # fall *inside* a listed function are blocks of that function, not
    # entries.  Symbol/call/objc/entry/unwind seeds are metadata facts and
    # always stand — LC and unwind are independent authoritative lists,
    # and neither vetoes the other.
    lc_starts = _lc_function_starts(img)
    if lc_starts:
        lc_set = set(lc_starts)
        for a in [a for a, src in seeds.items()
                  if src in ("prologue", "data-ref", "data-ptr")
                  and a not in lc_set]:
            del seeds[a]

    # --- recursive descent: collect reachable + call targets ------------
    reachable: set[int] = set()
    work: deque[int] = deque(seeds)
    enqueued = set(seeds)
    while work:
        addr = work.popleft()
        while addr in decoded and addr not in reachable:
            reachable.add(addr)
            ins = decoded[addr]
            if ins.call_target is not None:
                seeds.setdefault(ins.call_target, "call-target")
                if ins.call_target not in enqueued:
                    work.append(ins.call_target)
                    enqueued.add(ins.call_target)
            if ins.branch_target is not None:
                if ins.branch_target not in enqueued:
                    work.append(ins.branch_target)
                    enqueued.add(ins.branch_target)
            if ins.is_ret or (ins.is_branch and not ins.is_cond_branch):
                break
            addr = ins.end
    # sweep-only instructions are real too (indirect code), flag coverage
    coverage = (sum(decoded[a].size for a in reachable) /
                max(1, sum(s.size for s in exec_secs))) if exec_secs else 0.0

    # --- functions ------------------------------------------------------
    # Trap bytes (udf/brk/int3) in code are data (jump tables, literal
    # pools), never function entries — a seed pointing at one is bogus.
    trap = ("udf", "brk", "hlt", "int3", "trap", "ud2")
    starts = sorted(a for a, src in seeds.items()
                    if (a in decoded and decoded[a].mnemonic not in trap)
                    or (a not in decoded and img.section_at(a) is not None
                        and img.section_at(a).is_code))
    sym_names = {s.addr: s.name for s in img.symbols}
    functions: list[Function] = []
    start_set = set(starts)
    ordered = sorted(decoded)  # once, not per function (was O(F·N))
    import bisect as _bis
    for i, start in enumerate(starts):
        limit = starts[i + 1] if i + 1 < len(starts) else (img.section_at(start).end
                                                          if img.section_at(start) else start)
        lo = _bis.bisect_left(ordered, start)
        hi = _bis.bisect_left(ordered, limit)
        f_ins = [decoded[a] for a in ordered[lo:hi]]
        blocks = _build_blocks(f_ins, start_set)
        end = max((b.end for b in blocks), default=start)
        callees = sorted({ins.call_target for b in blocks for ins in b.instructions
                          if ins.call_target is not None})
        functions.append(Function(
            addr=start, name=objc_names.get(start) or sym_names.get(start, f"sub_{start:x}"), end=end,
            blocks=blocks, callees=callees,
            source=seeds.get(start, "symbol"),
            is_import_stub=img.section_at(start) is not None
            and img.section_at(start).name.endswith("__stubs")))
    by_addr = {f.addr: f for f in functions}
    for f in functions:
        for c in f.callees:
            if c in by_addr and f.addr not in by_addr[c].callers:
                by_addr[c].callers.append(f.addr)

    # --- strings + xrefs --------------------------------------------------
    strings = extract_strings(img)
    s_by_addr = {s.addr: s for s in strings}
    xref_map: dict[int, list[int]] = {}
    for ins in flat:
        for r in ins.refs:
            if r in s_by_addr:
                ins.string_ref = s_by_addr[r].value
                s_by_addr[r].xrefs.append(ins.addr)
            xref_map.setdefault(r, []).append(ins.addr)
    return {"instructions": flat, "functions": functions, "strings": strings,
            "decoded": decoded, "reachable": reachable, "coverage": coverage,
            "xrefs": xref_map, "exec_sections": exec_secs}


def _build_blocks(instrs: list[Instruction], func_starts: set[int]) -> list[BasicBlock]:
    if not instrs:
        return []
    leaders = {instrs[0].addr}
    for ins in instrs:
        if ins.branch_target is not None:
            leaders.add(ins.branch_target)
        if ins.is_branch or ins.is_ret or ins.is_call is False and False:
            pass
        if ins.is_branch or ins.is_ret:
            nxt = ins.end
            leaders.add(nxt)
    blocks: list[BasicBlock] = []
    cur: list[Instruction] = []
    by_addr = {i.addr: i for i in instrs}
    for ins in instrs:
        if ins.addr in leaders and cur:
            blocks.append(BasicBlock(cur[0].addr, cur[-1].end, cur))
            cur = []
        cur.append(ins)
        if ins.is_branch or ins.is_ret:
            blocks.append(BasicBlock(cur[0].addr, cur[-1].end, cur))
            cur = []
    if cur:
        blocks.append(BasicBlock(cur[0].addr, cur[-1].end, cur))
    starts = {b.start for b in blocks}
    for b in blocks:
        if not b.instructions:
            continue
        last = b.instructions[-1]
        succ: list[int] = []
        if last.branch_target is not None:
            succ.append(last.branch_target)
        if not last.is_ret and not (last.is_branch and not last.is_cond_branch):
            succ.append(last.end)
        b.successors = sorted({s for s in succ if s in starts or s in by_addr})
    by_start = {b.start: b for b in blocks}
    for b in blocks:
        for s in b.successors:
            tgt = by_start.get(s)
            if tgt is not None:
                tgt.predecessors.append(b.start)
    return blocks
