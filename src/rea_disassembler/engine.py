"""Instruction decoder: a thin, honest wrapper over Capstone (LLVM-derived,
the same lineage as Hopper's bundled libLLVMServices.dylib).

We request full operand detail and then classify control flow from Capstone's
instruction groups rather than from mnemonic string matching wherever the
groups exist — string matching is how naive disassemblers misclassify.
Data references are recovered per-architecture:
  * x86-64 / x86 : RIP/EIP-relative memory operands (absolute target computed)
  * AArch64      : PC-relative immediates (b/bl/adr/adrp page + paired add/ldr
                   is resolved one level up, in analysis.py, which sees pairs)
"""
from __future__ import annotations

import capstone
from capstone import (CS_ARCH_ARM, CS_ARCH_ARM64, CS_ARCH_X86, CS_MODE_32,
                      CS_MODE_64, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN,
                      CS_MODE_THUMB, CS_OPT_DETAIL, CS_GRP_CALL, CS_GRP_JUMP,
                      CS_GRP_RET)

from .models import BinaryImage, Instruction

_ARCHS = {
    "arm64": (CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN),
    "arm64_32": (CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN),
    "arm": (CS_ARCH_ARM, CS_MODE_ARM),
    "x86_64": (CS_ARCH_X86, CS_MODE_64),
    "x86": (CS_ARCH_X86, CS_MODE_32),
}


def make_decoder(arch: str, big_endian: bool = False):
    if arch not in _ARCHS:
        raise ValueError(f"unsupported architecture {arch!r}; supported: {sorted(_ARCHS)}")
    cs_arch, mode = _ARCHS[arch]
    if big_endian:
        mode = mode | capstone.CS_MODE_BIG_ENDIAN
    md = capstone.Cs(cs_arch, mode)
    md.detail = True
    if cs_arch == CS_ARCH_X86:
        md.syntax = capstone.CS_OPT_SYNTAX_INTEL
    return md


def _classify(ins) -> tuple[bool, bool, bool, bool, int | None, int | None, tuple[int, ...]]:
    groups = set(ins.groups)
    is_call = CS_GRP_CALL in groups
    is_jump = CS_GRP_JUMP in groups
    is_ret = CS_GRP_RET in groups
    target = None
    refs: list[int] = []
    try:
        for op in ins.operands:
            if op.type == capstone.CS_OP_IMM and (is_call or is_jump):
                target = op.imm & 0xFFFFFFFFFFFFFFFF
            elif op.type == capstone.CS_OP_MEM:
                base = ins.reg_name(op.mem.base) if op.mem.base else ""
                if base in ("rip", "eip"):
                    refs.append(ins.address + ins.size + op.mem.disp)
    except (capstone.CsError, AttributeError):
        pass
    # AArch64 adrp/adr carry the PC-relative value as an immediate operand
    # without jump/call group membership — capture it as a data reference.
    if ins.mnemonic in ("adrp", "adr") and ins.operands:
        try:
            refs.append(ins.operands[1].imm & 0xFFFFFFFFFFFFFFFF)
        except (capstone.CsError, IndexError):
            pass
    cond = is_jump and not is_call and ins.mnemonic not in ("jmp", "b", "braa", "brab", "br")
    # Capstone puts `bl` in both CALL and JUMP groups; a call is not a CFG
    # branch — classifying it as one corrupts every block edge it touches.
    return is_call, is_jump and not is_call, cond, is_ret, target if is_call else None, \
        target if (is_jump and not is_call) else None, tuple(refs)


def decode_at(img: BinaryImage, md, addr: int) -> Instruction | None:
    off = img.addr_to_offset(addr)
    if off is None:
        return None
    code = img.data[off:off + 16]
    for ins in md.disasm(code, addr, count=1):
        is_call, is_jump, cond, is_ret, call_t, branch_t, refs = _classify(ins)
        return Instruction(
            addr=ins.address, size=ins.size, mnemonic=ins.mnemonic,
            op_str=ins.op_str, bytes_hex=ins.bytes.hex(),
            is_call=is_call, is_branch=is_jump, is_cond_branch=cond,
            is_ret=is_ret,
            is_indirect=(is_call or is_jump) and call_t is None and branch_t is None,
            branch_target=branch_t, call_target=call_t, refs=refs)
    return None


def _hex_target(op_str: str) -> int | None:
    """Last `#0x…` / bare `0x…` token in an operand string, if any."""
    tok = None
    for part in op_str.replace(",", " ").split():
        if part.startswith("#"):
            tok = part[1:]
        elif part.startswith("0x"):
            tok = part
    if tok is None:
        return None
    try:
        return int(tok, 16)
    except ValueError:
        return None


def _lite_classify(mn: str, op_str: str, arch: str):
    """Fast-path classification without Capstone detail objects.

    Returns (is_call, is_branch, is_cond, is_ret, call_t, branch_t, refs,
    needs_detail).  Anything ambiguous is flagged for a detailed decode.
    """
    if arch in ("arm64", "arm64_32", "arm"):
        if mn in ("ret", "retaa", "retab"):
            return False, False, False, True, None, None, (), False
        if mn in ("bl", "blr", "blraa", "blrab"):
            t = _hex_target(op_str) if mn == "bl" else None
            return True, False, False, False, t, None, (), mn != "bl"
        if mn == "b" or mn.startswith("b.") or mn in (
                "cbz", "cbnz", "tbz", "tbnz", "br", "braa", "brab"):
            cond = mn != "b" and mn not in ("br", "braa", "brab")
            t = _hex_target(op_str) if mn not in ("br", "braa", "brab") else None
            return False, True, cond, False, None, t, (), False
        if mn in ("adrp", "adr"):
            t = _hex_target(op_str)
            return False, False, False, False, None, None, (t,) if t is not None else (), False
        if mn.startswith(("ldr", "ldur")) and "#" in op_str and "[" not in op_str:
            t = _hex_target(op_str)  # literal load: pc-relative address
            return False, False, False, False, None, None, (t,) if t is not None else (), False
        return False, False, False, False, None, None, (), False
    # x86 family
    if mn in ("ret", "retf", "retn"):
        return False, False, False, True, None, None, (), False
    if mn == "call":
        t = _hex_target(op_str)
        return True, False, False, False, t, None, (), t is None
    if mn == "jmp" or (mn.startswith("j") and mn not in ("jmp",)):
        t = _hex_target(op_str)
        return False, True, mn != "jmp", False, None, t, (), t is None
    if "rip" in op_str or "eip" in op_str:
        return False, False, False, False, None, None, (), True
    return False, False, False, False, None, None, (), False


def decode_linear(img: BinaryImage, md, start: int, data: bytes) -> list[Instruction]:
    """Decode a whole contiguous region with resynchronisation.

    Fast path: Capstone *lite* decode (no per-instruction detail objects,
    which dominated profile time at scale).  Instructions whose operands
    need detail (indirect branches, rip-relative references) are re-decoded
    individually with detail enabled.

    Capstone's iterator stops at the first undecodable byte (data embedded
    in code: jump tables, literal pools).  A naive sweep therefore loses
    every instruction after the first data island — on a 27 MB binary that
    was 199k instructions.  We restart the sweep past each gap (4 bytes on
    fixed-width ISAs, 1 on x86) until the region is fully covered.
    """
    step = 1 if img.arch in ("x86", "x86_64") else 4
    out: list[Instruction] = []
    off = 0
    while off < len(data):
        chunk_start = off
        for addr, size, mn, op_str in md.disasm_lite(data[off:], start + off):
            rel = addr - start
            if size == 4 and data[rel:rel + 4] == b"\x00\x00\x00\x00":
                off = rel + size  # all-zero padding is not an instruction
                continue
            is_call, is_jump, cond, is_ret, call_t, branch_t, refs, need = \
                _lite_classify(mn, op_str, img.arch)
            ins = None
            if need:
                ins = decode_at(img, md, addr) if img.data else None
            if ins is not None:
                out.append(ins)
            else:
                out.append(Instruction(
                    addr=addr, size=size, mnemonic=mn, op_str=op_str,
                    bytes_hex=data[rel:rel + size].hex(),
                    is_call=is_call, is_branch=is_jump, is_cond_branch=cond,
                    is_ret=is_ret,
                    is_indirect=(is_call or is_jump) and call_t is None and branch_t is None,
                    branch_target=branch_t, call_target=call_t, refs=refs))
            off = rel + size
        if off == chunk_start:  # undecodable byte(s): skip and resync
            off += step
        elif off < len(data):
            # iterator stopped early at a bad byte; skip it and continue
            off += step
    return out
