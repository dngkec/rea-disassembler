"""Assembler and binary write-back (Hopper's assemble() /
produceNewExecutable(), without the GUI).

Backend: the system LLVM assembler (`clang -c`), the same LLVM lineage
Hopper bundles.  The snippet is assembled at offset 0, decoded, and every
PC-relative operand is then re-encoded for the real patch address
(B/BL/B.cond/CBZ/ADR/ADRP on arm64, rel8/rel32 on x86) — so branches land
exactly where the source text says.  Keystone is used instead when its
native library is importable, but it is not required.

Patching writes into a *new* file (the original is never touched), then
restores an ad-hoc Mach-O signature with codesign so the result runs,
and verifies by re-disassembling the written file at the patch site.
"""
from __future__ import annotations

import re
import struct
import subprocess
import tempfile
from pathlib import Path

from . import engine
from .models import BinaryImage

_TARGETS = {
    "arm64": "arm64-apple-darwin",
    "arm64_32": "arm64-apple-darwin",
    "arm": "armv7-apple-darwin",
    "x86_64": "x86_64-apple-darwin",
    "x86": "i386-apple-darwin",
}


def _prepare_asm(asm: str, addr: int, arch: str = "arm64") -> tuple[str, list[int], list[str]]:
    """Rewrite absolute branch/adrp operands for the LLVM assembler,
    which wants labels or PC-relative expressions, not raw addresses.
    x86 is left alone (its rel32 is re-encoded afterwards instead).
    Returns (rewritten asm, [adr/adrp targets in order], [prelude labels])."""
    import re as _re  # noqa: F401  (also bound as `re` via module import below)
    adrp_targets: list[int] = []
    labels: list[str] = []
    out_lines = []
    if arch in ("x86", "x86_64"):
        # Absolute targets become undefined labels: the object carries a
        # placeholder rel32 that the fixup step overwrites exactly.
        out = []
        n = 0
        for line in re.split(r"[;\n]", asm):
            line = line.strip()
            if not line:
                continue
            mb = re.search(r"0x[0-9a-fA-F]+\s*$", line)
            mn = line.split(None, 1)[0].lower() if line.split() else ""
            if mb and (mn.startswith("j") or mn in ("call", "loop")):
                n += 1
                adrp_targets.append(int(mb.group(0), 16))
                line = line[:mb.start()] + f"__rea_t{n}"
            out.append(line)
        return "\n".join(out), adrp_targets, labels
    for line in re.split(r"[;\n]", asm):
        line = line.strip()
        if not line:
            continue
        m = _re.match(r"((adrp|adr)\s+\w+,\s*)(0x[0-9a-fA-F]+)", line)
        if m:
            adrp_targets.append(int(m.group(3), 16))
            lbl = f"__rea_pg{len(adrp_targets)}"
            labels.append(lbl)
            suffix = "@PAGE" if m.group(2) == "adrp" else ""
            line = m.group(1) + lbl + suffix
        else:
            mb = _re.search(r"(0x[0-9a-fA-F]+)\s*$", line)
            mn = line.split(None, 1)[0].lower() if line.split() else ""
            if mb and mn.startswith(("b", "bl", "cbz", "cbnz", "tbz", "tbnz",
                                     "jmp", "call", "j")):
                delta = int(mb.group(1), 16) - addr
                rel = f".+{delta}" if delta >= 0 else f".-{-delta}"
                line = line[:mb.start()] + rel
                addr += 4  # next instruction's address (arm64 stride)
                out_lines.append(line)
                continue
        out_lines.append(line)
        addr += 4
    return "\n".join(out_lines), adrp_targets, labels


def _assemble_clang(arch: str, asm: str, addr: int = 0) -> tuple[bytes, list[int]]:
    target = _TARGETS[arch]
    rewritten, adrp_targets, labels = _prepare_asm(asm, addr, arch)
    syntax = ".intel_syntax noprefix\n" if arch in ("x86", "x86_64") else ""
    prelude = "".join(f"{lbl}:\n" for lbl in labels)
    src = f"{syntax}.text\n{prelude}.globl _rea_patch\n_rea_patch:\n{rewritten}\n"
    with tempfile.TemporaryDirectory() as td:
        s, o = Path(td) / "p.s", Path(td) / "p.o"
        s.write_text(src)
        r = subprocess.run(["clang", "-target", target, "-c", str(s), "-o", str(o)],
                           capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            raise ValueError(f"cannot assemble {asm!r} for {arch}: {r.stderr.strip()}")
        from .formats import load_binary
        img = load_binary(str(o), raw_arch=arch)
        sec = next((x for x in img.sections if x.is_code), None)
        if sec is None:
            raise ValueError(f"assembler produced no code section for {asm!r}")
        return img.data[sec.offset:sec.offset + sec.size], adrp_targets


def _assemble_keystone(arch: str, asm: str, addr: int) -> bytes | None:
    try:
        import keystone
    except Exception:
        return None
    ks_map = {
        "arm64": (keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN),
        "x86_64": (keystone.KS_ARCH_X86, keystone.KS_MODE_64),
        "x86": (keystone.KS_ARCH_X86, keystone.KS_MODE_32),
        "arm": (keystone.KS_ARCH_ARM, keystone.KS_MODE_ARM),
    }
    if arch not in ks_map:
        return None
    try:
        ks = keystone.Ks(*ks_map[arch])
        encoding, _ = ks.asm(asm, addr)
        return bytes(encoding) if encoding else None
    except Exception:
        return None


def _fixup_pc_relative(code: bytes, arch: str, addr: int,
                       adrp_targets: list[int] | None = None) -> bytes:
    """Re-encode PC-relative operands from assembly-at-0 to assembly-at-addr."""
    md = engine.make_decoder(arch)
    buf = bytearray(code)
    adrp_queue = list(adrp_targets or [])
    off = 0
    fake = BinaryImage(path="", format="raw", arch=arch, bits=64 if arch in
                       ("arm64", "x86_64") else 32, endian="little", entry=0,
                       image_base=0, data=bytes(buf))
    from .models import Section, Segment
    fake.segments.append(Segment("__t", 0, len(buf), 0))
    fake.sections.append(Section("__t", "__t", 0, len(buf), 0, is_code=True))
    for ins in engine.decode_linear(fake, md, 0, bytes(buf)):
        if arch in ("x86", "x86_64"):
            # x86 targets were recorded while rewriting to labels; encode
            # rel8/rel32 for the real address from the recorded target.
            if ins.branch_target is None and ins.call_target is None:
                continue
            target = adrp_queue.pop(0) if adrp_queue else (
                ins.branch_target if ins.branch_target is not None else ins.call_target)
            if target is None:
                continue
            real = addr + ins.addr
            if ins.size >= 5:
                struct.pack_into("<i", buf, ins.addr + ins.size - 4,
                                 target - (real + ins.size))
            elif ins.size >= 2:
                struct.pack_into("<b", buf, ins.addr + ins.size - 1,
                                 target - (real + ins.size))
            continue
        # arm64 branches were rewritten PC-relative, so their encodings are
        # already correct at any address.  Only adr/adrp placeholders need
        # their recorded absolute target encoded.
        if ins.mnemonic not in ("adrp", "adr") or not adrp_queue:
            continue
        target = adrp_queue.pop(0)
        real = addr + ins.addr  # address this instruction will live at
        if arch in ("arm64", "arm64_32"):
            w, = struct.unpack_from("<I", buf, ins.addr)
            mn = ins.mnemonic
            if mn in ("b", "bl"):
                imm = ((target - real) >> 2) & 0x3FFFFFF
                struct.pack_into("<I", buf, ins.addr, (w & 0xFC000000) | imm)
            elif mn.startswith(("b.", "cbz", "cbnz")):
                imm = ((target - real) >> 2) & 0x7FFFF
                struct.pack_into("<I", buf, ins.addr, (w & 0xFF00001F) | (imm << 5))
            elif mn in ("tbz", "tbnz"):
                imm = ((target - real) >> 2) & 0x3FFF
                struct.pack_into("<I", buf, ins.addr, (w & 0xFFF8001F) | (imm << 5))
            elif mn in ("adr", "adrp"):
                if mn == "adrp":
                    delta = (target & ~0xFFF) - (real & ~0xFFF)
                else:
                    delta = target - real
                imm21 = (delta >> 12) & 0x1FFFFF if mn == "adrp" else delta & 0x1FFFFF
                immlo, immhi = imm21 & 0x3, (imm21 >> 2) & 0x7FFFF
                w = (w & 0x9F00001F) | (immlo << 29) | (immhi << 5)
                struct.pack_into("<I", buf, ins.addr, w)
        else:  # x86: rel32 (last 4 bytes) or rel8 (last byte)
            if ins.size >= 5 and ins.bytes_hex[-8:]:
                rel = target - (real + ins.size)
                struct.pack_into("<i", buf, ins.addr + ins.size - 4, rel)
            elif ins.size >= 2:
                rel = target - (real + ins.size)
                struct.pack_into("<b", buf, ins.addr + ins.size - 1, rel)
    return bytes(buf)


def assemble(arch: str, asm: str, addr: int = 0) -> bytes:
    """Assemble `asm` as it will execute at `addr`."""
    if arch not in _TARGETS:
        raise ValueError(f"unsupported architecture {arch!r}; supported: {sorted(_TARGETS)}")
    ks = _assemble_keystone(arch, asm, addr)
    if ks:
        return ks
    code, adrp_targets = _assemble_clang(arch, asm, addr)
    if addr:
        code = _fixup_pc_relative(code, arch, addr, adrp_targets)
    return code


def patch_binary(img: BinaryImage, addr: int, asm: str, out_path: str,
                 resign: bool = True) -> dict:
    """Write assembled code at `addr` into a copy at `out_path`; verify it."""
    code = assemble(img.arch, asm, addr)
    off = img.addr_to_offset(addr)
    if off is None:
        raise ValueError(f"address {addr:#x} is not mapped in {img.path}")
    if off + len(code) > len(img.data):
        raise ValueError("patch extends past end of file")
    old = img.data[off:off + len(code)]
    buf = bytearray(img.data)
    buf[off:off + len(code)] = code
    out = Path(out_path)
    if out.exists():
        raise FileExistsError(f"patch output already exists: {out}")
    # "xb" closes the check/write race: an existing path is never truncated.
    with out.open("xb") as fh:
        fh.write(buf)
    try:
        out.chmod(0o755)
    except OSError:
        pass
    signed = False
    if resign and img.format in ("mach-o", "mach-o-fat"):
        try:
            r = subprocess.run(["codesign", "-f", "-s", "-", str(out)],
                               capture_output=True, text=True, timeout=60)
            signed = r.returncode == 0
        except (OSError, subprocess.SubprocessError):
            signed = False
    from .formats import load_binary
    check = load_binary(str(out), raw_arch=img.arch if img.format == "raw" else None)
    md = engine.make_decoder(check.arch, big_endian=(check.endian == "big"))
    ins = engine.decode_at(check, md, addr)
    return {"out": str(out), "addr": hex(addr), "offset": off,
            "old_bytes": old.hex(), "new_bytes": code.hex(),
            "resigned": signed,
            "verified_instruction": ins.text if ins else None}
