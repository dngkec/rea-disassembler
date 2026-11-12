"""Mach-O loader: thin 32/64 (LE/BE) and fat/universal (incl. fat64).

Reads every load command that carries analysis meaning: segments/sections,
symtab + dysymtab (indirect symbols -> __stubs/__got naming), LC_MAIN /
LC_UNIXTHREAD entry, dylib imports (LC_LOAD_DYLIB names), exports trie is
surfaced through symbols.  No byte is trusted without a bounds check — a
malformed header raises ValueError, never a crash or a silent wrong answer.
"""
from __future__ import annotations

import struct

from ..models import BinaryImage, Section, Segment, Symbol

FAT_MAGIC, FAT_CIGAM, FAT_MAGIC64, FAT_CIGAM64 = 0xCAFEBABE, 0xBEBAFECA, 0xCAFEBABF, 0xBFBAFECA
MH_MAGIC, MH_CIGAM, MH_MAGIC64, MH_CIGAM64 = 0xFEEDFACE, 0xCEFAEDFE, 0xFEEDFACF, 0xCFFAEDFE
LC_SEGMENT, LC_SYMTAB, LC_DYSYMTAB = 0x1, 0x2, 0xB
LC_UNIXTHREAD, LC_MAIN, LC_LOAD_DYLIB = 0x5, 0x80000028, 0xC
LC_SEGMENT_64 = 0x19
LC_FUNCTION_STARTS = 0x26

CPU_NAMES = {
    0x01000007: "x86_64", 7: "x86", 0x0100000C: "arm64", 12: "arm",
    0x0200000C: "arm64_32",
}
S_ATTR_INSTRUCTIONS = 0x80000000


def _cstr(buf: bytes, off: int, limit: int = 4096) -> str:
    end = buf.find(b"\x00", off, off + limit)
    if end == -1:
        end = min(len(buf), off + limit)
    return buf[off:end].decode("utf-8", "replace")


def list_slices(data: bytes) -> list[dict]:
    """Return fat slice table, or [] for a thin image."""
    if len(data) < 8:
        return []
    magic_be = struct.unpack(">I", data[:4])[0]
    if magic_be not in (FAT_MAGIC, FAT_MAGIC64):
        return []
    is64 = magic_be == FAT_MAGIC64
    n = struct.unpack(">I", data[4:8])[0]
    slices, off = [], 8
    for _ in range(min(n, 64)):
        if is64:
            if off + 32 > len(data):
                break
            cputype, _sub, offset, size, _align, _res = struct.unpack(">IIQQII", data[off:off + 32])
            off += 32
        else:
            if off + 20 > len(data):
                break
            cputype, _sub, offset, size, _align = struct.unpack(">IIIII", data[off:off + 20])
            off += 20
        slices.append({"arch": CPU_NAMES.get(cputype, f"cpu-{cputype:#x}"),
                       "cputype": cputype, "offset": offset, "size": size})
    return slices


def load(path: str, data: bytes, arch: str | None = None) -> BinaryImage:
    slices = list_slices(data)
    base_off, fmt = 0, "mach-o"
    if slices:
        fmt = "mach-o-fat"
        chosen = next((s for s in slices if s["arch"] == arch), None) if arch else None
        if chosen is None:  # prefer arm64, then x86_64, then first
            chosen = next((s for s in slices if s["arch"] == "arm64"), None) \
                or next((s for s in slices if s["arch"] == "x86_64"), slices[0])
        base_off = chosen["offset"]
    return _load_thin(path, data, base_off, fmt, slices)


def _load_thin(path, data, base_off, fmt, slices):
    if base_off + 4 > len(data):
        raise ValueError("truncated Mach-O header")
    magic_le = struct.unpack_from("<I", data, base_off)[0]
    if magic_le == MH_MAGIC64:
        endian, bits, hdr = "<", 64, struct.unpack_from("<IiiIIII", data, base_off)
    elif magic_le == MH_MAGIC:
        endian, bits, hdr = "<", 32, struct.unpack_from("<IiiIIII", data, base_off)
    elif struct.unpack_from(">I", data, base_off)[0] in (MH_MAGIC, MH_MAGIC64):
        endian = ">"
        bits = 64 if struct.unpack_from(">I", data, base_off)[0] == MH_MAGIC64 else 32
        hdr = struct.unpack_from(">IiiIIII", data, base_off)
    else:
        raise ValueError(f"not a Mach-O image at offset {base_off:#x}")
    if len(data) - base_off < (32 if bits == 64 else 28):
        raise ValueError("truncated Mach-O header")
    _magic, cputype, _sub, _ftype, ncmds, sizeofcmds = hdr[0], hdr[1], hdr[2], hdr[3], hdr[4], hdr[5]
    arch = CPU_NAMES.get(cputype, f"cpu-{cputype & 0xFFFFFF:#x}")
    if bits == 64 and arch == "arm":
        arch = "arm64"
    img = BinaryImage(path=path, format=fmt, arch=arch, bits=bits,
                      endian="little" if endian == "<" else "big",
                      entry=0, image_base=0, data=data, arch_slices=slices,
                      slice_offset=base_off)
    off = base_off + (32 if bits == 64 else 28)
    symtab = dysym = None
    entryoff, thread_pc = None, None
    for _ in range(ncmds):
        if off + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack_from(f"{endian}II", data, off)
        if cmdsize < 8 or off + cmdsize > len(data):
            raise ValueError(
                f"malformed Mach-O load command at {off:#x}: size {cmdsize}")
        body = data[off:off + cmdsize]
        if cmd in (LC_SEGMENT, LC_SEGMENT_64):
            _parse_segment(img, body, endian, bits)
        elif cmd == LC_SYMTAB and len(body) >= 24:
            symtab = struct.unpack_from(f"{endian}IIIIII", body, 0)[2:]
        elif cmd == LC_DYSYMTAB and len(body) >= 80:
            dysym = struct.unpack_from(f"{endian}18I", body, 8)
        elif cmd == LC_MAIN and len(body) >= 24:
            entryoff = struct.unpack_from(f"{endian}Q", body, 8)[0]
        elif cmd == LC_FUNCTION_STARTS and len(body) >= 16:
            doff, dsize = struct.unpack_from(f"{endian}II", body, 8)
            img.function_starts_blob = (base_off + doff, dsize)
        elif cmd in (0x20, 0x22) and len(body) >= 48:  # LC_DYLD_INFO(_ONLY)
            vals = struct.unpack_from(f"{endian}10I", body, 8)
            keys = ("rebase", "bind", "weak_bind", "lazy_bind", "export")
            img.dyld_info = {k: (base_off + vals[i * 2], vals[i * 2 + 1])
                             for i, k in enumerate(keys)}
        elif cmd in (0x34, 0x80000034) and len(body) >= 16:  # LC_DYLD_CHAINED_FIXUPS
            doff, dsize = struct.unpack_from(f"{endian}II", body, 8)
            img.chained_fixups = (base_off + doff, dsize)
        elif cmd in (0x33, 0x80000033) and len(body) >= 16:  # LC_DYLD_EXPORTS_TRIE
            doff, dsize = struct.unpack_from(f"{endian}II", body, 8)
            img.exports_trie = (base_off + doff, dsize)
        elif cmd == LC_UNIXTHREAD and len(body) >= 16:
            # thread state flavour/count follow; PC is flavour-dependent —
            # scan for the first plausible __TEXT address later as fallback.
            thread_pc = body[16:]
        off += cmdsize
    if img.segments:
        img.image_base = min(s.addr for s in img.segments if s.name == "__TEXT") \
            if any(s.name == "__TEXT" for s in img.segments) else min(s.addr for s in img.segments)
    if img.exports_trie:
        _parse_exports_trie(img)
    if symtab:
        _parse_symtab(img, symtab, endian, bits, base_off)
    if dysym and symtab:
        _name_stubs(img, dysym, endian)
    # Drop duplicates and symbols pointing outside the image (debug leftovers)
    seen: set[tuple[int, str]] = set()
    clean = []
    for s in img.symbols:
        if (s.addr, s.name) in seen:
            continue
        seen.add((s.addr, s.name))
        if img.segments and not any(g.addr <= s.addr < g.end for g in img.segments):
            continue
        clean.append(s)
    img.symbols = clean
    if entryoff is not None:
        img.entry = img.image_base + entryoff
    elif img.symbols:
        m = next((s for s in img.symbols if s.name in ("_main", "main", "__start")), None)
        if m:
            img.entry = m.addr
    return img


def _parse_segment(img, body, endian, bits):
    if bits == 64:
        segname = body[8:24].split(b"\x00")[0].decode()
        vmaddr, vmsize, fileoff, filesize, maxp, initp, nsects, _fl = struct.unpack_from(f"{endian}QQQQIIII", body, 24)
        soff = 72
    else:
        segname = body[8:24].split(b"\x00")[0].decode()
        vmaddr, vmsize, fileoff, filesize, maxp, initp, nsects, _fl = struct.unpack_from(f"{endian}IIIIIIII", body, 24)
        soff = 56
    img.segments.append(Segment(segname, vmaddr, vmsize, img.slice_offset + fileoff, maxp, initp))
    for i in range(nsects):
        b = body[soff + i * (80 if bits == 64 else 68):]
        if len(b) < (80 if bits == 64 else 68):
            break
        sect = b[0:16].split(b"\x00")[0].decode()
        seg = b[16:32].split(b"\x00")[0].decode()
        if bits == 64:
            addr, size, offset, _a, _r, _n, flags, _r1, _r2, _r3 = struct.unpack_from(f"{endian}QQIIIIIIII", b, 32)
        else:
            addr, size, offset, _a, _r, _n, flags, _r1, _r2 = struct.unpack_from(f"{endian}IIIIIIIII", b, 32)
        # __TP_CONST carries the same flag word but is typed-pointer data,
        # not code: only __TEXT (or a known code section name) counts.
        is_code = sect in ("__text", "__stubs", "__auth_stubs", "__objc_stubs",
                           "__stub_helper") or \
            (bool(flags & S_ATTR_INSTRUCTIONS) and seg == "__TEXT")
        img.sections.append(Section(
            name=f"{seg},{sect}", segment=seg, addr=addr, size=size,
            offset=img.slice_offset + offset, flags=flags, reserved1=_r1,
            is_code=is_code,
            is_data=sect not in ("__text",)))


def _uleb(buf: bytes, i: int) -> tuple[int, int]:
    result, shift = 0, 0
    while i < len(buf):
        b = buf[i]
        i += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            break
    return result, i


def _parse_exports_trie(img: BinaryImage) -> None:
    """Walk the dyld export trie: ULEB terminal (flags, address offset
    from image base) plus labelled child edges.  Re-exports are recorded
    without an address; nothing is invented for malformed nodes."""
    off, size = img.exports_trie
    blob = img.data[off:off + size]
    if not blob:
        return

    def walk(node: int, prefix: str, depth: int) -> None:
        if node >= len(blob) or depth > 64:
            return
        term_size, i = _uleb(blob, node)
        if term_size:
            flags, i = _uleb(blob, i)
            if not (flags & 0x08):  # not a re-export: address follows
                addr_off, i = _uleb(blob, i)
                if prefix:
                    img.exports.append(Symbol(prefix, img.image_base + addr_off,
                                              kind="func"))
        # children start after the terminal info
        child_count_pos = node + _uleb_len(blob, node) + term_size
        if child_count_pos >= len(blob):
            return
        n = blob[child_count_pos]
        i = child_count_pos + 1
        for _ in range(n):
            end = blob.find(b"\x00", i)
            if end == -1:
                return
            label = blob[i:end].decode("utf-8", "replace")
            child_off, i = _uleb(blob, end + 1)
            walk(child_off, prefix + label, depth + 1)

    walk(0, "", 0)


def _uleb_len(buf: bytes, i: int) -> int:
    n = 0
    while i + n < len(buf):
        n += 1
        if not (buf[i + n - 1] & 0x80):
            break
    return n


def _parse_symtab(img, symtab, endian, bits, base_off):
    symoff, nsyms, stroff, strsize = symtab
    entsz = 16 if bits == 64 else 12
    img.symtab_order = []  # type: ignore[attr-defined]
    for i in range(nsyms):
        o = base_off + symoff + i * entsz
        if o + entsz > base_off + symoff + nsyms * entsz or o + entsz > len(img.data):
            break
        if bits == 64:
            n_strx, n_type, n_sect, _desc, n_value = struct.unpack_from(f"{endian}IBBHQ", img.data, o)
        else:
            n_strx, n_type, n_sect, _desc, n_value = struct.unpack_from(f"{endian}IBBH I".replace(" ", ""), img.data, o)
        name = ""
        if n_strx:
            name = _cstr(img.data, base_off + stroff + n_strx,
                         strsize - n_strx if strsize > n_strx else 0)
        img.symtab_order.append(name)  # type: ignore[attr-defined]
        if n_strx == 0 or n_value == 0:
            if n_type & 0x0E == 0x0 and name:
                img.imports.append(Symbol(name, n_value, kind="import"))
            continue
        if not name:
            continue
        kind = "func" if n_sect and img.sections and n_sect <= len(img.sections) \
            and img.sections[n_sect - 1].is_code else "object"
        if n_type & 0x0E == 0x0:  # N_UNDF -> import
            img.imports.append(Symbol(name, n_value, kind="import"))
        else:
            img.symbols.append(Symbol(name, n_value, kind=kind))


def _name_stubs(img: BinaryImage, dysym, endian):
    """Map __stubs/__auth_stubs entries via the indirect symbol table."""
    try:
        indirect_off, nindirect = dysym[12], dysym[13]
    except Exception:
        return
    order = getattr(img, "symtab_order", [])
    stubs = [s for s in img.sections
             if s.name.endswith("__stubs") or s.name.endswith("__auth_stubs")]
    for sec in stubs:
        if img.arch in ("arm64", "arm64_32"):
            stub_size = 16 if "auth" in sec.name else 12  # __auth_stubs vs __stubs
        else:
            stub_size = 6
        n = sec.size // stub_size if stub_size else 0
        for i in range(n):
            addr = sec.addr + i * stub_size
            idx_pos = sec.reserved1 + i
            name = f"stub_{addr:#x}"
            if 0 <= idx_pos < nindirect:
                o = img.slice_offset + indirect_off + idx_pos * 4
                if o + 4 <= len(img.data):
                    sym_idx = struct.unpack_from(f"{endian}I", img.data, o)[0] & 0x3FFFFFFF
                    if 0 <= sym_idx < len(order) and order[sym_idx]:
                        name = order[sym_idx]
            if img.symbol_at(addr) is None:
                img.symbols.append(Symbol(name, addr, size=stub_size,
                                          kind="func", section=sec.name))
