"""Dyld bind resolution: which symbol a data slot is bound to.

Two encodings are supported:
  * LC_DYLD_INFO bind opcode streams (classic), walked as a state machine
    over (segment, offset, symbol) exactly as dyld defines them.
  * LC_DYLD_CHAINED_FIXUPS (modern): the header's import table maps an
    ordinal to a symbol name; a slot whose raw value is a bind pointer
    (top bit set on arm64e) carries that ordinal in its low bits.

This is what turns a category's `cls` field into `_OBJC_CLASS_$_Foo`.
Anything unresolvable returns None — never a guess.
"""
from __future__ import annotations

import struct

from .models import BinaryImage


def _uleb(data: bytes, i: int) -> tuple[int, int]:
    result, shift = 0, 0
    while i < len(data):
        b = data[i]
        i += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            break
    return result, i


def _sleb(data: bytes, i: int) -> tuple[int, int]:
    result, shift = 0, 0
    while i < len(data):
        b = data[i]
        i += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            if b & 0x40:
                result |= -(1 << shift)
            break
    return result, i


def parse_classic_binds(img: BinaryImage) -> dict[int, str]:
    """addr -> symbol for every DO_BIND in bind/weak/lazy streams."""
    out: dict[int, str] = {}
    if not img.dyld_info:
        return out
    for key in ("bind", "weak_bind", "lazy_bind"):
        off, size = img.dyld_info.get(key, (0, 0))
        if not size:
            continue
        stream = img.data[off:off + size]
        seg_idx, seg_off, symbol, i = 0, 0, None, 0
        while i < len(stream):
            byte = stream[i]
            i += 1
            opcode, imm = byte & 0xF0, byte & 0x0F
            if opcode == 0x00:  # DONE
                break
            elif opcode == 0x10:
                pass  # ordinal imm: irrelevant to naming
            elif opcode in (0x20, 0x80, 0x70):
                v, i = _uleb(stream, i)
                if opcode == 0x70:
                    seg_idx, seg_off = imm, v
                elif opcode == 0x80:
                    seg_off += v
            elif opcode == 0x30:
                pass
            elif opcode == 0x40:
                end = stream.find(b"\x00", i)
                symbol = stream[i:end if end != -1 else len(stream)].decode("utf-8", "replace")
                i = (end + 1) if end != -1 else len(stream)
            elif opcode == 0x50:
                pass
            elif opcode == 0x60:
                _v, i = _sleb(stream, i)
            elif opcode in (0x90, 0xA0, 0xB0, 0xC0):
                if opcode == 0xA0:
                    v, i = _uleb(stream, i)
                    seg_off += v
                elif opcode == 0xC0:
                    count, i = _uleb(stream, i)
                    skip, i = _uleb(stream, i)
                    for _ in range(count):
                        _record(img, seg_idx, seg_off, symbol, out)
                        seg_off += skip + 8
                    continue
                _record(img, seg_idx, seg_off, symbol, out)
                seg_off += (imm * 8) if opcode == 0xB0 else 8
    return out


def _record(img, seg_idx, seg_off, symbol, out):
    if symbol and 0 <= seg_idx < len(img.segments):
        out[img.segments[seg_idx].addr + seg_off] = symbol


def chained_imports(img: BinaryImage) -> list[str]:
    """Import symbol names from the chained-fixups header, in ordinal order."""
    if not img.chained_fixups:
        return []
    base, _size = img.chained_fixups
    if base + 24 > len(img.data):
        return []
    (_ver, starts_off, imports_off, symbols_off, imports_count,
     _symbols_count, imports_fmt, _sym_fmt) = struct.unpack_from("<IIIIIIII", img.data, base)
    names: list[str] = []
    pool = base + symbols_off
    # dyld_chained_import is a u32 bitfield: lib_ordinal[0:8], weak[8],
    # name_offset[9:32] into the symbol pool.  (Verified empirically:
    # ordinal 43 of Hopper's launcher is _OBJC_CLASS_$_NSMetadataQuery,
    # at pool offset 734 = 0x5bc01 >> 9.)
    for k in range(min(imports_count, 100000)):
        entry, = struct.unpack_from("<I", img.data, base + imports_off + k * 4)
        off = entry >> 9
        end = img.data.find(b"\x00", pool + off, pool + off + 512)
        names.append(img.data[pool + off:end if end != -1 else pool + off + 512]
                     .decode("utf-8", "replace"))
    return names


def slot_symbol(img: BinaryImage, addr: int, classic: dict[int, str] | None = None,
                imports: list[str] | None = None) -> str | None:
    """Symbol bound at `addr`, or None."""
    if classic is not None and addr in classic:
        return classic[addr]
    off = img.addr_to_offset(addr)
    if off is None or off + 8 > len(img.data):
        return None
    raw, = struct.unpack_from("<Q", img.data, off)
    if raw >> 63:  # arm64e chained bind/auth pointer: ordinal in low bits
        if imports is None:
            imports = chained_imports(img)
        for width in (16, 8):
            ordinal = raw & ((1 << width) - 1)
            if 0 <= ordinal < len(imports):
                return imports[ordinal]
    return None


def bind_map(img: BinaryImage) -> tuple[dict[int, str], list[str]]:
    return parse_classic_binds(img), chained_imports(img)
