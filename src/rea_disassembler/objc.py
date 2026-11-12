"""Objective-C method discovery for Mach-O images.

Modern (relative) and legacy (absolute) method lists are parsed wherever
they live: the standalone __objc_methlist section, class data reached from
__objc_classlist, and category data reached from __objc_catlist.  Each IMP
becomes a named function seed — this is how Hopper finds methods that no
direct call reaches, and a disassembler without it is blind on macOS.

Pointer hygiene: every pointer is validated against the image's segments,
with dyld chained-fixup masking as a fallback.  Anything unparseable is
skipped, never guessed.
"""
from __future__ import annotations

import struct

from .models import BinaryImage


def _u32(img: BinaryImage, addr: int) -> int | None:
    off = img.addr_to_offset(addr)
    if off is None or off + 4 > len(img.data):
        return None
    return struct.unpack_from("<I", img.data, off)[0]


def _i32(img: BinaryImage, addr: int) -> int | None:
    v = _u32(img, addr)
    return struct.unpack("<i", struct.pack("<I", v))[0] if v is not None else None


def _ptr(img: BinaryImage, addr: int) -> int | None:
    off = img.addr_to_offset(addr)
    if off is None:
        return None
    if img.bits == 64:
        if off + 8 > len(img.data):
            return None
        v = struct.unpack_from("<Q", img.data, off)[0]
    else:
        if off + 4 > len(img.data):
            return None
        v = struct.unpack_from("<I", img.data, off)[0]
    if img.section_at(v) is not None or any(s.addr <= v < s.end for s in img.segments):
        return v
    for cand in (img.image_base + (v & 0xFFFFFFFFF), v & 0x0000FFFFFFFFFFFF,
                 img.image_base + (v & 0xFFFFFFFFFF)):
        if any(s.addr <= cand < s.end for s in img.segments):
            return cand
    return None


def _cstr_at(img: BinaryImage, addr: int, limit: int = 512) -> str | None:
    off = img.addr_to_offset(addr)
    if off is None:
        return None
    end = img.data.find(b"\x00", off, off + limit)
    if end == -1:
        return None
    try:
        return img.data[off:end].decode("utf-8")
    except UnicodeDecodeError:
        return None


def _selector(img: BinaryImage, name_field_addr: int, relative: bool) -> str | None:
    if relative:
        off = _i32(img, name_field_addr)
        if off is None:
            return None
        selref = name_field_addr + off
        target = _ptr(img, selref)  # selref -> methname string
        return _cstr_at(img, target) if target else _cstr_at(img, selref)
    target = _ptr(img, name_field_addr)
    if target is None:
        return None
    direct = _cstr_at(img, target)
    if direct:
        return direct
    deref = _ptr(img, target)
    return _cstr_at(img, deref) if deref else None


def parse_method_list(img: BinaryImage, list_addr: int,
                      owner: str = "") -> dict[int, str]:
    """Return {imp_addr: '-[Owner selector:]'} for one method list."""
    out: dict[int, str] = {}
    header = _u32(img, list_addr)
    count = _u32(img, list_addr + 4)
    if header is None or count is None or count > 100000:
        return out
    relative = bool(header & 0x80000000)
    entsize = (header & 0xFFFC) if relative else header
    if relative and entsize == 0:
        entsize = 12
    if not relative and entsize == 0:
        entsize = 24 if img.bits == 64 else 12
    step = 12 if relative else entsize
    for i in range(count):
        entry = list_addr + 8 + i * step
        if relative:
            imp_off = _i32(img, entry + 8)
            if imp_off is None:
                continue
            imp = entry + 8 + imp_off
            sel = _selector(img, entry, True)
        else:
            imp = _ptr(img, entry + (16 if img.bits == 64 else 8))
            if imp is None:
                continue
            sel = _selector(img, entry, False)
        if imp and img.section_at(imp) is not None and img.section_at(imp).is_code:
            name = f"-[{owner} {sel}]" if owner and sel else (sel or f"sub_{imp:x}")
            out[imp] = name
    return out


def discover_objc_methods(img: BinaryImage) -> dict[int, str]:
    """All ObjC method IMPs in the image, named where the metadata allows."""
    if img.format not in ("mach-o", "mach-o-fat"):
        return {}
    out: dict[int, str] = {}
    sec_by_name = {s.name.split(",")[-1]: s for s in img.sections}
    # 1. Standalone method-list section (small / single-class images)
    ml = sec_by_name.get("__objc_methlist")
    if ml is not None:
        out.update(parse_method_list(img, ml.addr))
    w = 8 if img.bits == 64 else 4

    def ptr_array(sec_name: str) -> list[int]:
        sec = sec_by_name.get(sec_name)
        if sec is None:
            return []
        vals = []
        for off in range(0, sec.size - w + 1, w):
            v = _ptr(img, sec.addr + off)
            if v:
                vals.append(v)
        return vals

    # 2. Classes: classlist -> class -> data (ro) -> name + baseMethods
    for cls in ptr_array("__objc_classlist"):
        ro = _ptr(img, cls + (32 if img.bits == 64 else 20))
        if ro is None:
            continue
        ro &= ~0x7  # class_rw/ro pointer carries flag bits in the low bits
        if img.addr_to_offset(ro) is None:  # masked variant may need base fix
            ro = _ptr(img, cls + (32 if img.bits == 64 else 20)) or ro
        name_ptr = _ptr(img, ro + (24 if img.bits == 64 else 20))
        cname = _cstr_at(img, name_ptr) if name_ptr else ""
        methods = _ptr(img, ro + (32 if img.bits == 64 else 24))
        if methods:
            out.update(parse_method_list(img, methods, cname or ""))
        # metaclass methods live on the isa class's ro list
        isa = _ptr(img, cls)
        if isa:
            mro = _ptr(img, isa + (32 if img.bits == 64 else 20))
            if mro:
                mm = _ptr(img, (mro & ~0x7) + (32 if img.bits == 64 else 24))
                if mm:
                    out.update(parse_method_list(img, mm, cname or ""))
    # 3. Categories: catlist -> category -> instance/class method lists.
    #    Owner is the *class* name (from the cls pointer), not the category
    #    name in the first field.
    # External classes (e.g. categories on Foundation classes) exist only
    # as dyld binds: resolve the cls slot's bound symbol first.
    from .binds import bind_map, slot_symbol
    classic, imports = bind_map(img)
    for cat in ptr_array("__objc_catlist"):
        sym = slot_symbol(img, cat + (8 if img.bits == 64 else 4), classic, imports)
        owner = ""
        if sym and "_OBJC_CLASS_$_" in sym:
            owner = sym.split("_OBJC_CLASS_$_", 1)[1]
        elif sym and "_OBJC_METACLASS_$_" in sym:
            owner = sym.split("_OBJC_METACLASS_$_", 1)[1]
        cls = _ptr(img, cat + (8 if img.bits == 64 else 4))
        if cls and not owner:
            cro = _ptr(img, cls + (32 if img.bits == 64 else 20))
            if cro:
                np = _ptr(img, (cro & ~0x7) + (24 if img.bits == 64 else 20))
                owner = _cstr_at(img, np) if np else ""
        for off, kind in ((16, "-"), (24, "+")):
            methods = _ptr(img, cat + (off if img.bits == 64 else off // 2))
            if methods:
                for imp, nm in parse_method_list(img, methods, owner or "").items():
                    out[imp] = nm.replace("-[", f"{kind}[", 1) if nm.startswith("-[") else nm
    return out
