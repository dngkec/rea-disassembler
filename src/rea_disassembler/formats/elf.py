"""ELF loader: 32/64-bit, LE/BE, sections + symtab/dynsym + program headers."""
from __future__ import annotations

import struct

from ..models import BinaryImage, Section, Segment, Symbol

ET_EXEC, ET_DYN = 2, 3
SHT_SYMTAB, SHT_DYNSYM, SHT_STRTAB = 2, 11, 3
STT_FUNC, STT_OBJECT = 2, 1
MACHINES = {62: ("x86_64", 64), 3: ("x86", 32), 183: ("arm64", 64), 40: ("arm", 32)}


def load(path: str, data: bytes, arch: str | None = None) -> BinaryImage:
    if len(data) < 52 or data[:4] != b"\x7fELF":
        raise ValueError("not an ELF image")
    ei_class, ei_data = data[4], data[5]
    bits = 64 if ei_class == 2 else 32
    endian = "<" if ei_data == 1 else ">"
    if bits == 64:
        (_t, machine, _v, entry, phoff, shoff, _flags, _eh, phentsize, phnum,
         shentsize, shnum, shstrndx) = struct.unpack_from(f"{endian}HHIQQQIHHHHHH", data, 16)
    else:
        (_t, machine, _v, entry, phoff, shoff, _flags, _eh, phentsize, phnum,
         shentsize, shnum, shstrndx) = struct.unpack_from(f"{endian}HHIIIIIHHHHHH", data, 16)
    name, _ = MACHINES.get(machine, (arch or f"machine-{machine}", bits))
    img = BinaryImage(path=path, format="elf", arch=arch or name, bits=bits,
                      endian="little" if endian == "<" else "big",
                      entry=entry, image_base=0, data=data)
    e_type = struct.unpack_from(f"{endian}H", data, 16)[0]
    raw_sections = []
    for i in range(shnum):
        o = shoff + i * shentsize
        if o + shentsize > len(data):
            break
        if bits == 64:
            nm, typ, flags, addr, off, size, link, _info, _al, _es = struct.unpack_from(f"{endian}IIQQQQIIQQ", data, o)
        else:
            nm, typ, flags, addr, off, size, link, _info, _al, _es = struct.unpack_from(f"{endian}IIIIIIIIII", data, o)
        raw_sections.append((nm, typ, flags, addr, off, size, link))
    if e_type == 1:  # ET_REL: no VAs — assign synthetic, non-overlapping ones
        va = 0x400000
        fixed = []
        for (nm, typ, flags, addr, off, size, link) in raw_sections:
            if flags & 0x2 and size:  # SHF_ALLOC
                fixed.append((nm, typ, flags, va, off, size, link))
                va += (size + 0xFFF) & ~0xFFF
            else:
                fixed.append((nm, typ, flags, addr, off, size, link))
        raw_sections = fixed
    shstr = b""
    if 0 <= shstrndx < len(raw_sections):
        s = raw_sections[shstrndx]
        shstr = data[s[4]:s[4] + s[5]]

    def sname(nm: int) -> str:
        end = shstr.find(b"\x00", nm)
        return shstr[nm:end if end != -1 else len(shstr)].decode("utf-8", "replace")

    img.sections = [Section(name=sname(nm), segment="", addr=addr, size=size, offset=off,
                            flags=int(flags), is_code=bool(flags & 0x4),
                            is_data=not bool(flags & 0x4))
                    for (nm, _t, flags, addr, off, size, _l) in raw_sections if size or addr]
    for i in range(phnum):
        o = phoff + i * phentsize
        if o + phentsize > len(data):
            break
        if bits == 64:
            p_type, p_flags, p_off, p_va, _pa, p_filesz, _msz, _al = struct.unpack_from(f"{endian}IIQQQQQQ", data, o)
        else:
            p_type, p_off, p_va, _pa, p_filesz, _msz, p_flags, _al = struct.unpack_from(f"{endian}IIIIIIII", data, o)
        if p_type == 1:  # PT_LOAD
            img.segments.append(Segment(f"LOAD{i}", p_va, p_filesz, p_off, initprot=p_flags))
    if img.segments:
        img.image_base = min(s.addr for s in img.segments)
    for idx, (nm, typ, _f, _a, off, size, link) in enumerate(raw_sections):
        if typ not in (SHT_SYMTAB, SHT_DYNSYM) or not (0 <= link < len(raw_sections)):
            continue
        strtab = raw_sections[link]
        strs = data[strtab[4]:strtab[4] + strtab[5]]
        entsz = 24 if bits == 64 else 16
        for j in range(size // entsz if entsz else 0):
            o = off + j * entsz
            if bits == 64:
                st_name, st_info, _other, st_shndx, st_value, st_size = struct.unpack_from(f"{endian}IBBHQQ", data, o)
            else:
                st_name, st_value, st_size, st_info, _other, st_shndx = struct.unpack_from(f"{endian}IIIBBH", data, o)
            if e_type == 1 and 0 < st_shndx < len(raw_sections):
                st_value = raw_sections[st_shndx][3] + st_value
            if not st_name or st_value == 0:
                continue
            end = strs.find(b"\x00", st_name)
            nm2 = strs[st_name:end if end != -1 else len(strs)].decode("utf-8", "replace")
            if not nm2:
                continue
            stt = st_info & 0xF
            kind = "func" if stt == STT_FUNC else "object" if stt == STT_OBJECT else "unknown"
            sym = Symbol(nm2, st_value, size=int(st_size), kind=kind)
            (img.imports if typ == SHT_DYNSYM and st_value == 0 else img.symbols).append(sym)
            if kind == "func":
                img.exports.append(sym) if typ == SHT_DYNSYM else None
    return img
