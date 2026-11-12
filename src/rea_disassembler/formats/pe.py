"""PE loader: PE32/PE32+, sections, entry, import directory names."""
from __future__ import annotations

import struct

from ..models import BinaryImage, Section, Segment, Symbol


def load(path: str, data: bytes, arch: str | None = None) -> BinaryImage:
    if len(data) < 64 or data[:2] != b"MZ":
        raise ValueError("not a PE image (no MZ)")
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_off:pe_off + 4] != b"PE\x00\x00":
        raise ValueError("not a PE image (no PE signature)")
    machine, nsects, _ts, symtab_off, nsyms, opt_size, _chars = struct.unpack_from("<HHIIIHH", data, pe_off + 4)
    opt = pe_off + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    is64 = magic == 0x20B
    bits = 64 if is64 else 32
    if is64:
        image_base = struct.unpack_from("<Q", data, opt + 24)[0]
        entry_rva = struct.unpack_from("<I", data, opt + 16)[0]
        dd_base = opt + 112
    else:
        image_base = struct.unpack_from("<I", data, opt + 28)[0]
        entry_rva = struct.unpack_from("<I", data, opt + 16)[0]
        dd_base = opt + 96
    arch_name = "x86_64" if machine == 0x8664 else "arm64" if machine == 0xAA64 else "x86"
    img = BinaryImage(path=path, format="pe", arch=arch or arch_name, bits=bits,
                      endian="little", entry=image_base + entry_rva,
                      image_base=image_base, data=data)
    sec_base = opt + opt_size
    for i in range(nsects):
        o = sec_base + i * 40
        if o + 40 > len(data):
            break
        name = data[o:o + 8].split(b"\x00")[0].decode("utf-8", "replace")
        vsize, vaddr, rawsize, rawoff = struct.unpack_from("<IIII", data, o + 8)
        chars = struct.unpack_from("<I", data, o + 36)[0]
        img.sections.append(Section(name=name, segment=name, addr=image_base + vaddr,
                                    size=max(vsize, rawsize), offset=rawoff, flags=chars,
                                    is_code=bool(chars & 0x20), is_data=not bool(chars & 0x20)))
        img.segments.append(Segment(name, image_base + vaddr, max(vsize, rawsize), rawoff))
    def rva_off(rva: int) -> int | None:
        for s in img.sections:
            start = s.addr - image_base
            if start <= rva < start + s.size:
                return s.offset + (rva - start)
        return None
    # Import directory (data directory index 1)
    if dd_base + 16 <= len(data):
        imp_rva, _imp_sz = struct.unpack_from("<II", data, dd_base + 8)
        o = rva_off(imp_rva) if imp_rva else None
        while o is not None and o + 20 <= len(data):
            oft, _td, _fwd, name_rva, _ft = struct.unpack_from("<IIIII", data, o)
            if not any((oft, name_rva)):
                break
            no = rva_off(name_rva)
            dll = data[no:data.find(b"\x00", no)].decode("utf-8", "replace") if no else "?"
            to = rva_off(oft)
            if to:
                step = 8 if is64 else 4
                for j in range(4096):
                    val = struct.unpack_from("<Q" if is64 else "<I", data, to + j * step)[0]
                    if val == 0:
                        break
                    if not (val >> (63 if is64 else 31)):  # by-name import
                        hn = rva_off(val & 0x7FFFFFFF)
                        if hn:
                            fn = data[hn + 2:data.find(b"\x00", hn + 2)].decode("utf-8", "replace")
                            img.imports.append(Symbol(f"{dll}!{fn}", 0, kind="import"))
            o += 20
    # COFF symbols, when present
    if symtab_off and nsyms:
        strtab = symtab_off + nsyms * 18
        for i in range(nsyms):
            o = symtab_off + i * 18
            if o + 18 > len(data):
                break
            raw = data[o:o + 8]
            if raw[:4] == b"\x00\x00\x00\x00":
                zo = strtab + struct.unpack_from("<I", raw, 4)[0]
                name = data[zo:data.find(b"\x00", zo)].decode("utf-8", "replace")
            else:
                name = raw.split(b"\x00")[0].decode("utf-8", "replace")
            value, _sec, _typ, sclass, _aux = struct.unpack_from("<IhHBB", data, o + 8)
            if name and value:
                img.symbols.append(Symbol(name, image_base + value if value < image_base else value,
                                          kind="func" if sclass == 2 else "unknown"))
    return img
