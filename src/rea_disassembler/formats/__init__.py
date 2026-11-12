"""Format detection and dispatch.  A wrong guess is worse than an error:
unknown bytes raise, they are never silently disassembled as the wrong ISA.
"""
from __future__ import annotations

from pathlib import Path

from ..models import BinaryImage, Section, Segment
from . import elf, macho, pe


def load_binary(path: str, arch: str | None = None,
                base: int = 0x100000000, raw_arch: str | None = None) -> BinaryImage:
    data = Path(path).read_bytes()
    if data[:4] == b"\x7fELF":
        return elf.load(path, data, arch=raw_arch or arch)
    if data[:2] == b"MZ":
        return pe.load(path, data, arch=raw_arch or arch)
    if macho.list_slices(data) or (len(data) >= 4 and int.from_bytes(data[:4], "little")
                                   in (macho.MH_MAGIC, macho.MH_MAGIC64)
                                   or int.from_bytes(data[:4], "big")
                                   in (macho.MH_MAGIC, macho.MH_MAGIC64)):
        return macho.load(path, data, arch=raw_arch or arch)
    if raw_arch:  # caller explicitly declared a headerless image
        img = BinaryImage(path=path, format="raw", arch=raw_arch,
                          bits=64 if raw_arch in ("arm64", "x86_64") else 32,
                          endian="little", entry=base, image_base=base, data=data)
        img.segments.append(Segment("__raw", base, len(data), 0))
        img.sections.append(Section("__raw", "__raw", base, len(data), 0, is_code=True))
        return img
    raise ValueError(
        f"unrecognised format for {path!r} (first bytes {data[:8].hex()}); "
        "pass --arch with --raw for headerless images")
