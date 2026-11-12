"""Truncated/malformed container headers must be ValueError, never a
leaked struct.error/IndexError traceback.  The format boundary owns this
contract: callers (CLI/HTTP/MCP) only translate ValueError."""
import struct

import pytest

from rea_disassembler.formats import load_binary


def _write(tmp_path, data: bytes):
    p = tmp_path / "trunc.bin"
    p.write_bytes(data)
    return str(p)


def test_macho_thin_truncations(tmp_path):
    for n in (4, 8, 16, 27, 28, 31):
        data = struct.pack("<I", 0xFEEDFACF) + b"\x00" * max(0, n - 4)
        with pytest.raises(ValueError):
            load_binary(_write(tmp_path, data[:n]))


def test_macho_bad_load_command_size(tmp_path):
    # valid 64-bit header, one command claiming size 0 (would loop forever
    # if trusted) and one claiming a size past EOF
    hdr = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1, 8, 0, 0)
    for cmdsize in (0, 4, 0xFFFFFF00):
        data = hdr + struct.pack("<II", 0x1, cmdsize)
        with pytest.raises(ValueError):
            load_binary(_write(tmp_path, data))


def test_fat_truncated_and_huge_count(tmp_path):
    for data in (struct.pack(">II", 0xCAFEBABE, 1),
                 struct.pack(">II", 0xCAFEBABE, 0xFFFFFFFF),
                 struct.pack(">II", 0xCAFEBABE, 2) + b"\x00" * 10):
        with pytest.raises(ValueError):
            load_binary(_write(tmp_path, data))


def test_elf_truncations(tmp_path):
    for n in (5, 16, 40, 51):
        data = b"\x7fELF\x02\x01\x01" + b"\x00" * max(0, n - 7)
        with pytest.raises(ValueError):
            load_binary(_write(tmp_path, data[:n]))


def test_pe_truncations(tmp_path):
    for data in (b"MZ",
                 b"MZ" + b"\x00" * 30,
                 b"MZ" + b"\x00" * 58 + struct.pack("<I", 0xFFFF0000),
                 b"MZ" + b"\x00" * 58 + struct.pack("<I", 64) + b"PE\x00\x00" + b"\x64\x86"):
        with pytest.raises(ValueError):
            load_binary(_write(tmp_path, data))
