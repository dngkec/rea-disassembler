"""Core data model — the contract every format loader and analysis pass speaks.

Design note (vs. Hopper, audited in docs/AUDIT_HOPPER.md): Hopper's model is
Segment -> Section -> typed bytes, Procedure -> BasicBlock, with labels/tags
bolted onto addresses.  We keep that proven shape (it is the right shape) but
make every object a plain immutable-ish dataclass that serialises to JSON
without a live document, a GUI, or a proprietary .hop database.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Section:
    name: str
    segment: str
    addr: int
    size: int
    offset: int  # file offset
    flags: int = 0
    is_code: bool = False
    is_data: bool = False
    reserved1: int = 0  # Mach-O: first indirect-symbol index for stub sections

    @property
    def end(self) -> int:
        return self.addr + self.size


@dataclass
class Segment:
    name: str
    addr: int
    size: int
    offset: int
    maxprot: int = 0
    initprot: int = 0

    @property
    def end(self) -> int:
        return self.addr + self.size


@dataclass
class Symbol:
    name: str
    addr: int
    size: int = 0
    kind: str = "func"  # func | object | import | unknown
    binding: str = "global"
    section: str = ""


@dataclass
class Instruction:
    addr: int
    size: int
    mnemonic: str
    op_str: str
    bytes_hex: str
    is_call: bool = False
    is_branch: bool = False  # conditional or unconditional jump
    is_cond_branch: bool = False
    is_ret: bool = False
    is_indirect: bool = False
    branch_target: int | None = None
    call_target: int | None = None
    refs: tuple[int, ...] = ()  # data addresses referenced (rip-rel, adrp, imm)
    string_ref: str | None = None

    @property
    def text(self) -> str:
        return f"{self.mnemonic} {self.op_str}".strip()

    @property
    def end(self) -> int:
        return self.addr + self.size


@dataclass
class BasicBlock:
    start: int
    end: int  # exclusive
    instructions: list[Instruction] = field(default_factory=list)
    successors: list[int] = field(default_factory=list)
    predecessors: list[int] = field(default_factory=list)


@dataclass
class Function:
    addr: int
    name: str
    end: int = 0
    blocks: list[BasicBlock] = field(default_factory=list)
    callees: list[int] = field(default_factory=list)
    callers: list[int] = field(default_factory=list)
    is_import_stub: bool = False
    source: str = "entry"  # entry | symbol | call-target | prologue | stub

    @property
    def size(self) -> int:
        return max(0, self.end - self.addr)


@dataclass
class StringRef:
    addr: int
    value: str
    encoding: str  # ascii | utf16le | utf16be
    length: int
    xrefs: list[int] = field(default_factory=list)


@dataclass
class BinaryImage:
    path: str
    format: str  # mach-o | mach-o-fat | elf | pe | raw
    arch: str  # arm64 | x86_64 | x86 | arm
    bits: int
    endian: str  # little | big
    entry: int
    image_base: int
    data: bytes
    segments: list[Segment] = field(default_factory=list)
    sections: list[Section] = field(default_factory=list)
    symbols: list[Symbol] = field(default_factory=list)
    imports: list[Symbol] = field(default_factory=list)
    exports: list[Symbol] = field(default_factory=list)
    arch_slices: list[dict] = field(default_factory=list)  # fat containers
    slice_offset: int = 0  # file offset of the selected thin image
    function_starts_blob: tuple[int, int] | None = None  # LC_FUNCTION_STARTS (off, size)
    dyld_info: dict | None = None        # LC_DYLD_INFO_ONLY offsets/sizes
    chained_fixups: tuple[int, int] | None = None  # LC_DYLD_CHAINED_FIXUPS (off, size)
    exports_trie: tuple[int, int] | None = None    # LC_DYLD_EXPORTS_TRIE (off, size)

    def addr_to_offset(self, addr: int) -> int | None:
        for seg in self.segments:
            if seg.addr <= addr < seg.end and seg.size:
                off = seg.offset + (addr - seg.addr)
                if 0 <= off < len(self.data):
                    return off
        for sec in self.sections:
            if sec.addr <= addr < sec.end:
                off = sec.offset + (addr - sec.addr)
                if 0 <= off < len(self.data):
                    return off
        return None

    def offset_to_addr(self, off: int) -> int | None:
        for seg in self.segments:
            if seg.offset <= off < seg.offset + seg.size:
                return seg.addr + (off - seg.offset)
        return None

    def bytes_at(self, addr: int, size: int) -> bytes:
        off = self.addr_to_offset(addr)
        if off is None:
            return b""
        return self.data[off:off + size]

    def section_at(self, addr: int) -> Section | None:
        # Bisect on section starts (cached); linear scan only as fallback
        # for overlapping layouts.  This is the hottest lookup in analysis.
        starts = self.__dict__.get("_sec_starts")
        if starts is None or len(starts) != len(self.sections):
            ordered = sorted(self.sections, key=lambda s: s.addr)
            starts = [s.addr for s in ordered]
            self.__dict__["_sec_starts"] = starts
            self.__dict__["_sec_ordered"] = ordered
        import bisect as _b
        i = _b.bisect_right(starts, addr) - 1
        if i >= 0:
            sec = self.__dict__["_sec_ordered"][i]
            if sec.addr <= addr < sec.end:
                return sec
        for sec in self.sections:
            if sec.addr <= addr < sec.end:
                return sec
        return None

    def symbol_at(self, addr: int) -> Symbol | None:
        for sym in self.symbols:
            if sym.addr == addr:
                return sym
        return None
