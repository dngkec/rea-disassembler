"""Regression tests.  The corpus tests are the negative tests for the bug
classes found during development: Mach-O segment/section struct layouts,
unwind compressed-page header size, ET_REL symbol relocation, stub naming
through the indirect symbol table, and string-xref resolution."""
import struct
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from rea_disassembler.analysis import analyse, _unwind_starts  # noqa: E402
from rea_disassembler.formats import load_binary  # noqa: E402
from rea_disassembler.pseudocode import lift_function  # noqa: E402

BENCH = Path(__file__).parent.parent / "bench"
EXPECTED_FUNCS = {"_add", "_mul", "_fib", "_classify", "_banner",
                  "_secret", "_sum_array", "_average", "_main"}


@pytest.mark.parametrize("name,arch", [("corpus_arm64", "arm64"),
                                       ("corpus_x86_64", "x86_64")])
def test_macho_corpus_functions_complete(name, arch):
    img = load_binary(str(BENCH / name))
    assert img.arch == arch and img.format == "mach-o"
    res = analyse(img)
    found = {f.name for f in res["functions"]}
    assert EXPECTED_FUNCS <= found, f"missing {EXPECTED_FUNCS - found}"


def test_macho_corpus_string_xrefs():
    img = load_binary(str(BENCH / "corpus_arm64"))
    res = analyse(img)
    by_val = {s.value: s for s in res["strings"]}
    assert "string-xref-target-12345" in by_val
    assert by_val["string-xref-target-12345"].xrefs, "secret string has no xref"
    assert "rea-disassembler-corpus-v1" in by_val


def test_unwind_starts_match_objdump_corpus():
    img = load_binary(str(BENCH / "corpus_arm64"))
    starts = {hex(a) for a in _unwind_starts(img)}
    # objdump --macho --unwind-info on this binary lists exactly these four
    assert starts == {"0x1000004b0", "0x1000004c0", "0x100000500", "0x1000005a4"}


def test_fib_is_recursive_and_sized():
    img = load_binary(str(BENCH / "corpus_arm64"))
    res = analyse(img)
    fib = next(f for f in res["functions"] if f.name == "_fib")
    assert fib.addr in fib.callees, "fib must call itself"
    assert fib.size == 64


def test_universal_binary_slices():
    img = load_binary(str(BENCH / "corpus_universal"))
    assert img.format == "mach-o-fat" and len(img.arch_slices) == 2
    img_x = load_binary(str(BENCH / "corpus_universal"), arch="x86_64")
    assert img_x.arch == "x86_64"


@pytest.mark.parametrize("name", ["corpus_elf_x86_64.o", "corpus_elf_arm64.o"])
def test_elf_relocatable(name):
    img = load_binary(str(BENCH / name))
    assert img.format == "elf"
    res = analyse(img)
    names = {f.name for f in res["functions"]}
    assert {"add", "fib", "classify", "banner", "secret"} <= names
    vals = {s.value for s in res["strings"]}
    assert "string-xref-target-12345" in vals


def test_pe_synthetic_minimal(tmp_path):
    # Minimal PE32+ built byte-by-byte: one .text section, entry at start.
    code = bytes.fromhex("4883ec28" "b82a000000" "4883c428" "c3")  # sub/mov eax,42/add/ret
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 64)
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 240, 0)
    opt = bytearray(240)
    struct.pack_into("<H", opt, 0, 0x20B)
    struct.pack_into("<I", opt, 16, 0x1000)          # entry RVA
    struct.pack_into("<Q", opt, 24, 0x140000000)     # image base
    sec = bytearray(40)
    sec[0:5] = b".text"
    struct.pack_into("<IIII", sec, 8, len(code), 0x1000, len(code), 64 + 4 + 20 + 240 + 40)
    struct.pack_into("<I", sec, 36, 0x60000020)
    blob = bytes(dos) + b"PE\x00\x00" + coff + bytes(opt) + bytes(sec) + code
    p = tmp_path / "mini.exe"
    p.write_bytes(blob)
    img = load_binary(str(p))
    assert img.format == "pe" and img.arch == "x86_64"
    res = analyse(img)
    texts = [i.text for i in res["instructions"]]
    assert any("0x2a" in t for t in texts) and any(t.startswith("ret") for t in texts)


def test_raw_arm64():
    p = BENCH / "corpus_arm64"
    img = load_binary(str(p), raw_arch="arm64")
    assert img.format in ("mach-o", "raw")  # header wins over raw request


def test_pseudocode_and_cfg_shapes():
    img = load_binary(str(BENCH / "corpus_arm64"))
    res = analyse(img)
    main = next(f for f in res["functions"] if f.name == "_main")
    code = lift_function(img, main)
    assert "_fib();" in code and "return;" in code
    assert main.blocks and all(b.start < b.end for b in main.blocks)


def test_malformed_inputs_raise_not_crash(tmp_path):
    p = tmp_path / "junk.bin"
    p.write_bytes(b"\xde\xad\xbe\xef" * 64)
    with pytest.raises(ValueError):
        load_binary(str(p))
    p.write_bytes(b"\x7fELF" + b"\x00" * 8)
    with pytest.raises((ValueError, struct.error)):
        load_binary(str(p))


def test_system_ls_regression():
    if not Path("/bin/ls").exists():
        pytest.skip("macOS only")
    img = load_binary("/bin/ls")
    res = analyse(img)
    # Hopper via REA reports 133 procedures / 111 strings; we match the
    # procedure set exactly and are a superset on strings.
    assert len(res["functions"]) == 133
    assert len(res["strings"]) >= 111
    names = {f.name for f in res["functions"]}
    assert "_strlen" in names and "_write" in names  # named stubs, not stub_0x…


def test_ls_data_ref_leaf_functions():
    """Regression: qsort-style comparators at __text start are reachable
    only as function pointers (adrp+add).  Pure call-graph discovery
    missed all eleven; data-reference discovery must find every one."""
    if not Path("/bin/ls").exists():
        pytest.skip("macOS only")
    img = load_binary("/bin/ls")
    res = analyse(img)
    addrs = {f.addr for f in res["functions"]}
    for a in (0x10000070C, 0x10000071C, 0x100000780, 0x100000790, 0x1000007F4,
              0x100000804, 0x100000868, 0x100000878, 0x1000008DC, 0x1000008EC,
              0x100000924):
        assert a in addrs, f"comparator {a:#x} not discovered"
    # Short __cstring table entries a >=4-char regex cannot see
    vals = {s.value for s in res["strings"]}
    assert {"AF", "AB", "yes", "tty", "%s"} <= vals


def test_lc_function_starts_corpus():
    from rea_disassembler.analysis import _lc_function_starts
    img = load_binary(str(BENCH / "corpus_arm64"))
    lc = {hex(a) for a in _lc_function_starts(img)}
    assert lc == {"0x1000004b0", "0x1000004b8", "0x1000004c0", "0x100000500",
                  "0x100000514", "0x100000520", "0x10000052c", "0x100000560",
                  "0x1000005a4"}


def test_installed_hopper_launcher():
    """The installed app's own launcher: Hopper reports 248 procedures,
    of which 150 start at `brk #1` padding inside __objc_stubs.  We must
    find every real one (98) and none of the padding."""
    p = Path("/Users/dineshgoswami/Applications/Hopper Disassembler.app"
             "/Contents/MacOS/hopper")
    if not p.exists():
        pytest.skip("Hopper not installed")
    img = load_binary(str(p))
    res = analyse(img)
    addrs = {f.addr for f in res["functions"]}
    assert len(addrs) == 98
    for a in (0x100000D88, 0x100000DE4, 0x1000029BC):  # previously missed
        assert a in addrs
    firsts = {f.addr: f.blocks[0].instructions[0].mnemonic
              for f in res["functions"] if f.blocks and f.blocks[0].instructions}
    assert not any(m in ("brk", "udf") for m in firsts.values())
    objc = {f.name for f in res["functions"] if f.source == "objc-method"}
    assert any("resultsForSearchString:" in n for n in objc)
    assert len(res["strings"]) == 302  # exactly Hopper's string count


def test_call_is_not_a_cfg_branch():
    # Regression: Capstone puts AArch64 `bl` in both CALL and JUMP groups.
    img = load_binary(str(BENCH / "corpus_arm64"))
    res = analyse(img)
    fib = next(f for f in res["functions"] if f.name == "_fib")
    bl = [i for b in fib.blocks for i in b.instructions if i.mnemonic == "bl"]
    assert bl and all(i.is_call and not i.is_branch for i in bl)
    succ = {s for b in fib.blocks for s in b.successors}
    assert fib.addr not in succ  # the call must not become a block edge


def test_big_binary_resync_coverage():
    """Regression: Capstone stops at the first data-in-code byte.  Without
    resync, Hopper's own 27 MB binary lost ~200k instructions (86% recall
    vs objdump); with resync it must stay above 99% by count."""
    p = Path("/Users/dineshgoswami/Applications/Hopper Disassembler.app"
             "/Contents/MacOS/Hopper Disassembler")
    if not p.exists():
        pytest.skip("Hopper not installed")
    img = load_binary(str(p))
    res = analyse(img)
    assert len(res["instructions"]) >= 1_400_000
    assert len(res["functions"]) >= 26_000


def test_binds_external_objc_class_name():
    """Categories on external classes: the class name exists only as a
    dyld bind.  Hopper names these -[NSMetadataQuery …]; so must we."""
    p = Path("/Users/dineshgoswami/Applications/Hopper Disassembler.app"
             "/Contents/MacOS/hopper")
    if not p.exists():
        pytest.skip("Hopper not installed")
    from rea_disassembler.objc import discover_objc_methods
    img = load_binary(str(p))
    names = set(discover_objc_methods(img).values())
    assert names == {"-[NSMetadataQuery resultsForSearchString:]",
                     "-[NSMetadataQuery resultsForSearchString:inFolders:]",
                     "-[NSMetadataQuery doneSearching:]"}


def test_assembler_exact_encodings():
    from rea_disassembler.assembler import assemble
    assert assemble("arm64", "mov w0, #42", 0x1000004B0).hex() == "40058052"
    assert assemble("x86_64", "mov eax, 42", 0x1000004C0).hex() == "b82a000000"


def test_assembler_branch_targets_land():
    from rea_disassembler import engine
    from rea_disassembler.assembler import assemble
    from rea_disassembler.models import BinaryImage, Section, Segment
    for arch, asm, addr, want in (
            ("arm64", "b 0x100000500", 0x1000004C0, 0x100000500),
            ("arm64", "adrp x0, 0x100000000", 0x100000514, 0x100000000),
            ("x86_64", "jmp 0x100000500", 0x1000004C0, 0x100000500),
            ("x86_64", "call 0x100000600", 0x1000004C0, 0x100000600)):
        code = assemble(arch, asm, addr)
        img = BinaryImage(path="", format="raw", arch=arch, bits=64,
                          endian="little", entry=addr, image_base=addr, data=code)
        img.segments.append(Segment("__t", addr, len(code), 0))
        img.sections.append(Section("__t", "__t", addr, len(code), 0, is_code=True))
        ins = engine.decode_at(img, engine.make_decoder(arch), addr)
        got = ins.branch_target or ins.call_target or (ins.refs[0] if ins.refs else None)
        assert got == want, f"{asm}: decoded target {got:#x} != {want:#x}"


def test_patch_changes_program_behavior(tmp_path):
    """Write-back proof: patch `answer()` to return 42, re-sign, run it."""
    import shutil
    if not shutil.which("clang"):
        pytest.skip("clang required")
    src = tmp_path / "p.c"
    src.write_text('#include <stdio.h>\n'
                   '__attribute__((noinline)) int answer(void) { return 1; }\n'
                   'int main(void) { printf("answer=%d\\n", answer()); return 0; }\n')
    exe = tmp_path / "p"
    subprocess.run(["clang", "-O0", "-o", str(exe), str(src)], check=True)
    assert subprocess.run([str(exe)], capture_output=True, text=True).stdout == "answer=1\n"
    img = load_binary(str(exe))
    fn = next(f for f in analyse(img)["functions"] if f.name == "_answer")
    out = tmp_path / "p_patched"
    from rea_disassembler.assembler import patch_binary
    receipt = patch_binary(img, fn.addr, "mov w0, #42; ret", str(out))
    assert receipt["verified_instruction"].startswith("mov")
    assert receipt["resigned"] is True
    got = subprocess.run([str(out)], capture_output=True, text=True)
    assert got.stdout == "answer=42\n", got


def test_decompiler_structured_fib():
    from rea_disassembler.decompile import decompile_function
    img = load_binary(str(BENCH / "corpus_arm64"))
    res = analyse(img)
    fib = next(f for f in res["functions"] if f.name == "_fib")
    code = decompile_function(img, fib)
    assert "_fib(" in code and "if (" in code and "return" in code
    assert "block_" in code  # CFG labels retained, expressions propagated


def test_debugger_lldb_breaks():
    import shutil
    if not shutil.which("lldb"):
        pytest.skip("lldb required")
    from rea_disassembler.debugger import debug_run
    r = debug_run(str(BENCH / "corpus_arm64"), ["main"], timeout=90)
    assert r["stop_reason"] and "breakpoint" in r["stop_reason"]
    assert r["frames"] and "main" in r["frames"][0]


def test_gui_native_app_present():
    gui = Path(__file__).parent.parent / "gui"
    assert (gui / "ReaDisassemblerApp.swift").exists()
    assert (gui / "build_app.sh").exists()
    app = gui / "ReaDisassembler.app" / "Contents" / "MacOS" / "ReaDisassembler"
    if not app.exists():
        pytest.skip("GUI not built yet (run gui/build_app.sh)")
    assert app.stat().st_size > 50_000


def test_tp_const_is_data_not_code():
    """__TP_CONST carries the pure-instructions flag bit but is typed
    pointer data: decoding it invented a bogus empty ObjC function."""
    p = Path("/Users/dineshgoswami/Applications/Hopper Disassembler.app"
             "/Contents/MacOS/Hopper Disassembler")
    if not p.exists():
        pytest.skip("Hopper not installed")
    img = load_binary(str(p))
    tp = [s for s in img.sections if "__tp_const" in s.name]
    assert tp and not tp[0].is_code
    res = analyse(img)
    assert not any(f.size <= 0 or not f.blocks for f in res["functions"])


def test_exports_trie_matches_nm():
    p = Path("/Users/dineshgoswami/Applications/Hopper Disassembler.app"
             "/Contents/Frameworks/libLLVMServices.dylib")
    if not p.exists():
        pytest.skip("Hopper not installed")
    img = load_binary(str(p))
    assert len(img.exports) == 2922  # `nm -gU` on the same file
    assert img.exports[0].name == "_LLVMConsumeError"


def test_zero_padding_is_not_an_instruction():
    """All-zero words in code are alignment padding.  Capstone decodes
    0x00000000 as `udf #0`; counting it invented 8 fake instructions on
    Hopper's own binary."""
    from rea_disassembler import engine
    from rea_disassembler.models import BinaryImage, Section, Segment
    code = bytes.fromhex("c0035fd6") + b"\x00" * 8 + bytes.fromhex("c0035fd6")
    img = BinaryImage(path="", format="raw", arch="arm64", bits=64,
                      endian="little", entry=0x1000, image_base=0x1000, data=code)
    img.segments.append(Segment("__t", 0x1000, len(code), 0))
    img.sections.append(Section("__t", "__t", 0x1000, len(code), 0, is_code=True))
    out = engine.decode_linear(img, engine.make_decoder("arm64"), 0x1000, code)
    assert [i.mnemonic for i in out] == ["ret", "ret"]


def test_unwind_not_demoted_by_lc():
    """LC_FUNCTION_STARTS and __unwind_info are independent authoritative
    lists: an unwind start inside an LC range must still be a function."""
    if not Path("/bin/ls").exists():
        pytest.skip("macOS only")
    img = load_binary("/bin/ls")
    res = analyse(img)
    from rea_disassembler.analysis import _unwind_starts
    ours = {f.addr for f in res["functions"]}
    dec = res["decoded"]
    for a in _unwind_starts(img):
        if a in dec and dec[a].mnemonic not in ("udf", "brk"):
            assert a in ours


def test_cli_json(tmp_path):
    out = subprocess.run(
        [sys.executable, "-m", "rea_disassembler", "info",
         str(BENCH / "corpus_arm64"), "--json"],
        capture_output=True, text=True,
        env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(Path(__file__).parent.parent / "src")})
    assert out.returncode == 0, out.stderr
    assert '"format": "mach-o"' in out.stdout
