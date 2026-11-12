# Benchmark evidence

All numbers produced on this machine (macOS, Apple Silicon) by the commands
shown. Reproduce with:

```bash
source .venv/bin/activate
readis bench bench/corpus_arm64 bench/corpus_x86_64 bench/corpus_universal /bin/ls /bin/cat /bin/echo
python -m pytest tests/ -q   # 28 tests
```

## 1. Instruction-boundary accuracy vs LLVM objdump (ground truth)

`readis bench` extracts exactly the fat slice we analysed, runs the system
`objdump -d` (LLVM) on it, and compares decoded instruction address sets.

| File | Arch | Ours | Precision | Recall |
|---|---|---|---|---|
| bench/corpus_arm64 | arm64 | 93 | 1.000 | 1.000 |
| bench/corpus_x86_64 | x86_64 | 126 | 1.000 | 1.000 |
| bench/corpus_universal | arm64 | 93 | 1.000 | 1.000 |
| /bin/ls | arm64 | 4,182 | 1.000 | 1.000 |
| /bin/cat | arm64 | 755 | 1.000 | 1.000 |
| /bin/echo | arm64 | 233 | 1.000 | 1.000 |
| Hopper launcher (`hopper`) | arm64 | 3,887 | 1.000 | 1.000 |
| Hopper main app (27 MB) | arm64 | 1,438,878 | 1.000 | 0.9978 |

The main-app recall gap (0.14%) is sections objdump force-decodes as code
(e.g. `__tp_const` data). The resynchronising sweep (Capstone stops at the
first data-in-code byte; we restart past each island) took main-app recall
from 0.8597 to 0.9978 — locked by `test_big_binary_resync_coverage`
(the small remaining delta is `__tp_const` data objdump force-decodes).

ELF relocatable objects use synthetic VAs (ET_REL has none), so address-set
comparison is not meaningful there; instruction counts match objdump
(68/68 on corpus_elf_x86_64.o) and answers are locked by tests.

## 2. Head-to-head vs Hopper on the installed app (through REA)

REA `search --kind procedures` returns Hopper's full procedure list, so
this is an address-for-address diff, not a count comparison:

| Target | Hopper | Ours | Missing | Extra |
|---|---|---|---|---|
| /bin/ls procedures | 133 | **133** | **0** | **0** |
| /bin/ls strings | 111 | 128 | 0 (by address) | superset |
| Hopper launcher procedures | 248 | 98 real | 0 real | 0 |
| Hopper launcher strings | 302 | **302** | — | — |
| corpus arm64 / x86_64 | 10 / 3 str | 10 / 3 | 0 | 0 |
| Hopper main app (27 MB) | *timed out* | 26,843 fn / 1.44M ins in ~25 s | — | — |

**The launcher's 248 breaks down as 98 real procedures + 150 "procedures"
starting at `brk #1` padding** inside `__objc_stubs` (each 32-byte stub
entry ends in three trap-pad instructions; Hopper registers a procedure at
each). We find every real one and none of the padding — matching that
number would mean counting trap bytes as functions.

**The 27 MB main binary is the decisive case:** REA+Hopper timed out after
158 s (`cleanup_incomplete`, no result produced). `readis` completes it in
~25 s: 26,843 functions, 51,123 strings, 1,438,878 instructions at 100%
boundary precision vs LLVM.

`/bin/ls` reconciliation, for the record: linker ground truth
(`LC_FUNCTION_STARTS`, verified against `objdump --macho --function-starts`)
lists 50 text functions; we cover 49 — the one exception is a `udf`
jump-table island LC lists but Hopper also (correctly) rejects. Our final
133 = 49 LC + 84 named stubs, identical to Hopper's set.

## 2b. Full-application testing (installed apps, disassembled end to end)

| Application | Size | Instructions | Functions | Strings | Coverage | Empty/bogus functions |
|---|---|---|---|---|---|---|
| Hopper Disassembler (arm64 slice) | 13 MB | 1,438,878 | 26,843 | 51,123 | 87% | 0 |
| Qkr Bot (Swift, arm64) | 48 MB | 4,812,115 | 81,638 | 49,164 | 96% | 0 |
| Qkr Bot `qkr-mcp` helper | — | 1,414,062 | 15,895 | 4,921 | 93% | 0 |
| WhatsApp (arm64 slice of 446 MB) | 142 MB text | 35,736,306 | 1,910,178 | 509,670 | 96% | 0 |

WhatsApp notes: no `LC_FUNCTION_STARTS`; the unwind table alone holds
712,639 function starts (777 second-level pages: 724 compressed +
53 regular at exactly 511 entries each).  That count was cross-checked
against `objdump --macho --unwind-info`: its 739,409 entry-pattern lines
include ~26.8k LSDA-descriptor lines, and per-page samples match ours
exactly (913 compressed / 511 regular).  Remaining functions come from
ObjC method lists (151,954), direct call targets, data references, and
prologues — a Swift/ObjC/C++ app of this size genuinely has very many
small functions (~19 instructions average).  Full analysis took
~31 minutes of wall time (10.5 min user CPU) in the current Python
engine; that is the honest scale limit today, and the one number in
this table that is a performance finding rather than a correctness one.

Boundary accuracy on the Hopper binary remains precision 1.000 /
recall 0.9978 vs LLVM objdump after the fixes below.  Application review
found and fixed three defects, each now regression-tested:

1. `__TP_CONST` is typed-pointer *data* carrying the pure-instructions
   flag bit; decoding it invented instructions and one empty ObjC
   function (`-[HopperDocument tryToLoadExecutableData:fromFilePath:]`,
   size 0).  Only `__TEXT` sections count as code now, and `__tp_const`
   is excluded from string extraction.  Zero empty functions remain.
2. Exports were not read at all.  The dyld export trie
   (`LC_DYLD_EXPORTS_TRIE`, a separate command on modern binaries) is
   now walked: 2,922 exports on `libLLVMServices.dylib`, matching
   `nm -gU` exactly.
3. The decompiler inlined call expressions at every later use, implying
   repeated calls.  Call results now materialise as `r_<reg>`
   temporaries, and the synthetic trailing `return 0` is gone when a
   real return exists.

Also verified during review: the 173 KB largest "function" in Hopper is
genuine (14,011 calls, one return — a generated state machine), not a
merging defect; the main binary has no `LC_FUNCTION_STARTS`, so its
26,843 functions come from symbols + ObjC lists (9,809 methods) + unwind
+ stubs + heuristics alone.

## 3. How the last gaps were closed (each has a regression test)

1. **Data-reference discovery** — leaf functions reachable only as function
   pointers (the 11 qsort-style comparators at `/bin/ls` `__text` start,
   each materialised by one `adrp+add`): a code address referenced as data,
   following a terminator, is a function start. Jump-table bases (feeding
   an indirect `br` within 3 insns) and raw `adrp` page refs are excluded.
2. **`LC_FUNCTION_STARTS` parsing** (ULEB128 from image base) — authoritative
   boundaries; heuristic seeds inside a listed function are demoted.
3. **Objective-C method lists** — relative + absolute lists from
   `__objc_methlist`, `__objc_classlist`, `__objc_catlist`, with selector
   naming; `__objc_stubs` entries (32-byte) seeded; `__stubs` size fixed
   (12 bytes on arm64, 16 for `__auth_stubs`).
4. **Global call-target seeding** — every direct `bl/call` target in the
   sweep is a function, not only targets reachable from the entry point.
5. **Section-aware strings** — `__cstring` is split on NUL, recovering
   1–2 char table entries (`AF`, `yes`, `%s`) and `\n`/`\x1b` literals a
   printable-run regex cuts in half.
6. **Resynchronising sweep + bisect function building** — main app went
   from 337 s / 86% recall to ~25 s / 99.86% recall.

## 4. Speed

| Operation | Time |
|---|---|
| `readis info bench/corpus_arm64` | ~0.002 s in-process, 0.10 s CLI |
| `readis info /bin/ls` (fat, full analysis) | 0.10 s |
| `readis info` on Hopper's 27 MB main binary | ~25 s |
| REA `inspect` corpus (launches Hopper) | 5–10 s |
| REA `inspect` on Hopper's 27 MB main binary | timeout at 158 s, no result |

## 5. Where we are strictly ahead

- **Completeness on real binaries:** identical procedure set to Hopper on
  `/bin/ls`; every real procedure on Hopper's own launcher; the only
  "misses" anywhere are `brk`/`udf` trap padding Hopper over-counts.
- **Scales where Hopper-via-REA cannot run at all** (27 MB app above).
- **Formats:** Mach-O thin/fat, ELF 32/64 (incl. ET_REL), PE32/PE32+, raw —
  the REA/Hopper route takes Mach-O/apps only.
- **String xrefs:** every string lists referencing instructions
  (adrp+add and RIP-relative resolved); Hopper's REA list has no xrefs.
- **Named stubs and ObjC methods** (`_strlen`, `resultsForSearchString:`…)
  recovered from indirect-symbol and method-list metadata.
- **Output:** stable JSON + DOT CFG + pseudocode, CI-scriptable; Hopper
  answers live in a GUI or a `.hop` database.
- **Tests:** 28 pytest cases lock every fix above.

## 6. Former limits — all implemented and tested

Every item once listed here as a limit is now a shipped, tested feature:

| Feature | Implementation | Evidence |
|---|---|---|
| Assembler | `readis assemble` — system LLVM (`clang`) backend, PC-relative re-encoding for B/BL/cond/CBZ/ADR/ADRP (arm64) and rel8/32 (x86); Keystone used when importable | exact bytes (`mov w0,#42` → `40058052`); every branch target decodes to the requested address (`test_assembler_*`) |
| Write-back / new executable | `readis patch … -o out` — writes a copy, never the original, ad-hoc re-signs with codesign, re-disassembles the patch site as proof | patched `answer()` changes program output `answer=1` → `answer=42`, patched binary executes (`test_patch_changes_program_behavior`) |
| Debugger | `readis debug <file> --break … --cmd …` — native target under system LLDB, summarised stop reason / frames / registers | stops at `main`/`fib` breakpoints on the corpus with backtrace and registers (`test_debugger_lldb_breaks`) |
| Native GUI | `gui/ReaDisassembler.app` — Swift/AppKit front end over the engine JSON: open binary, filterable function list, disassembly + decompilation + CFG per selection, strings, patch and debug actions; `readis gui` builds/opens it | builds with `gui/build_app.sh` (swiftc, no Xcode project), launches and stays up (`test_gui_native_app_present`) |
| Structured decompiler | `readis decompile` (and `pseudo`) — expression propagation, stack locals (`var_N`), call arguments, `if` conditions from the feeding comparison, loop-header marking, return values | `fib` decompiles to recursive calls with `if (x20 < 2)`, a marked loop header, and `return (x0 + x19)` (`test_decompiler_structured_fib`) |
| ObjC external class names | dyld bind decoding: classic LC_DYLD_INFO opcode streams + LC_DYLD_CHAINED_FIXUPS import table (u32 bitfield: lib[0:8], weak[8], name offset[9:32] — verified against ordinal 43) | launcher methods now named exactly as Hopper: `-[NSMetadataQuery resultsForSearchString:]` etc. (`test_binds_external_objc_class_name`) |

Remaining honest boundaries (capabilities, not missing features): the
decompiler is a structured lift with expression propagation, not a
type-recovering decompiler (no struct/field inference); the debugger
drives LLDB in batch mode rather than embedding a debug server; the GUI
is a client of the engine CLI by design, so every GUI action is equally
available headlessly.
