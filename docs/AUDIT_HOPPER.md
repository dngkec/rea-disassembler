# Audit of the installed disassembler (Hopper, via REA)

Installed target: `~/Applications/Hopper Disassembler.app` (70 MB), provider
confirmed healthy by `rea doctor` (REA 6.7.0, Hopper launcher SHA-256
`f75b6862…fbf42`). Every line of its public scripting surface was read:
`Contents/Resources/hopper_api.py` (1,168 lines), `script_disassemble.py`
(31 lines), `script_beginning.py` (17 lines), plus `Info.plist`, the bundle
layout, and REA Evidence for `/bin/ls`, `/bin/cat`, the corpus, and Hopper's
own launcher binary. Line numbers below are `hopper_api.py`.

## What Hopper's model is (and what we kept)

| Hopper concept | Lines | Verdict |
|---|---|---|
| Segment → Section → typed bytes (`TYPE_CODE`, `TYPE_NEXT`, …) | 418–471, 4–8 | Right shape. Kept as `Segment`/`Section` dataclasses. |
| `Procedure` = collection of `BasicBlock`s, entry point, tags | 93–273 | Kept as `Function`/`BasicBlock`. |
| `Instruction`: arch, string, raw/formatted args, cjmp/ijmp flags, length | 326–395 | Kept, but classification comes from Capstone instruction *groups*, not flags set by a GUI document. |
| `CallReference` (direct/objc/unknown), callers/callees | 46–66, 229–240 | Kept as call-graph edges on `Function`. |
| Xrefs: `getReferencesOf/FromAddress`, add/remove | 644–655 | Kept; ours are computed for the whole image in one pass, including string xrefs Hopper's REA surface does not return. |
| Labels, renames, comments, tags, colours, bookmarks | 617–643, 925–999, 1000–1144 | Interactive annotation. Out of scope for a headless engine; JSON output is the annotation surface instead. |
| `decompile()` → pseudo-code string | 259–261 | Kept in spirit: our lift is CFG-shaped and never invents variables (see `pseudocode.py`). |
| `Document`: segments, entry, cursor, selection, GUI dialogs | 720–1144 | GUI-bound. Dropped deliberately — headless is the feature. |
| `assemble()`, `produceNewExecutable()` | 805–808, 1119–1123 | Write-back/patching. Not in v1; recorded as a known gap, not hidden. |
| `GlobalInformation` version triple | 1147–1164 | Equivalent: `readis --version`. |
| CPU support in the API enum: i386, x86_64, ARM, Thumb, AArch64, plugin | 330–336 | Matched (arm64/x86_64/x86/arm) plus formats Hopper-via-REA does not take: ELF, PE, raw. |
| Scripting via embedded Python (`HopperLowLevel`) | throughout | Replaced by a real installable Python package + CLI; no app process needed. |

## Weaknesses found (each maps to a design decision in ARCHITECTURE.md)

1. **GUI/document-bound.** Analysis exists only inside a Hopper document;
   REA must launch Hopper, load a `.hop`, and close it per file. Measured:
   5.3 s for REA+Hopper on a 34 KB corpus binary vs 0.10 s for `readis`.
2. **Mach-O-centric through REA.** The REA `inspect` route takes Mach-O/app
   paths and a fixed arch list; ELF/PE/raw need other providers or nothing.
3. **String splitting.** REA's own limitations state Hopper "may split long
   literals into adjacent unterminated fragments" and that string search
   matches fragments independently. We extract whole C strings and attach
   xrefs, so `readis strings --xrefs` answers what Hopper's list cannot.
4. **Closed results.** Counts and listings live in the GUI or a proprietary
   database. Ours are stable JSON (`info --json`) that diffs, greps, and
   version-controls.
5. **No shipped ground-truth scoring.** Nothing in the bundle scores Hopper
   against LLVM/objdump boundaries. Our `bench` command does exactly that,
   and `tests/` locks the corpus answers in.

## REA baseline (Evidence IDs from this machine)

- `/bin/ls`: Hopper 133 procedures, 111 strings, 5 segments
  (`ev_dc9cc163…`, arm64 slice).
- Hopper launcher (`hopper`): Hopper 248 procedures, 302 strings
  (`ev_f6c8db40…`).
- corpus (ours, ground truth known): Hopper 10 procedures / 3 strings on
  both arm64 and x86_64 — our exact match is in BENCHMARK.md.
