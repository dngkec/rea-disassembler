# Architecture

```
            ┌──────────── formats/ ────────────┐
 file ────► │ macho.py  fat/thin, symtab,      │──► BinaryImage
            │ elf.py    32/64, ET_REL, symtab  │    (segments, sections,
            │ pe.py     PE32+, imports         │     symbols, imports, entry)
            │ raw       caller-declared only   │
            └──────────────┬───────────────────┘
                           ▼
            engine.py  Capstone (LLVM lineage, same as Hopper's
                     libLLVMServices) with operand detail; control
                     flow classified from instruction groups
                           ▼
            analysis.py  recursive descent from entry + symbols +
                     __unwind_info + prologues + call targets, then
                     validated linear sweep; CFG, call graph, xrefs,
                     adrp+add / RIP-relative string-xref resolution
                           ▼
            pseudocode.py  CFG-shaped C-like lift (no invented vars)
            demangle.py    c++filt / swift demangle when present
            output.py      stable JSON + human listing
            cli.py         readis info|disasm|functions|strings|pseudo|cfg|bench
```

## Principles

1. **A wrong guess is worse than an error.** Unknown formats and unsupported
   architectures raise; headerless bytes are only disassembled when the
   caller declares `--raw --arch`.
2. **Boundaries come from decoders, truth from corpora.** Instruction
   boundaries are Capstone's; correctness is scored against LLVM objdump
   and against binaries whose functions/strings are known by construction.
3. **Coverage is measured, never assumed.** `info` reports reachable-code
   coverage; sweep-only code is still listed, and the number says how much
   recursive descent actually reached.
4. **Every heuristic is labelled.** A function's `source` is one of
   entry/symbol/unwind/call-target/prologue/stub, so a reader can discount
   prologue guesses without discarding symbol facts.
5. **No live document.** Results are plain dataclasses → JSON. Nothing
   needs a GUI, a licence, or a `.hop` file.

## Function discovery (layered, in order)

entry point → function symbols → exported symbols → Objective-C method
IMPs (relative + absolute method lists via `__objc_methlist` /
`__objc_classlist` / `__objc_catlist`, selector-named) and `__objc_stubs`
entries → `LC_FUNCTION_STARTS` (the linker's own ULEB128 list) →
`__unwind_info` compact-unwind starts (REGULAR + COMPRESSED pages) →
`__stubs` (12-byte) / `__auth_stubs` (16-byte) entries named through the
Mach-O indirect symbol table → every direct call target in the sweep →
data references (function pointers materialised by adrp+add / lea, or
stored in data sections, guarded to terminator-following targets and
excluding jump-table bases) → prologue patterns (`pacibsp` anywhere;
frame setup only after a control transfer).

When `LC_FUNCTION_STARTS` exists it is authoritative: heuristic seeds
falling inside a listed function are demoted to blocks.  Trap bytes
(`udf`/`brk`/`int3`) are never function entries.  The decoder sweep
resynchronises past data-in-code islands instead of stopping at the
first one.

ELF uses symtab/dynsym function symbols (with ET_REL section relocation);
PE uses entry + COFF symbols + import thunks.
