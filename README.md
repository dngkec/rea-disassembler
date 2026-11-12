# rea-disassembler (`readis`)

A headless, evidence-first disassembler built after a line-by-line audit of
the installed Hopper Disassembler (see [docs/AUDIT_HOPPER.md](docs/AUDIT_HOPPER.md)).

Mach-O (thin + universal), ELF (32/64, executables and relocatable objects),
PE (32/64), and caller-declared raw images; ARM64, x86-64, x86, ARM.
Recursive-descent + validated sweep disassembly, CFG and call graph,
`__unwind_info` function discovery, named import stubs, string extraction
with cross-references, CFG-shaped pseudocode, and stable JSON output.
Benchmark evidence against Hopper and LLVM objdump: [docs/BENCHMARK.md](docs/BENCHMARK.md).
Design: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Install and run

```bash
uv venv --python 3.11 .venv
uv pip install --python .venv/bin/python -e .
source .venv/bin/activate

readis info /bin/ls
readis disasm bench/corpus_arm64 --function 0x1000005a4
readis functions /bin/ls
readis strings --xrefs bench/corpus_arm64
readis decompile bench/corpus_arm64 _fib   # structured decompiler
readis cfg bench/corpus_arm64 _fib        # DOT graph
readis assemble bench/corpus_arm64 0x1000004b0 "mov w0, #42"
readis patch bench/corpus_arm64 0x1000004b0 "mov w0, #42; ret" -o /tmp/patched
readis debug bench/corpus_arm64 --break _fib
readis bench bench/corpus_arm64 /bin/ls   # vs LLVM objdump
readis info /bin/ls --json
readis gui                                # native macOS app (builds + opens)
```

Native GUI without the CLI: `./gui/build_app.sh && open gui/ReaDisassembler.app`
(Swift/AppKit; open a binary, browse functions, disassembly/decompilation/CFG,
strings, assemble-patch, and LLDB debug actions).

As a library:

```python
from rea_disassembler.formats import load_binary
from rea_disassembler.analysis import analyse

img = load_binary("/bin/ls")
result = analyse(img)
print(len(result["functions"]), len(result["strings"]), result["coverage"])
```

## For agents and AI models

One engine, four doors — all answers are the same JSON (`schema_version: "1"`,
paginated list envelopes, `{"error": {"code", "message"}}` on failure,
exit codes 0/2/3):

```bash
# npx (no install; first run provisions a managed Python venv in ~/.cache)
npx rea-disassembler info /bin/ls --json
npx rea-disassembler functions /bin/ls --json --limit 50 --offset 0

# MCP over stdio (any MCP client: Claude Code, Codex, Cursor, ...)
npx rea-disassembler mcp
#   config: {"mcpServers": {"rea-disassembler":
#             {"command": "npx", "args": ["-y", "rea-disassembler", "mcp"]}}}
#   tools: binary_overview, list_functions, list_strings,
#          disassemble_function, decompile_function
#   (assemble_and_patch / debug_run appear only with
#    READIS_MCP_ENABLE_WRITE=1 / READIS_MCP_ENABLE_DEBUG=1)

# HTTP API
readis serve --port 8765            # 127.0.0.1 only, unless you say otherwise
curl "http://127.0.0.1:8765/v1/info?path=/bin/ls"
curl "http://127.0.0.1:8765/v1/functions?path=/bin/ls&limit=50"

# Plain CLI / Python library
pip install "rea-disassembler[all]"
readis info /bin/ls --json
```

Install from source in this repo: `uv pip install -e ".[all]"`.
The analysed binary is never executed by the read tools; `patch` writes
a new file, and execution happens only through the explicit debug tool.

## Tests

```bash
.venv/bin/python -m pytest tests/ -q   # 37 tests + 4 Node launcher tests
```

The corpus in `bench/` is compiled from `bench/corpus_src/`; its functions,
strings, and branches are known by construction, so scores are exact.
Rebuild it with the `clang` commands in `bench/corpus_src/corpus.c`'s history
(Mach-O: `clang -O1 -g -arch arm64`; ELF: `--target=*-linux-gnu -ffreestanding -c`).
