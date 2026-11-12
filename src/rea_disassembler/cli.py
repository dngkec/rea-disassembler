"""readis — command-line interface.

  readis info      <file> [--arch A] [--raw] [--json]
  readis disasm    <file> [--function 0xADDR] [--json]
  readis functions <file>
  readis strings   <file> [--xrefs]
  readis pseudo    <file> <0xADDR | name>     (alias of decompile)
  readis decompile <file> <0xADDR | name>
  readis cfg       <file> <0xADDR | name>
  readis assemble  <file> <0xADDR> "mov x0, #1"
  readis patch     <file> <0xADDR> "mov x0, #1" -o <out>
  readis debug     <file> [--break NAME|0xADDR]... [--cmd "step"]...
  readis bench     <file> [<file> ...]
  readis gui                                   (build/open the native app)
"""
from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .analysis import analyse
from .assembler import assemble, patch_binary
from .bench import run_bench
from .debugger import debug_run
from .decompile import decompile_function
from .formats import load_binary
from .output import listing, page, to_json
from .pseudocode import lift_function


def _load(args):
    return load_binary(args.file, raw_arch=args.arch if getattr(args, "raw", False) else None,
                       arch=args.arch if not getattr(args, "raw", False) else None)


def _resolve_fn(img, result, ident: str):
    try:
        addr = int(ident, 0)
        fn = next((f for f in result["functions"] if f.addr == addr), None)
    except ValueError:
        fn = next((f for f in result["functions"] if f.name in (ident, "_" + ident)), None)
    if fn is None:
        print(f"no function {ident!r}", file=sys.stderr)
        raise SystemExit(2)
    return fn


def main(argv: list[str] | None = None) -> int:
    """Entry point with the agent error contract: analysis failures are a
    JSON error envelope on stderr and exit code 3; usage errors stay 2."""
    try:
        return _run(argv)
    except FileNotFoundError as e:
        print(json.dumps({"error": {"code": "not_found", "message": str(e)}}),
              file=sys.stderr)
        return 3
    except ValueError as e:
        print(json.dumps({"error": {"code": "invalid_input", "message": str(e)}}),
              file=sys.stderr)
        return 3


def _run(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="readis", description=__doc__)
    p.add_argument("--version", action="version", version=f"readis {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("file")
        sp.add_argument("--arch", default=None, help="arm64 | x86_64 | x86 | arm")
        sp.add_argument("--raw", action="store_true", help="headerless image (needs --arch)")

    for name in ("info", "disasm", "functions", "strings"):
        sp = sub.add_parser(name)
        common(sp)
        sp.add_argument("--json", action="store_true")
    sub.choices["disasm"].add_argument("--function", default=None)
    sub.choices["strings"].add_argument("--xrefs", action="store_true")
    for nm in ("functions", "strings"):
        sub.choices[nm].add_argument("--limit", type=int, default=None)
        sub.choices[nm].add_argument("--offset", type=int, default=0)
    for name in ("pseudo", "cfg", "decompile"):
        sp = sub.add_parser(name)
        common(sp)
        sp.add_argument("target", help="function address (0x…) or name")
    sp = sub.add_parser("bench")
    sp.add_argument("files", nargs="+")
    sp = sub.add_parser("assemble")
    common(sp)
    sp.add_argument("address")
    sp.add_argument("asm")
    sp = sub.add_parser("patch")
    common(sp)
    sp.add_argument("address")
    sp.add_argument("asm")
    sp.add_argument("-o", "--out", required=True)
    sp = sub.add_parser("debug")
    sp.add_argument("file")
    sp.add_argument("--break", dest="breaks", action="append", default=[])
    sp.add_argument("--cmd", dest="cmds", action="append", default=[])
    sp = sub.add_parser("serve")
    sp.add_argument("--host", default="127.0.0.1")
    sp.add_argument("--port", type=int, default=8765)
    sp.add_argument("--enable-write", action="store_true",
                    help="enable the guarded patch endpoint")
    sub.add_parser("gui")

    args = p.parse_args(argv)
    if args.cmd == "bench":
        rows = run_bench(args.files)
        print(json.dumps(rows, indent=2))
        return 0
    if args.cmd == "gui":
        from .gui import launch_gui
        return launch_gui()
    if args.cmd == "debug":
        print(json.dumps(debug_run(args.file, args.breaks or None, args.cmds or None),
                         indent=2))
        return 0
    if args.cmd == "serve":
        from .http_api import run_server
        run_server(args.host, args.port, enable_write=args.enable_write)
        return 0
    img = _load(args)
    result = analyse(img)
    if args.cmd == "info":
        print(to_json(img, result) if args.json else
              f"{img.path}: {img.format} {img.arch} {img.bits}-bit entry={img.entry:#x}\n"
              f"segments={len(img.segments)} sections={len(img.sections)} "
              f"symbols={len(img.symbols)} imports={len(img.imports)}\n"
              f"functions={len(result['functions'])} instructions={len(result['instructions'])} "
              f"strings={len(result['strings'])} coverage={result['coverage']:.1%}")
    elif args.cmd == "disasm":
        fa = int(args.function, 0) if args.function else None
        print(to_json(img, result) if args.json else listing(img, result, fa), end="")
    elif args.cmd == "functions":
        if args.json:
            from .output import image_to_dict
            items = image_to_dict(img, result)["functions"]
            limit = args.limit if args.limit is not None else len(items)
            print(json.dumps(page(items[args.offset:args.offset + limit],
                                  len(items), limit, args.offset), indent=2))
        else:
            for f in sorted(result["functions"], key=lambda x: x.addr):
                print(f"{f.addr:#014x}  {f.end - f.addr:5d}  {f.name}  [{f.source}]"
                      f" callees={len(f.callees)} callers={len(f.callers)}")
    elif args.cmd == "strings":
        if args.json:
            items = [{"addr": hex(s.addr), "value": s.value, "encoding": s.encoding,
                      "xrefs": [hex(x) for x in s.xrefs]} for s in result["strings"]]
            limit = args.limit if args.limit is not None else len(items)
            print(json.dumps(page(items[args.offset:args.offset + limit],
                                  len(items), limit, args.offset), indent=2))
        else:
            for s in result["strings"]:
                xr = f"  xrefs={[hex(x) for x in s.xrefs]}" if args.xrefs and s.xrefs else ""
                print(f"{s.addr:#014x}  [{s.encoding}] {s.value!r}{xr}")
    elif args.cmd in ("pseudo", "decompile"):
        print(decompile_function(img, _resolve_fn(img, result, args.target)))
    elif args.cmd == "assemble":
        addr = int(args.address, 0)
        code = assemble(img.arch, args.asm, addr)
        print(f"{addr:#x}: {code.hex()}  ({len(code)} bytes)")
    elif args.cmd == "patch":
        print(json.dumps(patch_binary(img, int(args.address, 0), args.asm, args.out),
                         indent=2))
    elif args.cmd == "cfg":
        fn = _resolve_fn(img, result, args.target)
        print(f"digraph cfg_{fn.name} {{")
        for b in fn.blocks:
            print(f'  "b_{b.start:x}" [label="block_{b.start:x} ({len(b.instructions)} ins)"];')
            for s in b.successors:
                print(f'  "b_{b.start:x}" -> "b_{s:x}";')
        print("}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
