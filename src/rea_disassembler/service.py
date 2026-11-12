"""Shared service layer for the MCP server and HTTP API.

One analysis cache (bounded, keyed by path+mtime) feeds every agent
surface so CLI, MCP, and HTTP answers can never drift apart: they are
literally the same dictionaries the CLI prints.
"""
from __future__ import annotations

import os
from pathlib import Path

from .analysis import analyse
from .formats import load_binary
from .output import image_to_dict, page

_CACHE: dict[str, tuple[float, object, dict]] = {}
_MAX_CACHE = 2


def get_analysis(path: str):
    p = str(Path(path))
    if not os.path.isfile(p):
        raise FileNotFoundError(p)
    mtime = os.path.getmtime(p)
    hit = _CACHE.get(p)
    if hit and hit[0] == mtime:
        return hit[1], hit[2]
    img = load_binary(p)
    result = analyse(img)
    if len(_CACHE) >= _MAX_CACHE:
        _CACHE.clear()
    _CACHE[p] = (mtime, img, result)
    return img, result


def overview(path: str) -> dict:
    img, result = get_analysis(path)
    return image_to_dict(img, result)


def functions_page(path: str, limit: int = 200, offset: int = 0) -> dict:
    items = overview(path)["functions"]
    limit = max(0, min(limit, 5000))
    return page(items[offset:offset + limit], len(items), limit, offset)


def strings_page(path: str, limit: int = 200, offset: int = 0) -> dict:
    img, result = get_analysis(path)
    items = [{"addr": hex(s.addr), "value": s.value, "encoding": s.encoding,
              "xrefs": [hex(x) for x in s.xrefs]} for s in result["strings"]]
    limit = max(0, min(limit, 5000))
    return page(items[offset:offset + limit], len(items), limit, offset)


def _resolve(result: dict, ident: str):
    try:
        addr = int(ident, 0)
        fn = next((f for f in result["functions"] if f.addr == addr), None)
    except (TypeError, ValueError):
        fn = next((f for f in result["functions"]
                   if f.name in (ident, "_" + str(ident))), None)
    if fn is None:
        raise ValueError(f"no function {ident!r}")
    return fn


def disassemble(path: str, target: str) -> dict:
    from .output import listing
    img, result = get_analysis(path)
    fn = _resolve(result, target)
    text = listing(img, result, fn.addr)
    return {"schema_version": "1", "function": fn.name, "addr": hex(fn.addr),
            "listing": text}


def decompile(path: str, target: str) -> dict:
    from .decompile import decompile_function
    img, result = get_analysis(path)
    fn = _resolve(result, target)
    return {"schema_version": "1", "function": fn.name, "addr": hex(fn.addr),
            "code": decompile_function(img, fn)}
