"""MCP server for rea-disassembler (stdio transport).

Exposes the engine as tools any MCP client can call.  Stdout carries
JSON-RPC only — all logging goes to stderr.  Write/debug tools
(assemble_and_patch, debug_run) are registered exclusively when
READIS_MCP_ENABLE_WRITE / READIS_MCP_ENABLE_DEBUG are set to 1; the
analysed binary is never executed by the read-only tools.

Run:  readis-mcp        (or: python -m rea_disassembler.mcp_server)
"""
from __future__ import annotations

import os
import sys

from . import service

try:  # mcp 2.x renamed FastMCP -> MCPServer; support both
    from mcp.server.mcpserver import MCPServer as _ServerImpl
except ImportError:  # mcp 1.x
    from mcp.server.fastmcp import FastMCP as _ServerImpl

server = _ServerImpl("rea-disassembler")


@server.tool()
def binary_overview(path: str) -> dict:
    """Full analysis overview (format, segments, counts, functions, strings)."""
    return service.overview(path)


@server.tool()
def list_functions(path: str, limit: int = 200, offset: int = 0) -> dict:
    """Paginated function list (address-ordered, envelope with total)."""
    return service.functions_page(path, limit, offset)


@server.tool()
def list_strings(path: str, limit: int = 200, offset: int = 0) -> dict:
    """Paginated strings with cross-reference addresses."""
    return service.strings_page(path, limit, offset)


@server.tool()
def disassemble_function(path: str, target: str) -> dict:
    """Disassembly listing for one function (address 0x… or name)."""
    return service.disassemble(path, target)


@server.tool()
def decompile_function(path: str, target: str) -> dict:
    """Structured pseudocode for one function (address 0x… or name)."""
    return service.decompile(path, target)


if os.environ.get("READIS_MCP_ENABLE_WRITE") == "1":

    @server.tool()
    def assemble_and_patch(path: str, address: str, asm: str, out: str) -> dict:
        """Assemble `asm` at `address` into a patched copy at `out`
        (original untouched, ad-hoc re-signed on Mach-O)."""
        from .assembler import patch_binary
        from .formats import load_binary
        img = load_binary(path)
        return patch_binary(img, int(address, 0), asm, out)


if os.environ.get("READIS_MCP_ENABLE_DEBUG") == "1":

    @server.tool()
    def debug_run(path: str, breakpoints: list[str] | None = None) -> dict:
        """Run the target under LLDB until the given breakpoints hit."""
        from .debugger import debug_run as _dbg
        return _dbg(path, breakpoints)


def main() -> int:
    server.run("stdio")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
