"""HTTP API for rea-disassembler (`readis serve`).

Same payloads as the CLI JSON contract, over HTTP:
  GET  /health
  GET  /v1/info?path=…
  GET  /v1/functions?path=…&limit=&offset=
  GET  /v1/strings?path=…&limit=&offset=
  GET  /v1/disassemble?path=…&target=…
  GET  /v1/decompile?path=…&target=…
  POST /v1/patch   (only with --enable-write; JSON {path,address,asm,out})

Errors are the shared envelope: {"error": {"code", "message"}}.
Binds localhost by default; the analysed binary is never executed.
"""
from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from . import service


class PatchRequest(BaseModel):
    path: str
    address: str
    asm: str
    out: str


def _err(code: str, message: str, status: int) -> JSONResponse:
    return JSONResponse({"error": {"code": code, "message": message}},
                        status_code=status)


def create_app(enable_write: bool = False) -> FastAPI:
    app = FastAPI(title="rea-disassembler", version="1")

    @app.exception_handler(FileNotFoundError)
    async def _nf(_req: Request, exc: FileNotFoundError):
        return _err("not_found", str(exc), 404)

    @app.exception_handler(ValueError)
    async def _bad(_req: Request, exc: ValueError):
        return _err("invalid_input", str(exc), 400)

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok", "schema_version": "1"}

    @app.get("/v1/info")
    def info(path: str) -> dict:
        return service.overview(path)

    @app.get("/v1/functions")
    def functions(path: str, limit: int = 200, offset: int = 0) -> dict:
        return service.functions_page(path, limit, offset)

    @app.get("/v1/strings")
    def strings(path: str, limit: int = 200, offset: int = 0) -> dict:
        return service.strings_page(path, limit, offset)

    @app.get("/v1/disassemble")
    def disassemble(path: str, target: str) -> dict:
        return service.disassemble(path, target)

    @app.get("/v1/decompile")
    def decompile(path: str, target: str) -> dict:
        return service.decompile(path, target)

    @app.post("/v1/patch")
    def patch(req: PatchRequest):
        if not enable_write:
            return _err("write_disabled",
                        "patch endpoint requires --enable-write", 403)
        from .assembler import patch_binary
        from .formats import load_binary
        img = load_binary(req.path)
        return patch_binary(img, int(req.address, 0), req.asm, req.out)

    return app


def run_server(host: str = "127.0.0.1", port: int = 8765,
               enable_write: bool = False) -> None:
    import uvicorn
    uvicorn.run(create_app(enable_write=enable_write), host=host, port=port)
