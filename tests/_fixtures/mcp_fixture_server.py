"""Minimal REAL stdio MCP server for the R2-D2 owning-client integration test.

This is a genuine MCP server — it speaks the MCP protocol over stdio via the
installed ``mcp`` SDK (``mcp.server.FastMCP``) — not a monkeypatched stub. It
serves ONE harmless tool, ``echo``, which returns ``ECHO:<message>``.

It writes its own PID to the path named by the ``FIXTURE_PID_FILE`` env var so
the test can kill it precisely (SIGKILL) to prove the owning client survives and
can reconnect. Every native reconnect spawns a FRESH child process (same
script), so a new PID is written on each respawn.
"""

from __future__ import annotations

import os


def _write_pid() -> None:
    path = os.environ.get("FIXTURE_PID_FILE")
    if not path:
        return
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(str(os.getpid()))
    except OSError:
        pass


def main() -> int:
    from mcp.server import FastMCP

    server = FastMCP("fixture")

    @server.tool()
    def echo(message: str = "") -> str:
        """Return ECHO:<message> (harmless round-trip probe)."""
        return f"ECHO:{message}"

    _write_pid()
    server.run(transport="stdio")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
