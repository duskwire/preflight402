"""Live streamable-http transport check (deselected by default).

Run with: uv run pytest -m slow tests/integration/test_mcp_http_live.py

Starts the real `preflight402-mcp --transport streamable-http` as a
subprocess (uvicorn out-of-process, so its teardown never entangles the test
runner) and drives it with the SDK's streamable-http client.
"""

import os
import socket
import subprocess
import sys
import time

import pytest
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

pytestmark = [pytest.mark.anyio, pytest.mark.slow]


def _free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


async def test_streamable_http_tool_call(tmp_path) -> None:
    port = _free_port()
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "preflight402.api.mcp_server",
            "--transport",
            "streamable-http",
            "--port",
            str(port),
        ],
        env={**os.environ, "PREFLIGHT402_DB_PATH": str(tmp_path / "http.db")},
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
                break
            except OSError:
                time.sleep(0.2)
        else:
            raise RuntimeError("streamable-http server did not come up")

        async with (
            streamable_http_client(f"http://127.0.0.1:{port}/mcp") as (read, write, _),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            tools = await session.list_tools()
            assert "preflight" in {t.name for t in tools.tools}
            result = await session.call_tool("preflight", {"url": "https://www.google.com/"})
            assert result.isError is False
            doc = result.structuredContent
            assert doc["schema"] == "trust-preview.v1"
            assert doc["endpoint"]["payment_endpoint"] is False
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
