"""The examples shown in the documentation run (plan step DOCS-03):
``examples/*.py``, which ``docs-src/source/index.md`` includes."""

import asyncio
import importlib.util
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path
from types import ModuleType

import pytest
from conftest import TIMEOUT, epmd_request

EXAMPLES = Path(__file__).parent.parent / "examples"


def _load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, EXAMPLES / (name + ".py"))
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.asyncio
async def test_embedded_epmd() -> None:
    """The server listens while the example's block runs and not after."""
    port = await _load("embedded_epmd").main()
    assert port != 0
    with pytest.raises(OSError):
        await epmd_request(port, b"n")


def test_run_epmd() -> None:
    """``python examples/run_epmd.py PORT`` answers a NAMES_REQ on that
    port until it is stopped."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = int(s.getsockname()[1])
    proc = subprocess.Popen(
        [sys.executable, str(EXAMPLES / "run_epmd.py"), str(port)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + TIMEOUT
        while True:
            try:
                reply = asyncio.run(epmd_request(port, b"n"))
                break
            except OSError:
                if proc.poll() is not None or time.monotonic() > deadline:
                    raise AssertionError(proc.communicate()[1])
                time.sleep(0.1)
        assert reply == struct.pack(">I", port)  # its port, no names yet
    finally:
        proc.terminate()
        proc.communicate(timeout=TIMEOUT)


def test_every_example_is_tested() -> None:
    tested = {"embedded_epmd.py", "run_epmd.py"}
    assert {p.name for p in EXAMPLES.glob("*.py")} == tested
