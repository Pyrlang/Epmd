"""Where the server listens: a free port, IPv6 loopback, and ``python -m
epmd`` configured through OTP's environment variables."""

import asyncio
import os
import socket
import struct
import subprocess
import sys
import time
from collections.abc import Iterator

import pytest
from conftest import TIMEOUT, alive2_req, epmd_request, register

from epmd import Epmd


def _ipv6_loopback() -> bool:
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            s.bind(("::1", 0))
        return True
    except OSError:
        return False


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.mark.asyncio
@pytest.mark.skipif(not _ipv6_loopback(), reason="no IPv6 loopback address")
async def test_register_name_ipv6() -> None:
    """From epmd_SUITE:register_name_ipv6. Given only 127.0.0.1, the server
    also listens on ::1 (as OTP with ERL_EPMD_ADDRESS), and a node registers
    over IPv6."""
    server = Epmd(port=0, addresses=["127.0.0.1"])
    await server.start()
    try:
        node = await register(server.port, alive2_req(b"foobar6"), host="::1")
        assert node.reply[:2] == b"y\x00", node.reply
        await node.close()
    finally:
        await server.stop()


@pytest.fixture
def epmd_process() -> Iterator[int]:
    """``python -m epmd`` with ERL_EPMD_PORT and ERL_EPMD_ADDRESS set; its
    port once it answers."""
    port = _free_port()
    env = dict(os.environ, ERL_EPMD_PORT=str(port), ERL_EPMD_ADDRESS="127.0.0.1")
    proc = subprocess.Popen(
        [sys.executable, "-m", "epmd"],
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + TIMEOUT
        while True:
            try:
                asyncio.run(epmd_request(port, b"n"))
                break
            except OSError:
                if proc.poll() is not None or time.monotonic() > deadline:
                    raise AssertionError(proc.communicate()[1])
                time.sleep(0.1)
        yield port
    finally:
        proc.terminate()
        proc.communicate(timeout=TIMEOUT)


@pytest.mark.asyncio
async def test_python_m_epmd(epmd_process: int) -> None:
    """``python -m epmd`` listens where ERL_EPMD_PORT says: a name registered
    there is found there. (Real nodes are served by the same server class in
    the pyrlang interop suite.)"""
    node = await register(epmd_process, alive2_req(b"cli", port=4711))
    try:
        assert node.reply[:2] == b"y\x00", node.reply
        found = await epmd_request(epmd_process, b"zcli")
        assert found[:4] == b"w\x00" + struct.pack(">H", 4711), found
    finally:
        await node.close()


@pytest.mark.asyncio
async def test_start_on_port_0_and_stop() -> None:
    """``start`` returns once listening on a free port; ``stop`` closes it
    and may be called twice."""
    server = Epmd(host="127.0.0.1", port=0)
    await server.start()
    try:
        assert server.port != 0
        reply = await epmd_request(server.port, b"n")  # NAMES_REQ
        assert reply == struct.pack(">I", server.port)  # no names yet
    finally:
        await server.stop()
    await server.stop()
    with pytest.raises(OSError):
        await epmd_request(server.port, b"n")
