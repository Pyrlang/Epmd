"""Where the server listens: IPv6 loopback, and ``python -m epmd``
configured through OTP's environment variables, serving a real node."""

import asyncio
import os
import re
import socket
import subprocess
import sys
import time
from collections.abc import Iterator

import pytest
from conftest import TIMEOUT, ErlNode, Otp, alive2_req, epmd_request, register

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


@pytest.mark.erlang
@pytest.mark.asyncio
async def test_python_m_epmd_serves_erl(otp: Otp, epmd_process: int) -> None:
    """An ``erl`` node with ERL_EPMD_PORT set registers in ``python -m
    epmd`` started with the same variable, and is listed by it."""
    node = ErlNode(otp, epmd_process)
    try:
        assert await node.eval("node().") == "'%s'" % node.name, node.log()
        names = await node.eval("net_adm:names('127.0.0.1').")
        short = node.name.split("@")[0]
        assert re.fullmatch(r'\{ok,\[\{"%s",\d+\}\]\}' % short, names), names
    finally:
        await node.stop()
