"""KILL_REQ and STOP_REQ rules, and a registration reset before its reply.

Raw sockets; ports of ``epmd_SUITE`` cases (OTP's ``erts/epmd/test``).
``no_nonlocal_register`` and ``no_nonlocal_kill`` are not ported: a peer on
another host cannot be made on one machine (OTP's suite needs an ssh proxy
for them and skips otherwise).
"""

import asyncio
import socket
import struct
import time
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from conftest import TIMEOUT, alive2_req, epmd_request, exchange, framed, register

from epmd import Epmd


@pytest_asyncio.fixture
async def relaxed() -> AsyncIterator[Epmd]:
    """A server started with relaxed_command_check."""
    server = Epmd(host="127.0.0.1", port=0, relaxed_command_check=True)
    await server.start()
    try:
        yield server
    finally:
        await server.stop()


async def wait_unregistered(port: int, name: bytes) -> None:
    deadline = time.monotonic() + TIMEOUT
    while await epmd_request(port, b"z" + name) != b"w\x01":
        assert time.monotonic() < deadline, name
        await asyncio.sleep(0.02)


async def refuses_connections(port: int) -> bool:
    try:
        await exchange(port, [framed(b"n")])
    except OSError:
        return True
    return False


@pytest.mark.asyncio
async def test_no_live_killing() -> None:
    """From epmd_SUITE:no_live_killing. Without relaxed_command_check, KILL
    is refused while a node is registered and STOP is ignored; once the node
    is gone KILL stops the server, and ``start_server`` returns."""
    server = Epmd(host="127.0.0.1", port=0)
    serving = asyncio.create_task(server.start_server())
    try:
        while server.port == 0:
            await asyncio.sleep(0.01)
        foo = await register(server.port, alive2_req(b"foo"))
        assert foo.reply[:2] == b"y\x00"
        assert await epmd_request(server.port, b"k") == b"NO"
        assert await epmd_request(server.port, b"sfoo") == b""
        assert (await epmd_request(server.port, b"zfoo"))[:2] == b"w\x00"
        await foo.close()
        await wait_unregistered(server.port, b"foo")
        assert await epmd_request(server.port, b"k") == b"OK"
        await asyncio.wait_for(serving, TIMEOUT)
        assert await refuses_connections(server.port)
    finally:
        serving.cancel()
        await server.stop()


@pytest.mark.asyncio
async def test_unregister_others_name(relaxed: Epmd) -> None:
    """From epmd_SUITE:unregister_others_name_1 and _2. With
    relaxed_command_check STOP unregisters any name and closes that node's
    connection; for an unknown name OTP sends NOEXIST and then STOPPED."""
    foo = await register(relaxed.port, alive2_req(b"foo"))
    assert foo.reply[:2] == b"y\x00"
    assert await epmd_request(relaxed.port, b"sfoo") == b"STOPPED"
    assert await asyncio.wait_for(foo.reader.read(), TIMEOUT) == b""
    assert await epmd_request(relaxed.port, b"zfoo") == b"w\x01"
    assert await epmd_request(relaxed.port, b"sxxx42") == b"NOEXISTSTOPPED"
    await foo.close()


@pytest.mark.asyncio
async def test_relaxed_kill_with_live_node(relaxed: Epmd) -> None:
    """With relaxed_command_check KILL stops the server even while a node
    is registered."""
    foo = await register(relaxed.port, alive2_req(b"foo"))
    assert foo.reply[:2] == b"y\x00"
    assert await epmd_request(relaxed.port, b"k") == b"OK"
    assert await asyncio.wait_for(foo.reader.read(), TIMEOUT) == b""
    deadline = time.monotonic() + TIMEOUT
    while not await refuses_connections(relaxed.port):
        assert time.monotonic() < deadline
        await asyncio.sleep(0.02)
    await foo.close()


@pytest.mark.asyncio
async def test_socket_reset_before_alive2_reply_is_written(
    epmd_server: Epmd,
) -> None:
    """From epmd_SUITE:socket_reset_before_alive2_reply_is_written: a node
    that resets its connection right after ALIVE2_REQ leaves no name
    behind."""
    _, writer = await asyncio.open_connection("127.0.0.1", epmd_server.port)
    sock = writer.get_extra_info("socket")
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    writer.write(framed(alive2_req(b"test", port=4711)))
    await writer.drain()
    writer.transport.abort()
    empty = struct.pack(">I", epmd_server.port)
    deadline = time.monotonic() + TIMEOUT
    while await epmd_request(epmd_server.port, b"n") != empty:
        assert time.monotonic() < deadline
        await asyncio.sleep(0.02)
