"""Fixtures and helpers for the EPMD server tests.

The server is tested from two places. What a real node shows (it registers,
is looked up, is listed by ``net_adm:names`` and ``epmd -names``, nodes
reach each other through the server) is tested by the pyrlang interop suite
run on this server (``pytest --epmd=python`` in ``pyrlang-src``). The tests
here cover only what that run cannot show and OTP cannot be made to send:
hostile requests over a raw socket and the kill, stop, limit and listening
rules. Nothing here starts ``erl``.

- ``epmd_server``: the Python ``Epmd`` listening on a free port of
  127.0.0.1 in the test's event loop; stopped afterwards.
- ``epmd_request``: open a TCP connection, send one length-prefixed request,
  read the reply until the server closes the connection. ``exchange`` does
  the same with raw chunks and pauses; ``register`` sends an ALIVE2_REQ and
  keeps the connection (the registration) open.
"""

import asyncio
import struct
from collections.abc import AsyncIterator, Sequence
from dataclasses import dataclass

import pytest_asyncio

from epmd import Epmd

# Seconds to wait for the server or a reply.
TIMEOUT = 20.0


@pytest_asyncio.fixture
async def epmd_server() -> AsyncIterator[Epmd]:
    """The Python EPMD on a free port of 127.0.0.1 (``.port`` after start)."""
    server = Epmd(host="127.0.0.1", port=0)
    await server.start()
    try:
        yield server
    finally:
        await server.stop()


def u16(n: int) -> bytes:
    return struct.pack(">H", n)


def framed(body: bytes) -> bytes:
    """A request body with its 2-byte length prefix."""
    return u16(len(body)) + body


def alive2_req(
    name: bytes,
    port: int = 1000,
    node_type: int = 77,
    hi_ver: int = 5,
    lo_ver: int = 5,
    extra: bytes = b"",
    proto: int = 0,
) -> bytes:
    """An ALIVE2_REQ body (erl_dist_protocol; defaults as epmd_SUITE's)."""
    head = struct.pack(">BHBBHH", 120, port, node_type, proto, hi_ver, lo_ver)
    return head + u16(len(name)) + name + u16(len(extra)) + extra


async def exchange(
    port: int,
    send: Sequence[bytes | float],
    host: str = "127.0.0.1",
    want: int | None = None,
) -> bytes:
    """Connect, write each ``bytes`` of ``send`` (a float pauses that many
    seconds), then read until the server closes, or until ``want`` bytes
    arrived. A reset counts as a close."""
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port), TIMEOUT
    )
    got = b""
    try:
        try:
            for item in send:
                if isinstance(item, float):
                    await asyncio.sleep(item)
                else:
                    writer.write(item)
                    await writer.drain()
        except ConnectionError:
            pass
        while want is None or len(got) < want:
            try:
                data = await asyncio.wait_for(reader.read(65536), TIMEOUT)
            except ConnectionError:
                break
            if not data:
                break
            got += data
    finally:
        writer.close()
    return got


async def epmd_request(port: int, request: bytes) -> bytes:
    """Send ``request`` with its 2-byte length to EPMD; read until EOF."""
    return await exchange(port, [framed(request)])


# A registration held open by a test; closing it unregisters the name.
@dataclass
class Registered:
    reply: bytes  # the ALIVE2 reply (b"" if the server closed instead)
    writer: asyncio.StreamWriter
    reader: asyncio.StreamReader

    async def close(self) -> None:
        self.writer.close()
        try:
            await self.writer.wait_closed()
        except ConnectionError:
            pass


async def register(port: int, body: bytes, host: str = "127.0.0.1") -> Registered:
    """Send an ALIVE2_REQ ``body`` and read its reply (4 or 6 bytes); the
    connection stays open."""
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port), TIMEOUT
    )
    writer.write(framed(body))
    reply = b""
    try:
        first = await asyncio.wait_for(reader.read(1), TIMEOUT)
        if first:
            size = 6 if first == b"v" else 4
            reply = first + await asyncio.wait_for(
                reader.readexactly(size - 1), TIMEOUT
            )
    except (ConnectionError, asyncio.IncompleteReadError):
        pass
    return Registered(reply, writer, reader)
