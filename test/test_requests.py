"""Requests a real Erlang node never sends, over a raw socket.

One table: what a client sends, and everything the server writes before it
closes the connection (``b""``: closed without a reply). Rows are ports of
``epmd_SUITE`` cases (OTP's ``erts/epmd/test``) and are named after them.
Behaviour that real nodes show (register, look up, list) is tested with real
nodes in ``test_epmd_server.py`` and in the pyrlang interop suite.
"""

import asyncio
import re
from collections.abc import AsyncIterator, Sequence
from typing import Any

import pytest
import pytest_asyncio
from conftest import Registered, alive2_req, exchange, framed, register, u16

from epmd import Epmd

# The OTP suite runs epmd with -packet_timeout 1.
PACKET_TIMEOUT = 1.0

# Registered by the fixture for the whole test.
FOO_PORT = 1042


def hostile(n: int) -> bytes:
    """From epmd_SUITE:buffer_overrun_1: Elen claims ``n`` bytes, none sent."""
    return framed(alive2_req(b"gurka", port=4747)[:-2] + u16(n))


def hostile2(n: int) -> bytes:
    """From epmd_SUITE:buffer_overrun_2: an Extra of ``n`` bytes of 255."""
    return framed(alive2_req(b"gurka", port=4747, extra=b"\xff" * n))


# Reply of a refused ALIVE2_REQ from a node with HighestVersion 5: creation 99.
REFUSED_5 = b"y\x01" + u16(99)

# The expected reply of a row: the bytes up to the server's close, or a
# pattern for a reply after which the server keeps the connection open (a
# registration); the pattern's length in bytes is read.
Reply = bytes | tuple[int, "re.Pattern[bytes]"]

# The 16-bit reply to a successful registration.
REGISTERED_5 = (4, re.compile(rb"y\x00..", re.S))

ROWS: dict[str, tuple[Sequence[bytes | float], Reply]] = {
    # From epmd_SUITE: framing.
    "no_data": ([], b""),
    "one_byte": ([b"\0"], b""),
    "two_bytes": ([u16(3)], b""),
    "partial_packet": ([u16(100) + b"only a few bytes"], b""),
    "zero_length": ([b"\0" * 10], b""),
    "too_large": ([u16(63000) + b"z" * 63000], b""),
    # Not in the suite: one request per connection, so a second one in the
    # same read closes it (epmd_srv.c do_read), and unknown codes close.
    "two_requests": ([framed(b"n") + framed(b"n")], b""),
    "unknown_request": ([framed(b"Q")], b""),
    # From epmd_SUITE: ALIVE2_REQ bounds.
    "alive_req_too_small_1": ([framed(alive2_req(b"")[:11])], b""),
    "alive_req_too_small_2": ([framed(alive2_req(b"")[:9])], b""),
    "alive_req_too_large": ([framed(alive2_req(b"a" * 600))], REFUSED_5),
    "buffer_overrun_1-1": ([hostile(1)], b""),
    "buffer_overrun_1-1020": ([hostile(1020)], b""),
    "buffer_overrun_1-65535": ([hostile(65535)], b""),
    "buffer_overrun_2-1020": ([hostile2(1020)], REGISTERED_5),
    "buffer_overrun_2-1021": ([hostile2(1021)], REFUSED_5),
    "buffer_overrun_2-3039": ([hostile2(3039)], REFUSED_5),
    "buffer_overrun_2-3040": ([hostile2(3040)], b""),
    "name_with_null_inside": ([framed(alive2_req(b"foo\0bar"))], b""),
    "name_null_terminated": ([framed(alive2_req(b"foobar\0"))], b""),
    "invalid_utf8_name": ([framed(alive2_req(b"\xc0\x80"))], REFUSED_5),
}


@pytest_asyncio.fixture
async def served() -> AsyncIterator[Epmd]:
    """A server with the suite's packet timeout and node ``foo`` registered;
    records calls of the loop's exception handler."""
    server = Epmd(host="127.0.0.1", port=0, packet_timeout=PACKET_TIMEOUT)
    await server.start()
    foo: Registered | None = None
    try:
        foo = await register(server.port, alive2_req(b"foo", port=FOO_PORT))
        assert foo.reply[:2] == b"y\x00", foo.reply
        yield server
    finally:
        if foo is not None:
            await foo.close()
        await server.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize("send, reply", ROWS.values(), ids=ROWS.keys())
async def test_request(
    served: Epmd, send: Sequence[bytes | float], reply: Reply
) -> None:
    """The server answers (or closes) as OTP's epmd does, raises nothing,
    and still serves its registered node afterwards."""
    errors: list[dict[str, Any]] = []
    asyncio.get_running_loop().set_exception_handler(lambda _, ctx: errors.append(ctx))
    if isinstance(reply, bytes):
        assert await exchange(served.port, send) == reply
    else:
        got = await exchange(served.port, send, want=reply[0])
        assert reply[1].fullmatch(got), got
    port_req = await exchange(served.port, [framed(b"zfoo")])
    assert port_req[:4] == b"w\x00" + u16(FOO_PORT), port_req
    assert errors == []
