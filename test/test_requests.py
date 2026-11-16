"""Requests a real Erlang node never sends, over a raw socket.

One table: what a client sends, and everything the server writes before it
closes the connection (``b""``: closed without a reply). Rows are ports of
``epmd_SUITE`` cases (OTP's ``erts/epmd/test``) and are named after them.
Behaviour that real nodes show (register, look up, list) is tested with real
nodes by the pyrlang interop suite run on this server (``--epmd=python``).
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

# Registered by the fixture for the whole test: name -> ALIVE2_REQ fields.
FOO_PORT = 1042
# From epmd_SUITE:unicode_name and long_unicode_name (800+ bytes).
DEVIL = "\U0001f608".encode()
LONG = "".join(map(chr, range(0x1F600, 0x1F600 + 201))).encode()
NODES: dict[bytes, dict[str, Any]] = {
    b"foo": dict(port=FOO_PORT),
    # From epmd_SUITE:returns_valid_populated_extra_with_nulls.
    b"bar": dict(port=4711, node_type=72, extra=b"ABC\0\0"),
    DEVIL: dict(port=4711, node_type=72),
    LONG: dict(port=4711, node_type=72),
}


def port2_resp(name: bytes) -> bytes:
    """The PORT2_RESP for a node in NODES (erl_dist_protocol layout)."""
    f: dict[str, Any] = dict(port=1000, node_type=77, proto=0, hi_ver=5, lo_ver=5)
    f["extra"] = b""
    f.update(NODES[name])
    return (
        b"w\x00"
        + u16(f["port"])
        + bytes([f["node_type"], f["proto"]])
        + u16(f["hi_ver"])
        + u16(f["lo_ver"])
        + u16(len(name))
        + name
        + u16(len(f["extra"]))
        + f["extra"]
    )


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
    # From epmd_SUITE:register_duplicate_name.
    "register_duplicate_name": ([framed(alive2_req(b"foo"))], REFUSED_5),
    "register_duplicate_name-v6": (
        [framed(alive2_req(b"foo", hi_ver=6, lo_ver=6))],
        b"v\x01\x00\x00" + u16(99),
    ),
    # From epmd_SUITE: PORT2_REQ, Extra and names.
    "get_port_nr": ([framed(b"zfoo")], port2_resp(b"foo")),
    "slow_get_port_nr": (
        [u16(4) + b"z", 0.2, b"f", 0.2, b"o", 0.2, b"o"],
        port2_resp(b"foo"),
    ),
    "returns_valid_empty_extra": ([framed(b"zfoo")], port2_resp(b"foo")),
    "returns_valid_populated_extra_with_nulls": (
        [framed(b"zbar")],
        port2_resp(b"bar"),
    ),
    "unicode_name": ([framed(b"z" + DEVIL)], port2_resp(DEVIL)),
    "long_unicode_name": ([framed(b"z" + LONG)], port2_resp(LONG)),
    # Not in the suite; rules from epmd_srv.c (EPMD_PORT2_REQ).
    "port2_unknown_name": ([framed(b"zxxx42")], b"w\x01"),
    "port2_trailing_nul": ([framed(b"zfoo\0")], port2_resp(b"foo")),
    "port2_empty_name": ([framed(b"z")], b""),
    "port2_only_nul": ([framed(b"z\0")], b""),
    "port2_nul_inside": ([framed(b"zfo\0o")], b""),
    "port2_invalid_utf8": ([framed(b"z\xed\xa0\x80")], b""),
    "port2_256_chars": ([framed(b"z" + b"a" * 256)], b""),
}


@pytest_asyncio.fixture
async def served() -> AsyncIterator[Epmd]:
    """A server with the suite's packet timeout and the NODES registered."""
    server = Epmd(host="127.0.0.1", port=0, packet_timeout=PACKET_TIMEOUT)
    await server.start()
    held: list[Registered] = []
    try:
        for name, fields in NODES.items():
            held.append(await register(server.port, alive2_req(name, **fields)))
            assert held[-1].reply[:2] == b"y\x00", (name, held[-1].reply)
        yield server
    finally:
        for reg in held:
            await reg.close()
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
    assert await exchange(served.port, [framed(b"zfoo")]) == port2_resp(b"foo")
    assert errors == []
