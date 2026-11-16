"""Registrations a real node cannot produce: many quick re-registrations of
one name, and a thousand names at once. Raw sockets; the cases come from
``epmd_SUITE`` (OTP's ``erts/epmd/test``)."""

import asyncio
import struct
import time

import pytest
from conftest import TIMEOUT, Registered, alive2_req, epmd_request, register

from epmd import Epmd


async def names(port: int) -> dict[str, int]:
    """Name -> port, as NAMES_REQ lists them."""
    reply = await epmd_request(port, b"n")
    assert reply[:4] == struct.pack(">I", port), reply
    listed = {}
    for line in reply[4:].decode().splitlines():
        name, _, node_port = line.removeprefix("name ").partition(" at port ")
        listed[name] = int(node_port)
    return listed


async def register_when_free(port: int, body: bytes) -> Registered:
    """Register, retrying while the server has not yet seen the previous
    holder of the name close its connection."""
    deadline = time.monotonic() + TIMEOUT
    while True:
        reg = await register(port, body)
        if reg.reply[1:2] == b"\x00" or time.monotonic() > deadline:
            return reg
        await reg.close()
        await asyncio.sleep(0.001)


@pytest.mark.asyncio
@pytest.mark.parametrize("hi_ver", [5, 6])
async def test_creation_changes_on_every_registration(
    epmd_server: Epmd, hi_ver: int
) -> None:
    """1000 register/unregister cycles of one name never answer creation 0
    and never repeat the previous creation; nodes before OTP 23 get 1..3
    (ALIVE2_RESP), newer ones a 32-bit value of at least 4 (ALIVE2_X_RESP)."""
    body = alive2_req(b"cr", hi_ver=hi_ver, lo_ver=5)
    previous = None
    for _ in range(1000):
        reg = await register_when_free(epmd_server.port, body)
        await reg.close()
        if hi_ver >= 6:
            assert reg.reply[:2] == b"v\x00", reg.reply
            (creation,) = struct.unpack(">I", reg.reply[2:])
            assert creation >= 4
        else:
            assert reg.reply[:2] == b"y\x00", reg.reply
            (creation,) = struct.unpack(">H", reg.reply[2:])
            assert 1 <= creation <= 3
        assert creation != previous
        previous = creation


@pytest.mark.asyncio
async def test_thousand_names(epmd_server: Epmd) -> None:
    """From epmd_SUITE:stupid_names_req and register_overflow: 1000 names
    register, NAMES_REQ lists exactly them, and unregistering them in
    either order and registering them again works."""
    wanted = {"foo%d" % i: 1000 + i for i in range(1, 1001)}
    for close_order in (list, reversed):
        held = []
        for name, port in wanted.items():
            reg = await register_when_free(
                epmd_server.port, alive2_req(name.encode(), port=port)
            )
            assert reg.reply[:2] == b"y\x00", (name, reg.reply)
            held.append(reg)
        await held[0].close()
        deadline = time.monotonic() + TIMEOUT
        while "foo1" in (listed := await names(epmd_server.port)):
            assert time.monotonic() < deadline
            await asyncio.sleep(0.05)
        assert listed == {n: p for n, p in wanted.items() if n != "foo1"}
        for reg in close_order(held[1:]):
            await reg.close()
        deadline = time.monotonic() + TIMEOUT
        while await names(epmd_server.port):
            assert time.monotonic() < deadline
            await asyncio.sleep(0.05)
