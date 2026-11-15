"""A flood of idle connections cannot lock nodes out for longer than the
packet timeout. (``slow_get_port_nr``, a slow but complete request, is a row
of the table in ``test_requests.py``.)"""

import asyncio
import time

import pytest
from conftest import TIMEOUT, alive2_req, register

from epmd import Epmd

LIMIT = 16
PACKET_TIMEOUT = 2.0


@pytest.mark.asyncio
async def test_idle_flood_ends_at_the_packet_timeout() -> None:
    """With 16 connections allowed, 1000 silent clients take the slots, so
    a node is refused at first; once the packet timeout closed the idle
    ones, the node registers, while the flood's sockets are still open."""
    server = Epmd(
        host="127.0.0.1",
        port=0,
        packet_timeout=PACKET_TIMEOUT,
        max_connections=LIMIT,
    )
    await server.start()
    flood: list[asyncio.StreamWriter] = []
    try:
        started = time.monotonic()
        for _ in range(1000):
            _, writer = await asyncio.open_connection("127.0.0.1", server.port)
            flood.append(writer)
        assert time.monotonic() - started < PACKET_TIMEOUT / 2, "flood too slow"
        refused = await register(server.port, alive2_req(b"late"))
        assert refused.reply == b""
        await refused.close()
        deadline = time.monotonic() + PACKET_TIMEOUT + TIMEOUT
        while True:
            node = await register(server.port, alive2_req(b"late"))
            if node.reply:
                break
            await node.close()
            assert time.monotonic() < deadline
            await asyncio.sleep(0.1)
        assert node.reply[:2] == b"y\x00", node.reply
        assert time.monotonic() - started >= PACKET_TIMEOUT * 0.9
        await node.close()
    finally:
        for writer in flood:
            writer.close()
        await server.stop()
