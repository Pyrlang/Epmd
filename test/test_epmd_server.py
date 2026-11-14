"""The Python EPMD serves real Erlang nodes (plan step EPMD-01).

Black-box: Erlang/OTP nodes of each matrix release register in the Python
``Epmd``, look each other up through it, and OTP's own ``epmd -names``
client reads its name list.
"""

import asyncio
import re
import struct
import subprocess
import time

import pytest
from conftest import TIMEOUT, ErlNode, Otp, StartNode, epmd_request

from epmd import Epmd

# NAMES_REQ (erl_dist_protocol, "EPMD Protocol").
EPMD_NAMES_REQ = bytes([110])


def _short(node: ErlNode) -> str:
    return node.name.split("@")[0]


async def _otp_epmd_names(otp: Otp, port: int) -> str:
    """What OTP's ``epmd -port N -names`` prints for our server."""
    proc = await asyncio.to_thread(
        subprocess.run,
        [otp.tool("epmd"), "-port", str(port), "-names"],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        stdin=subprocess.DEVNULL,
    )
    return proc.stdout


@pytest.mark.asyncio
async def test_start_on_port_0_and_stop() -> None:
    """``start`` returns once listening on a free port; ``stop`` closes it
    and may be called twice."""
    server = Epmd(host="127.0.0.1", port=0)
    await server.start()
    try:
        assert server.port != 0
        reply = await epmd_request(server.port, EPMD_NAMES_REQ)
        assert reply == struct.pack(">I", server.port)  # no names yet
    finally:
        await server.stop()
    await server.stop()
    with pytest.raises(OSError):
        await epmd_request(server.port, EPMD_NAMES_REQ)


@pytest.mark.erlang
@pytest.mark.asyncio
async def test_node_registers(
    otp: Otp, epmd_server: Epmd, erl_nodes: StartNode
) -> None:
    """A started node is listed by ``net_adm:names/1`` and by OTP's
    ``epmd -names``."""
    node = await erl_nodes()
    # The server listens on 127.0.0.1 only; names() alone asks the address of
    # the host name.
    names = await node.eval("net_adm:names('127.0.0.1').")
    assert re.fullmatch(r'\{ok,\[\{"%s",\d+\}\]\}' % _short(node), names), names
    listed = await _otp_epmd_names(otp, epmd_server.port)
    assert re.search(r"^name %s at port \d+$" % _short(node), listed, re.M), listed


@pytest.mark.erlang
@pytest.mark.asyncio
async def test_nodes_find_each_other(erl_nodes: StartNode) -> None:
    """``erl_epmd:port_please/2`` answers with the node's port, and a second
    node reaches the first through it."""
    a = await erl_nodes()
    b = await erl_nodes()
    reply = await b.eval('erl_epmd:port_please("%s", "127.0.0.1").' % _short(a))
    assert re.fullmatch(r"\{port,\d+,6\}", reply), reply
    assert await b.eval("net_adm:ping('%s')." % a.name) == "pong", a.log() + b.log()


@pytest.mark.erlang
@pytest.mark.asyncio
async def test_stopped_node_is_removed(
    otp: Otp, epmd_server: Epmd, erl_nodes: StartNode
) -> None:
    """When a node stops, its name disappears; other names stay."""
    a = await erl_nodes()
    b = await erl_nodes()
    await a.stop()
    deadline = time.monotonic() + TIMEOUT
    while True:
        listed = await _otp_epmd_names(otp, epmd_server.port)
        if "name %s " % _short(a) not in listed:
            break
        assert time.monotonic() < deadline, listed
        await asyncio.sleep(0.1)
    assert "name %s " % _short(b) in listed, listed
