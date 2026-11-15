# Copyright 2019, Erlang Solutions Ltd, and S2HC Sweden AB
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import asyncio
import logging
import secrets
from collections import OrderedDict
from collections.abc import Iterator
from typing import TYPE_CHECKING, Optional

from epmd import epmd_proto_packets as pk
from epmd.epmd_node import EpmdNode

if TYPE_CHECKING:
    from epmd.epmd_proto import EpmdProtocol

logger = logging.getLogger(__name__)

# Unregistered names remembered for their creation; above this a new name
# drops the oldest (MAX_UNREG_COUNT in epmd_int.h).
MAX_UNREG_COUNT = 1000


def _bump_creation(counter: int) -> int:
    """The next creation counter, 4..2^32-1 (epmd_srv.c bump_creation); 0..3
    are skipped because OTP gives them special meaning."""
    counter = (counter + 1) & 0xFFFFFFFF
    return counter if counter >= 4 else 4


class Epmd:
    """
    Listens on the EPMD protocol port and handles discovery of running
    Erlang nodes on this host.
    """

    EPMD_DEFAULT_PORT = 4369
    # Seconds a connection may take to send its request (OTP's default
    # -packet_timeout, CLOSE_TIMEOUT in epmd_int.h).
    DEFAULT_PACKET_TIMEOUT = 60.0

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = EPMD_DEFAULT_PORT,
        *,
        packet_timeout: float = DEFAULT_PACKET_TIMEOUT,
    ) -> None:
        """:param port: port to listen on; 0 picks a free one (see ``start``).
        :param packet_timeout: seconds after which a connection that has not
            sent a complete request is closed (registered nodes are exempt).
        """
        self.port = port
        self.host = host
        self.packet_timeout = packet_timeout
        self.nodes: dict[bytes, EpmdNode] = {}
        # Unused; kept for compatibility. The reply to ALIVE2_REQ follows the
        # node's HighestVersion, as in OTP.
        self.supports_protocol_6 = True
        # The listening server between start() and stop().
        self._server: Optional[asyncio.Server] = None
        # Open client connections, closed by stop(): Server.close() leaves
        # them open before Python 3.13.
        self._connections: set["EpmdProtocol"] = set()
        # Unregistered nodes, oldest first, so that a name registered again
        # gets the next creation (OTP's "unreg" list).
        self._unregistered: OrderedDict[bytes, EpmdNode] = OrderedDict()

    async def start(self) -> None:
        """Start listening and return once the socket listens.

        Afterwards ``self.port`` is the bound port (useful with ``port=0``).

        :raises OSError: the port is in use, typically by another EPMD.
        """
        if self._server is not None:
            return
        from epmd.epmd_proto import EpmdProtocol

        self._server = await asyncio.get_running_loop().create_server(
            host=self.host,
            port=self.port,
            protocol_factory=lambda: EpmdProtocol(parent=self),
        )
        self.port = self._server.sockets[0].getsockname()[1]
        logger.info("Listening at %s:%d", self.host, self.port)

    async def stop(self) -> None:
        """Stop listening and close every client connection. Registered
        nodes are forgotten. Calling it again, or before ``start``, is safe.
        """
        server, self._server = self._server, None
        if server is None:
            return
        server.close()
        for conn in list(self._connections):
            conn.transport.close()
        await server.wait_closed()
        logger.info("Stopped listening at %s:%d", self.host, self.port)

    async def start_server(self) -> None:
        """Start listening and serve until cancelled; then stop.

        :raises OSError: the port is in use, typically by another EPMD.
        """
        await self.start()
        assert self._server is not None
        try:
            await self._server.serve_forever()
        finally:
            await self.stop()

    def _connected(self, conn: "EpmdProtocol") -> None:
        self._connections.add(conn)

    def _disconnected(self, conn: "EpmdProtocol") -> None:
        self._connections.discard(conn)

    def register(self, node_name: bytes, data: EpmdNode) -> bool:
        """Attempts to register a node. Returns True if successful, False if the node is already registered.

        Sets ``data.cr_counter``: one more than at the name's previous
        registration if it is remembered, else a random start.
        """
        if node_name in self.nodes:
            logger.info("Node %r already registered", node_name)
            return False
        old = self._unregistered.pop(node_name, None)
        if old is not None:
            counter = old.cr_counter
        else:
            if len(self._unregistered) > MAX_UNREG_COUNT:
                self._unregistered.popitem(last=False)
            counter = secrets.randbits(32)
        data.cr_counter = _bump_creation(counter)
        logger.info("Registering node_name=%r", node_name)
        self.nodes[node_name] = data
        return True

    def unregister(self, node_name: bytes) -> bool:
        """
        Called from EpmdProtocol when a client disconnects or when a STOP command arrives
        (documentation claims this is not used but still implemented).
        Removes the node from the list of nodes.
        """
        node = self.nodes.pop(node_name, None)
        if node is None:
            return False
        logger.info("Unregistering node_name=%r", node_name)
        # Remembered for its next creation and listed by DUMP_REQ.
        self._unregistered[node_name] = node
        return True

    def _register_request(
        self, req: pk.Alive2Req, transport: asyncio.BaseTransport
    ) -> Optional[EpmdNode]:
        """Register the node of an ALIVE2_REQ; None if OTP's epmd refuses it
        (invalid name or Extra, name taken)."""
        if len(req.name) > pk.MAXSYMLEN:
            logger.info("Node name too long (%d bytes)", len(req.name))
            return None
        chars = pk.name_chars(req.name)
        if chars < 0 or chars > pk.MAX_NAME_CHARS:
            logger.info("Node name %r is invalid or too long", req.name)
            return None
        if len(req.extra) > pk.MAXSYMLEN:
            logger.info("Extra too long (%d bytes)", len(req.extra))
            return None
        sock = transport.get_extra_info("socket")
        node = EpmdNode(
            node_name=req.name,
            port=req.port,
            node_type=req.node_type,
            proto=req.proto,
            hi_ver=req.hi_ver,
            lo_ver=req.lo_ver,
            fd=sock.fileno() if sock is not None else -1,
            extra=req.extra,
        )
        return node if self.register(req.name, node) else None

    def _unregister_node(self, node: EpmdNode) -> None:
        """Unregister ``node`` if its name is still registered to it."""
        if self.nodes.get(node.node_name) is node:
            self.unregister(node.node_name)

    def _newest_first(self) -> Iterator[EpmdNode]:
        """Registered nodes, the latest registration first (OTP's order)."""
        return reversed(list(self.nodes.values()))

    def _old_nodes(self) -> Iterator[EpmdNode]:
        """Unregistered nodes still remembered, the oldest first."""
        return iter(list(self._unregistered.values()))
