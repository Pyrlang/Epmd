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
from typing import TYPE_CHECKING, Optional

from epmd.epmd_node import EpmdNode

if TYPE_CHECKING:
    from epmd.epmd_proto import EpmdProtocol

logger = logging.getLogger("epmd.server")
logger.setLevel(logging.INFO)


class Epmd:
    """
    Listens on the EPMD protocol port and handles discovery of running
    Erlang nodes on this host.
    """

    EPMD_DEFAULT_PORT = 4369

    def __init__(self, host: str = "0.0.0.0", port: int = EPMD_DEFAULT_PORT) -> None:
        """:param port: port to listen on; 0 picks a free one (see ``start``)."""
        self.port = port
        self.host = host
        self.nodes: dict[bytes, EpmdNode] = {}
        # self.min_version = 5
        # self.max_version = 6
        self.supports_protocol_6 = True
        # The listening server between start() and stop().
        self._server: Optional[asyncio.Server] = None
        # Open client connections, closed by stop(): Server.close() leaves
        # them open before Python 3.13.
        self._connections: set["EpmdProtocol"] = set()

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
        """Attempts to register a node. Returns True if successful, False if the node is already registered."""
        if node_name in self.nodes:
            logger.warning("Node %r already registered", node_name)
            return False
        logger.info("Registering node_name=%r", node_name)
        self.nodes[node_name] = data
        return True

    def unregister(self, node_name: bytes) -> bool:
        """
        Called from EpmdProtocol when a client disconnects or when a STOP command arrives
        (documentation claims this is not used but still implemented).
        Removes the node from the list of nodes.
        """
        if node_name in self.nodes:
            del self.nodes[node_name]
            return True
        return False
