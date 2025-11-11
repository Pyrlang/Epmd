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

from epmd.epmd_node import EpmdNode

logger = logging.getLogger("epmd.server")
logger.setLevel(logging.INFO)


class Epmd:
    """
    Listens on the EPMD protocol port and handles discovery of running
    Erlang nodes on this host.
    """

    EPMD_DEFAULT_PORT = 4369

    def __init__(self, host="0.0.0.0", port=EPMD_DEFAULT_PORT):
        self.port = port
        self.host = host
        self.nodes: dict[bytes, EpmdNode] = {}
        # self.min_version = 5
        # self.max_version = 6
        self.supports_protocol_6 = True

    async def start_server(self):
        """Start listening. This is asynchronous and may fail if the port is
        used. The addrinuse result is not an error and it means that another
        EPMD is running already and it should be used.
        """
        from epmd.epmd_proto import EpmdProtocol

        server = await asyncio.get_event_loop().create_server(
            host=self.host,
            port=self.port,
            protocol_factory=lambda: EpmdProtocol(parent=self),
        )
        logger.info("Listening at %s:%d", self.host, self.port)

        async with server:
            await server.serve_forever()

    def register(self, node_name: bytes, data: dict) -> bool:
        """Attempts to register a node. Returns True if successful, False if the node is already registered."""
        if node_name in self.nodes:
            logger.warning("Node {} already registered".format(node_name))
            return False
        logger.info("Registering node_name={}".format(node_name))
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
