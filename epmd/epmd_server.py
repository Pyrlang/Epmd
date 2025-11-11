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

from typing import Dict

from epmd.epmd_proto import EpmdProtocol

LOG = logging.getLogger("epmd.server")
LOG.setLevel(logging.INFO)


class Epmd:
    """Listens on the EPMD protocol port and handles discovery of running
    Erlang nodes on this host.
    """

    def __init__(self, host="0.0.0.0", port=4369):
        self.port_ = port
        self.host_ = host
        self.nodes_ = {}  # type: Dict[bytes, dict]

    async def start_server(self):
        """Start listening. This is asynchronous and may fail if the port is
        used. The addrinuse result is not an error and it means that another
        EPMD is running already and it should be used.
        """
        server = await asyncio.get_event_loop().create_server(
            host=self.host_,
            port=self.port_,
            protocol_factory=lambda: EpmdProtocol(parent=self),
        )
        LOG.info("Listening at %s:%d", self.host_, self.port_)

        async with server:
            await server.serve_forever()

    def register(self, node_name: bytes, data: dict):
        LOG.info("Registering node_name={}".format(node_name))
        self.nodes_[node_name] = data

    def unregister(self, node_name: bytes):
        if node_name in self.nodes_:
            del self.nodes_[node_name]

    def client_disconnect(self, protocol: EpmdProtocol):
        pass
