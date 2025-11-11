# Copyright 2018, Erlang Solutions Ltd, and S2HC Sweden AB
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
import sys
import time
import asyncio
import logging

from typing import TYPE_CHECKING

from epmd.epmd_node import EpmdNode

if TYPE_CHECKING:
    from epmd.epmd_server import Epmd

from struct import unpack

from epmd.epmd_proto_packets import (
    EpmdAliveReqPacket,
    EpmdAliveRespPacket,
    EpmdDumpRespPacket,
    EpmdPortPleaseErrorPacket,
    EpmdPortPleaseRespPacket,
    EpmdNamesRespPacket,
)

logger = logging.getLogger("epmd.server")
logger.setLevel(logging.DEBUG)


class EpmdProtocol(asyncio.Protocol):
    """Implements EPMD server protocol, used for Erlang node discovery"""

    EPMD_ALIVE2_REQ = 120
    EPMD_PORT_PLEASE2_REQ = 122
    EPMD_NAMES_REQ = 110
    EPMD_KILL_REQ = 107
    EPMD_DUMP_REQ = 100
    EPMD_STOP_REQ = 115

    ALIVE_NORMAL_NODE_TYPE = 77  # M: normal Erlang node
    ALIVE_HIDDEN_NODE_TYPE = 72  # H: hidden node

    def __init__(self, parent):
        self.parent: Epmd = parent
        self.transport = None
        self.addr = None
        self.unconsumed_data = b""
        self.node_name = b""

    def connection_lost(self, exc):
        logger.info("Disconnected %s", self.addr)
        if len(self.node_name) > 0:
            self.parent.unregister(self.node_name)

    def connection_made(self, transport: asyncio.Transport):
        """Connection has been accepted and established (callback)."""
        sock = transport.get_extra_info("socket")
        self.transport = transport
        self.addr = sock.getpeername()
        logger.info("Incoming from %s", self.addr)
        self.unconsumed_data = b""

    def data_received(self, data: bytes) -> None:
        logger.info("Data received from %s: %s", self.addr, data)
        self.unconsumed_data += data

        # Each request *_REQ is preceded by a 2 byte length field. Thus, the overall
        # request format is:
        # len_bytes:uint16 + request[len_bytes]
        if len(self.unconsumed_data) < 2:
            # Not even length is read yet
            return

        (packet_len,) = unpack(">H", self.unconsumed_data[:2])

        if len(self.unconsumed_data) < packet_len + 2:
            # Not ready yet, keep reading
            return

        # extract packet body
        packet = self.unconsumed_data[2 : (2 + packet_len)]

        # trim the accumulated data
        self.unconsumed_data = self.unconsumed_data[(2 + packet_len) :]

        # handle the packet
        self.on_packet(packet)

    def on_packet(self, packet: bytes):
        if packet[0] == EpmdProtocol.EPMD_ALIVE2_REQ:
            return self._on_packet_EPMD_ALIVE2_REQ(packet)
        elif packet[0] == EpmdProtocol.EPMD_PORT_PLEASE2_REQ:
            return self._on_packet_EPMD_PORT_PLEASE2_REQ(packet)
        elif packet[0] == EpmdProtocol.EPMD_NAMES_REQ:
            return self._on_packet_EPMD_NAMES_REQ(packet)
        elif packet[0] == EpmdProtocol.EPMD_KILL_REQ:
            return self._on_packet_EPMD_KILL_REQ(packet)
        elif packet[0] == EpmdProtocol.EPMD_DUMP_REQ:
            return self._on_packet_EPMD_DUMP_REQ(packet)
        elif packet[0] == EpmdProtocol.EPMD_STOP_REQ:
            return self._on_packet_EPMD_STOP_REQ(packet)

        logger.error("Unknown packet %d", packet[0])

    def _on_packet_EPMD_ALIVE2_REQ(self, payload: bytes):
        """Handle the ALIVE2_REQ packet."""
        logger.debug("Incoming ALIVE2_REQ")
        packet = EpmdAliveReqPacket(self.addr, payload)

        node = EpmdNode(
            node_name=packet.node_name,
            port=packet.port,
            node_type=packet.node_type,
            proto=packet.proto,
            hi_ver=packet.hi_ver,
            lo_ver=packet.lo_ver,
        )
        logger.info("New node: {} = {}".format(packet.node_name, node))

        self.node_name = packet.node_name  # remember the node name for later
        self.supports_protocol_6 = packet.hi_ver >= 6

        if self.parent.register(packet.node_name, node):
            response = EpmdAliveRespPacket(
                success=True,
                creation=int(time.time()),
                use32bit=self.parent.supports_protocol_6 and self.supports_protocol_6,
            )
            self.transport.write(response.data)
        else:
            response = EpmdAliveRespPacket(
                success=False,
                creation=99,  # as in the source of https://github.com/erlang/epmd/blob/master/src/epmd_srv.erl
                use32bit=self.parent.supports_protocol_6 and self.supports_protocol_6,
            )
            self.transport.write(response.data)

    def _on_packet_EPMD_PORT_PLEASE2_REQ(self, payload: bytes):
        """Handle the PORT_PLEASE2_REQ packet."""
        logger.debug("Incoming PORT_PLEASE2_REQ")
        node_name = payload[1:]
        logger.info("PORT_PLEASE2_REQ for node name: {}".format(node_name))
        node = self.parent.nodes.get(node_name, None)

        if node is not None:
            response = EpmdPortPleaseRespPacket(node)
        else:
            response = EpmdPortPleaseErrorPacket()

        self.transport.write(response.data)
        self.transport.close()

    def _on_packet_EPMD_NAMES_REQ(self, payload: bytes):
        """Handle the NAMES_REQ packet. Return all registered node names."""
        logger.debug("Incoming NAMES_REQ")
        response = EpmdNamesRespPacket(
            server_port=self.parent.port, nodes=self.parent.nodes
        )
        self.transport.write(response.data)
        # When all NodeInfo has been written the connection is closed by the EPMD.
        self.transport.close()

    def _on_packet_EPMD_KILL_REQ(self, payload: bytes):
        """Handle the KILL_REQ packet."""
        logger.debug("Incoming KILL_REQ")
        self.transport.write(b"OK")
        self.transport.close()
        sys.exit(0)

    def _on_packet_EPMD_DUMP_REQ(self, payload: bytes):
        """Handle the DUMP_REQ packet."""
        logger.debug("Incoming DUMP_REQ")
        response = EpmdDumpRespPacket(
            server_port=self.parent.port, nodes=self.parent.nodes
        )
        self.transport.write(response.data)
        # When all NodeInfo has been written the connection is closed by the EPMD.
        self.transport.close()

    def _on_packet_EPMD_STOP_REQ(self, payload: bytes):
        """Handle the STOP_REQ packet."""
        logger.debug("Incoming STOP_REQ")
        node_name = payload[1:]
        if self.parent.unregister(node_name):
            self.transport.write(b"STOPPED")
        else:
            self.transport.write(b"NOEXIST")


__all__ = ["EpmdProtocol"]
