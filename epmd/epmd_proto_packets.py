# Copyright 2025, Erlang Solutions Ltd, and S2HC Sweden AB
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

import logging
from epmd.epmd_node import EpmdNode
from epmd.errors import EpmdError
from struct import unpack, pack

logger = logging.getLogger("epmd.server")
logger.setLevel(logging.DEBUG)


class EpmdAliveReqPacket:
    def __init__(self, self_addr: tuple, packet: bytes):
        """
        Parse the bytes of the ALIVE2_REQ packet.
        """
        logger.debug("Incoming ALIVE2_REQ")
        if self_addr[0] not in ["127.0.0.1", "localhost"]:
            raise EpmdError(
                msg="ALIVE2_REQ must be coming from a local address (got from %s)"
                % self_addr
            )
        if len(packet) < 11:
            # Assume that node name is at least 1 letter
            raise EpmdError(msg="ALIVE2_REQ too short")

        # 120: u8             ALIVE2_REQ
        # PortNo: u16         node port for incoming requests
        # NodeType: u8        77 normal Erlang node, 72 hidden node
        # Protocol: u8        0 - tcp/ip
        # HighestVersion: u16 The highest distribution protocol version this node can handle. The
        #                     value in OTP 23 and later is 6. Older nodes only support version 5.
        # LowestVersion: u16  The lowest distribution version that this node can handle. The value
        #                     in OTP 25 and later is 6 as support for connections to nodes older
        #                     than OTP 23 has been dropped
        # Nlen: u16           The length (in bytes) of field NodeName
        # NodeName: uint8[]   The name of the node (UTF-8 encoded)
        # Elen: u16           The length (in bytes) of field Extra
        # Extra: uint8[]      Extra data
        port, node_type, proto, hi_ver, lo_ver, n_len = unpack(">HBBHHH", packet[1:11])
        self.port: int = port
        self.node_type: int = node_type
        self.proto: int = proto
        self.hi_ver: int = hi_ver
        self.lo_ver: int = lo_ver

        self.n_len: int = n_len
        index: int = 11 + self.n_len
        self.node_name: bytes = packet[11:index]

        self.extra_len: int = unpack(">H", packet[index : index + 2])[0]
        self.extra: bytes = packet[index + 2 :]


class EpmdAliveRespPacket:
    EPMD_ALIVE2_RESP = 121  # 16-bit creation response for dist protocol 5
    EPMD_ALIVE2_X_RESP = 118  # 32-bit creation response for dist protocol 6+

    def __init__(self, success: bool, creation: int, use32bit: bool):
        result = 0 if success else 1
        if use32bit:
            self.data = pack(
                ">BBL", EpmdAliveRespPacket.EPMD_ALIVE2_X_RESP, result, creation
            )
        else:
            self.data = pack(
                ">BBH", EpmdAliveRespPacket.EPMD_ALIVE2_RESP, result, creation % 65536
            )


class EpmdPortPleaseRespPacket:
    """Responds to PORT_PLEASE2_REQ with a success and node information."""

    EPMD_PORT2_RESP = ord("w")  # 119

    def __init__(
        self,
        node: EpmdNode,
    ):
        self.data = (
            pack(
                ">BBHBBHHH",
                EpmdPortPleaseRespPacket.EPMD_PORT2_RESP,
                0,
                node.port,
                node.node_type,
                node.proto,
                node.hi_ver,
                node.lo_ver,
                len(node.node_name),
            )
            + node.node_name
        )


class EpmdPortPleaseErrorPacket:
    """Responds to PORT_PLEASE2_REQ with an error."""

    EPMD_PORT2_RESP = ord("w")  # 119

    def __init__(self):
        self.data = pack(">BB", EpmdPortPleaseErrorPacket.EPMD_PORT2_RESP, 1)


class EpmdNamesRespPacket:
    """Responds to NAMES_REQ with a list of registered node names."""

    def __init__(self, server_port: int, nodes: dict[bytes, EpmdNode]):
        response_text = ""
        for node_name, node in nodes.items():
            # Each node is described by a string formatted like:
            # io:format("name ~ts at port ~p~n", [NodeName, Port]).
            response_text += f"name {node_name.decode('utf-8')} at port {node.port}\n"

        logger.debug("Names response: %s", response_text)

        self.data = pack(">L", server_port) + response_text.encode("utf-8")


class EpmdDumpRespPacket:
    """Responds to DUMP_REQ with a list of registered node names."""

    def __init__(self, server_port: int, nodes: dict[bytes, EpmdNode]):
        response_text = ""
        for node_name, node in nodes.items():
            # io_lib:format("active name     ~ts at port ~p, fd = ~p~n", [NodeName, Port, Fd]).
            # io_lib:format("old/unused name ~ts at port ~p, fd = ~p ~n", [NodeName, Port, Fd]).
            response_text += f"active name     {node_name.decode('utf-8')} at port {node.port}, fd = {0}\n"

        self.data = pack(">L", server_port) + response_text.encode("utf-8")
