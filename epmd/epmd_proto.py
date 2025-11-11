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
import time
import asyncio
import logging

from struct import pack, unpack

from epmd.errors import EpmdError

logger = logging.getLogger("epmd.server")
logger.setLevel(logging.INFO)

# Registration and queries
EPMD_ALIVE2_REQ = ord("x")  # 120
EPMD_PORT2_REQ = ord("z")  # 122
EPMD_ALIVE2_RESP = ord("y")  # 121
EPMD_PORT2_RESP = ord("w")  # 119
EPMD_NAMES_REQ = ord("n")

# Interactive client command codes
EPMD_DUMP_REQ = ord("d")
EPMD_KILL_REQ = ord("k")
EPMD_STOP_REQ = ord("s")


class EpmdProtocol(asyncio.Protocol):
    """Implements EPMD server protocol, used for Erlang node discovery"""

    def __init__(self, parent):
        self.parent_ = parent
        self.transport_ = None
        self.addr_ = None
        self.unconsumed_data_ = b""

    def connection_lost(self, exc):
        logger.info("Disconnected %s", self.addr_)
        self.parent_.client_disconnect(self)

    def connection_made(self, transport: asyncio.Transport):
        """Connection has been accepted and established (callback)."""
        sock = transport.get_extra_info("socket")
        self.transport_ = transport
        self.addr_ = sock.getpeername()
        logger.info("Incoming from %s", self.addr_)

    def data_received(self, data: bytes) -> None:
        logger.info("Data received from %s: %s", self.addr_, data)
        self.unconsumed_data_ += data
        if len(self.unconsumed_data_) < 2:
            # Not even length is read yet
            return

        (packet_len,) = unpack(">H", self.unconsumed_data_[:2])

        if len(self.unconsumed_data_) < packet_len + 2:
            # Not ready yet, keep reading
            return

        # extract
        packet = self.unconsumed_data_[2 : (2 + packet_len)]

        # trim
        self.unconsumed_data_ = self.unconsumed_data_[(2 + packet_len) :]

        # handle
        self.on_packet(packet)

    def on_packet(self, packet: bytes):
        if packet[0] == EPMD_ALIVE2_REQ:
            return self._epmd_register(packet)
        elif packet[0] == EPMD_PORT2_REQ:
            return self._epmd_port_please(packet)

        LOG.error("Unknown packet %d", packet[0])

    def _epmd_register(self, packet):
        LOG.debug("Incoming ALIVE2_REQ")
        if self.addr_[0] not in ["127.0.0.1", "localhost"]:
            raise EpmdError(
                msg="ALIVE2_REQ coming not from a local address %s" % self.addr_
            )
        if len(packet) < 11:
            # Assume that node name is at least 1 letter
            raise EpmdError(msg="ALIVE2_REQ too short")
        # 1     2       1           1           2           2       2
        # 120   PortNo  NodeType    Protocol    HighestV    LowestV Nlen
        # --------------------------
        # Nlen        2       Elen
        # NodeName    Elen    Extra
        (port, node_type, proto, hi_ver, lo_ver, n_len) = unpack(
            ">HBBHHH", packet[1:11]
        )
        node_name = packet[11 : (11 + n_len)]
        packet = packet[(11 + n_len) :]
        extra = packet[2:]

        node_record = {
            "port": port,
            "node_type": node_type,
            "proto": proto,
            "hi_ver": hi_ver,
            "lo_ver": lo_ver,
            "n_len": n_len,
            "extra": extra,
        }
        logger.info("New node: {} = {}".format(node_name, node_record))
        self.parent_.register(node_name, node_record)
        # ALIVE2_X_RESP
        # 1     1       2
        # 121	Result	Creation
        response = pack(">BBH", EPMD_ALIVE2_RESP, 0, int(time.time()) % 65536)
        self.transport_.write(response)

    def _epmd_port_please(self, packet):
        logger.debug("Incoming PORT2_REQ")
        node_name = packet[1:]
        logger.info("PORT2_REQ for node name: {}".format(node_name))
        node = self.parent_.nodes_.get(node_name, None)
        # 1     1	    2	    1	        1	        2 	            2	            2	    Nlen	    2	    Elen
        # 119	Result	PortNo	NodeType	Protocol	HighestVersion	LowestVersion	Nlen	NodeName	Elen	>Extra
        if node is not None:
            response = pack(
                f">BBHBBHHH{len(node_name)}sH0s",
                EPMD_PORT2_RESP,
                0,
                node["port"],
                node["node_type"],
                node["proto"],
                node["hi_ver"],
                node["lo_ver"],
                node["n_len"],
                node_name,
                0,
                b"",
            )
        else:
            response = pack(">BB", EPMD_PORT2_RESP, 1)
        self.transport_.write(response)
        self.transport_.close()


__all__ = ["EpmdProtocol"]
