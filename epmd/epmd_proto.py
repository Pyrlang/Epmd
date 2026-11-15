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
import asyncio
import ipaddress
import logging
from struct import unpack_from
from typing import TYPE_CHECKING, Any, Optional

from epmd import epmd_proto_packets as pk
from epmd.epmd_node import EpmdNode
from epmd.errors import EpmdRequestError

if TYPE_CHECKING:
    from epmd.epmd_server import Epmd

logger = logging.getLogger(__name__)


class EpmdProtocol(asyncio.Protocol):
    """One client connection of the EPMD server.

    As in OTP's epmd, a connection carries exactly one request. It is closed
    after the reply, except after a successful ALIVE2_REQ: then it stays
    open, and the node is unregistered when it closes or sends anything
    more. Malformed requests close the connection without a reply.
    """

    EPMD_ALIVE2_REQ = pk.EPMD_ALIVE2_REQ
    EPMD_PORT_PLEASE2_REQ = pk.EPMD_PORT2_REQ
    EPMD_NAMES_REQ = pk.EPMD_NAMES_REQ
    EPMD_KILL_REQ = pk.EPMD_KILL_REQ
    EPMD_DUMP_REQ = pk.EPMD_DUMP_REQ
    EPMD_STOP_REQ = pk.EPMD_STOP_REQ

    ALIVE_NORMAL_NODE_TYPE = 77  # M: normal Erlang node
    ALIVE_HIDDEN_NODE_TYPE = 72  # H: hidden node

    def __init__(self, parent: "Epmd") -> None:
        self.parent: Epmd = parent
        # asyncio calls connection_made before any data_received, so the
        # handlers never see None here.
        self.transport: asyncio.Transport = None  # type: ignore[assignment]  # set in connection_made
        # Peer address from the transport's "peername"; its shape depends on
        # the address family, hence Any.
        self.addr: Any = None
        self.unconsumed_data: bytes = b""
        # Name registered through this connection; b"" if none.
        self.node_name: bytes = b""
        # The node this connection registered, while it is registered.
        self.node_: Optional[EpmdNode] = None
        # Set once the one request of this connection has been handled.
        self.done_: bool = False
        # Closes a connection that sends no complete request in time.
        self.timer_: Optional[asyncio.TimerHandle] = None
        # The peer is on this host; only then are ALIVE2, DUMP, KILL and
        # STOP served.
        self.local_peer: bool = False

    def connection_lost(self, exc: Optional[Exception]) -> None:
        logger.debug("Disconnected %s", self.addr)
        self._cancel_timer()
        self.parent._disconnected(self)
        if self.node_ is not None:
            self.parent._unregister_node(self.node_)
            self.node_ = None

    # create_server always passes a stream Transport, not just a BaseTransport.
    def connection_made(self, transport: asyncio.Transport) -> None:  # type: ignore[override]
        """Connection has been accepted and established (callback)."""
        self.transport = transport
        self.addr = transport.get_extra_info("peername")
        self.local_peer = _is_local_peer(
            self.addr, transport.get_extra_info("sockname")
        )
        logger.debug("Incoming from %s (local: %s)", self.addr, self.local_peer)
        if not self.parent._connected(self):
            # Over the limit: OTP's epmd accepts and closes at once.
            logger.warning("Too many connections, closing %s", self.addr)
            self.done_ = True
            transport.close()
            return
        self.timer_ = asyncio.get_running_loop().call_later(
            self.parent.packet_timeout, self._timed_out
        )

    def _timed_out(self) -> None:
        logger.debug("No complete request from %s in time, closing", self.addr)
        self.timer_ = None
        self.transport.close()

    def _cancel_timer(self) -> None:
        if self.timer_ is not None:
            self.timer_.cancel()
            self.timer_ = None

    def data_received(self, data: bytes) -> None:
        if self.node_ is not None:
            # A registered node sends nothing more; OTP treats any data as
            # the end of the registration.
            logger.debug("Data on the ALIVE connection of %r", self.node_name)
            self.transport.close()
            return
        if self.done_ or self.transport.is_closing():
            return
        self.unconsumed_data += data
        if len(self.unconsumed_data) < 2:
            return
        # Each request is preceded by its 2-byte length.
        (body_len,) = unpack_from(">H", self.unconsumed_data)
        if body_len == 0 or body_len > pk.MAX_REQUEST_LEN:
            logger.debug("Invalid request size %d from %s", body_len, self.addr)
            self.transport.close()
            return
        if len(self.unconsumed_data) > body_len + 2:
            # More than one request: OTP closes rather than queueing.
            logger.debug("Data after the request from %s", self.addr)
            self.transport.close()
            return
        if len(self.unconsumed_data) < body_len + 2:
            return
        body, self.unconsumed_data = self.unconsumed_data[2:], b""
        self.done_ = True
        self._cancel_timer()
        try:
            self.on_packet(body)
        except EpmdRequestError as e:
            logger.debug("Bad request from %s: %s", self.addr, e)
        if self.node_ is None:
            self.transport.close()

    def on_packet(self, packet: bytes) -> None:
        """Answer one request body (without the length prefix).

        :raises EpmdRequestError: the request is malformed.
        """
        code = packet[0]
        if code == pk.EPMD_ALIVE2_REQ:
            return self._on_packet_EPMD_ALIVE2_REQ(packet)
        elif code == pk.EPMD_PORT2_REQ:
            return self._on_packet_EPMD_PORT_PLEASE2_REQ(packet)
        elif code == pk.EPMD_NAMES_REQ:
            return self._on_packet_EPMD_NAMES_REQ(packet)
        elif code == pk.EPMD_KILL_REQ:
            return self._on_packet_EPMD_KILL_REQ(packet)
        elif code == pk.EPMD_DUMP_REQ:
            return self._on_packet_EPMD_DUMP_REQ(packet)
        elif code == pk.EPMD_STOP_REQ:
            return self._on_packet_EPMD_STOP_REQ(packet)
        raise EpmdRequestError("unknown request %d" % code)

    def _on_packet_EPMD_ALIVE2_REQ(self, payload: bytes) -> None:
        """Handle the ALIVE2_REQ packet."""
        self._require_local_peer("ALIVE2_REQ")
        req = pk.decode_alive2_req(payload)
        node = self.parent._register_request(req, self.transport)
        if node is not None:
            creation = node.creation
            self.node_ = node
            self.node_name = req.name
        else:
            creation = 99  # as OTP's epmd_srv.c
        self.transport.write(
            pk.encode_alive2_resp(node is not None, creation, req.hi_ver)
        )

    def _on_packet_EPMD_PORT_PLEASE2_REQ(self, payload: bytes) -> None:
        """Handle the PORT2_REQ packet."""
        name = pk.decode_port2_req(payload)
        node = self.parent.nodes.get(name)
        info = None
        if node is not None:
            info = pk.Port2Info(
                port=node.port,
                node_type=node.node_type,
                proto=node.proto,
                hi_ver=node.hi_ver,
                lo_ver=node.lo_ver,
                name=node.node_name,
                extra=node.extra,
            )
        self.transport.write(pk.encode_port2_resp(info))

    def _on_packet_EPMD_NAMES_REQ(self, payload: bytes) -> None:
        """Handle the NAMES_REQ packet. Return all registered node names."""
        nodes = [(n.node_name, n.port) for n in self.parent._newest_first()]
        self.transport.write(pk.encode_names_resp(self.parent.port, nodes))

    def _require_local_peer(self, request: str) -> None:
        if not self.local_peer:
            raise EpmdRequestError("%s from non-local %s" % (request, self.addr))

    def _on_packet_EPMD_KILL_REQ(self, payload: bytes) -> None:
        """Handle the KILL_REQ packet: stop the server, unless nodes are
        registered and the server does not run with relaxed_command_check."""
        self._require_local_peer("KILL_REQ")
        if self.parent.nodes and not self.parent.relaxed_command_check:
            logger.info("KILL_REQ refused: nodes are registered")
            self.transport.write(b"NO")
            return
        logger.info("KILL_REQ: stopping")
        self.transport.write(b"OK")
        self.transport.close()
        self.parent._kill()

    def _on_packet_EPMD_DUMP_REQ(self, payload: bytes) -> None:
        """Handle the DUMP_REQ packet."""
        self._require_local_peer("DUMP_REQ")
        active = [(n.node_name, n.port, n.fd) for n in self.parent._newest_first()]
        old = [(n.node_name, n.port, n.fd) for n in self.parent._old_nodes()]
        self.transport.write(pk.encode_dump_resp(self.parent.port, active, old))

    def _on_packet_EPMD_STOP_REQ(self, payload: bytes) -> None:
        """Handle the STOP_REQ packet: unregister a name and close its
        node's connection. Only with relaxed_command_check."""
        self._require_local_peer("STOP_REQ")
        if not self.parent.relaxed_command_check:
            raise EpmdRequestError("STOP_REQ without relaxed_command_check")
        if len(payload) <= 1:
            raise EpmdRequestError("STOP_REQ without a node name")
        # OTP reads the name as a C string.
        name = payload[1:].split(b"\0", 1)[0]
        if not self.parent._stop_node(name):
            # OTP's epmd_srv.c falls through after NOEXIST and also sends
            # STOPPED; kept byte for byte.
            self.transport.write(b"NOEXIST")
        self.transport.write(b"STOPPED")


def _is_local_peer(peer: Any, local: Any) -> bool:
    """The peer is on this host: a loopback address (127.0.0.0/8, ::1, also
    IPv4-mapped) or the address it connected to (conn_local_peer_check in
    epmd_srv.c). ``peer`` and ``local`` are socket addresses, or None."""
    try:
        addr = ipaddress.ip_address(peer[0].split("%", 1)[0])
        own = ipaddress.ip_address(local[0].split("%", 1)[0])
    except (TypeError, IndexError, ValueError, AttributeError):
        return False  # OTP: no peer name means not local
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    if isinstance(own, ipaddress.IPv6Address) and own.ipv4_mapped is not None:
        own = own.ipv4_mapped
    return addr.is_loopback or addr == own


__all__ = ["EpmdProtocol"]
