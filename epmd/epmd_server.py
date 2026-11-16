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
"""The EPMD server and its table of registered nodes."""

import asyncio
import errno
import ipaddress
import logging
import secrets
from collections import OrderedDict
from collections.abc import Iterator, Sequence
from typing import TYPE_CHECKING, Optional

from epmd import epmd_proto_packets as pk
from epmd.epmd_node import EpmdNode
from epmd.errors import EpmdError

if TYPE_CHECKING:
    from epmd.epmd_proto import EpmdProtocol

logger = logging.getLogger(__name__)

# Unregistered names remembered for their creation; above this a new name
# drops the oldest (MAX_UNREG_COUNT in epmd_int.h).
MAX_UNREG_COUNT = 1000
# OTP's limit on listening sockets; two are kept for the loopback addresses.
MAX_LISTEN_SOCKETS = 16


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
    # Open client connections at most; OTP's epmd is bound by FD_SETSIZE,
    # 1024 on Linux and, since ERTS 16.0.2, on Windows.
    DEFAULT_MAX_CONNECTIONS = 1024

    def __init__(
        self,
        host: Optional[str] = None,
        port: int = EPMD_DEFAULT_PORT,
        *,
        addresses: Optional[Sequence[str]] = None,
        packet_timeout: float = DEFAULT_PACKET_TIMEOUT,
        relaxed_command_check: bool = False,
        max_connections: int = DEFAULT_MAX_CONNECTIONS,
    ) -> None:
        """Where it listens: on ``host`` only, if given; else on
        ``addresses`` (IP literals, as OTP's ``ERL_EPMD_ADDRESS``) plus the
        IPv4 and IPv6 loopback addresses, which are skipped if they cannot be
        bound; else on every IPv4 and IPv6 address (IPv6 skipped if the host
        has none).

        :param port: port to listen on; 0 picks a free one (see ``start``).
        :param packet_timeout: seconds after which a connection that has not
            sent a complete request is closed (registered nodes are exempt).
        :param max_connections: open client connections, registered nodes
            included; one more is accepted and closed at once.
        :param relaxed_command_check: as OTP's ``epmd
            -relaxed_command_check``: KILL_REQ stops the server even while
            nodes are registered, and STOP_REQ may unregister any name.
            Without it KILL_REQ is refused (``NO``) while nodes are
            registered and STOP_REQ is ignored. Both are always refused to
            peers on other hosts.
        """
        self.port = port
        self.host = host
        self.addresses: list[str] = list(addresses or [])
        self.packet_timeout = packet_timeout
        self.relaxed_command_check = relaxed_command_check
        self.max_connections = max_connections
        self.nodes: dict[bytes, EpmdNode] = {}
        # Unused; kept for compatibility. The reply to ALIVE2_REQ follows the
        # node's HighestVersion, as in OTP.
        self.supports_protocol_6 = True
        # One listening server per bound address, between start() and stop().
        self._servers: list[asyncio.Server] = []
        # Open client connections, closed by stop(): Server.close() leaves
        # them open before Python 3.13.
        self._connections: set["EpmdProtocol"] = set()
        # Unregistered nodes, oldest first, so that a name registered again
        # gets the next creation (OTP's "unreg" list).
        self._unregistered: OrderedDict[bytes, EpmdNode] = OrderedDict()
        # Set by stop(); start_server() waits for it.
        self._stopped: Optional[asyncio.Event] = None
        # The stop() started by a KILL_REQ, referenced until it is done.
        self._kill_task: Optional[asyncio.Task[None]] = None

    async def start(self) -> None:
        """Start listening and return once the socket listens.

        Afterwards ``self.port`` is the bound port (useful with ``port=0``;
        every address then gets the port the first one got).

        :raises OSError: the port is in use, typically by another EPMD, or a
            required address cannot be bound.
        :raises EpmdError: an entry of ``addresses`` is not an IP address,
            or there are more than 13.
        """
        if self._servers:
            return
        from epmd.epmd_proto import EpmdProtocol

        loop = asyncio.get_running_loop()
        servers: list[asyncio.Server] = []
        try:
            for host, required in self._listen_addresses():
                try:
                    server = await loop.create_server(
                        lambda: EpmdProtocol(parent=self), host=host, port=self.port
                    )
                except OSError as e:
                    # OTP exits on EADDRINUSE for any address.
                    if required or e.errno == errno.EADDRINUSE:
                        raise
                    logger.info("Not listening on %s: %s", host, e)
                    continue
                servers.append(server)
                self.port = server.sockets[0].getsockname()[1]
                logger.info("Listening at %s port %d", host, self.port)
        except BaseException:
            for server in servers:
                server.close()
            raise
        if not servers:
            raise EpmdError("unable to bind any address")
        self._servers = servers
        self._stopped = asyncio.Event()
        self._kill_task = None

    def _listen_addresses(self) -> list[tuple[str, bool]]:
        """``(address, required)`` pairs to bind (run() in epmd_srv.c)."""
        if self.host is not None:
            return [(self.host, True)]
        if not self.addresses:
            return [("0.0.0.0", True), ("::", False)]
        result = []
        v4_covered = v6_covered = False
        for text in self.addresses:
            try:
                addr = ipaddress.ip_address(text)
            except ValueError:
                raise EpmdError("cannot parse IP address %r" % text) from None
            covered = addr.is_loopback or addr.is_unspecified
            if addr.version == 4:
                v4_covered |= covered
            else:
                v6_covered |= covered
            result.append((str(addr), True))
        if len(result) >= MAX_LISTEN_SOCKETS - 2:
            raise EpmdError(
                "cannot listen on more than %d IP addresses" % (MAX_LISTEN_SOCKETS - 2)
            )
        # Loopback is always served; the stack may lack one family.
        if not v4_covered:
            result.append(("127.0.0.1", False))
        if not v6_covered:
            result.append(("::1", False))
        return result

    async def stop(self) -> None:
        """Stop listening and close every client connection. Registered
        nodes are forgotten. Calling it again, or before ``start``, is safe.
        """
        servers, self._servers = self._servers, []
        if not servers:
            return
        for server in servers:
            server.close()
        for conn in list(self._connections):
            conn.transport.close()
        for server in servers:
            await server.wait_closed()
        if self._stopped is not None:
            self._stopped.set()
        logger.info("Stopped listening on port %d", self.port)

    async def start_server(self) -> None:
        """Start listening and serve until cancelled or stopped (``stop()``
        or a KILL_REQ); then stop.

        :raises OSError: the port is in use, typically by another EPMD.
        """
        await self.start()
        assert self._stopped is not None
        try:
            await self._stopped.wait()
        finally:
            await self.stop()

    def _kill(self) -> None:
        """Stop the server after a KILL_REQ (from a protocol callback)."""
        if self._kill_task is None:
            self._kill_task = asyncio.get_running_loop().create_task(self.stop())

    def _stop_node(self, node_name: bytes) -> bool:
        """STOP_REQ: unregister ``node_name`` and close the connection that
        registered it. False if it is not registered."""
        node = self.nodes.get(node_name)
        if node is None or not self.unregister(node_name):
            return False
        for conn in list(self._connections):
            if conn.node_ is node:
                conn.node_ = None
                conn.transport.close()
        return True

    def _connected(self, conn: "EpmdProtocol") -> bool:
        """Track a new connection; False if it is over ``max_connections``."""
        if len(self._connections) >= self.max_connections:
            return False
        self._connections.add(conn)
        return True

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
