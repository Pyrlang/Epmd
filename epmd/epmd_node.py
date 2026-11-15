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
class EpmdNode:
    """Describes a connected Erlang node."""

    def __init__(
        self,
        node_name: bytes,
        port: int,
        node_type: int,
        proto: int,
        hi_ver: int,
        lo_ver: int,
        fd: int = -1,
        extra: bytes = b"",
    ) -> None:
        self.node_name = node_name
        self.port = port
        self.node_type = node_type
        self.proto = proto
        self.hi_ver = hi_ver
        self.lo_ver = lo_ver
        # Socket descriptor of the registering connection, shown by DUMP_REQ.
        self.fd = fd
        # The Extra field of ALIVE2_REQ, returned unchanged in PORT2_RESP.
        self.extra = extra
        # OTP's cr_counter: 4..2^32-1, set by Epmd.register, advanced by one
        # each time the name is registered again.
        self.cr_counter = 0

    @property
    def creation(self) -> int:
        """Creation sent to the node: the 32-bit counter to a node with
        HighestVersion >= 6, else 1..3 (epmd_srv.c get_creation)."""
        if self.hi_ver >= 6:
            return self.cr_counter
        return self.cr_counter % 3 + 1
