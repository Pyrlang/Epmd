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
"""EPMD requests and replies as pure functions over ``bytes``.

Layouts are from ``erl_dist_protocol`` ("EPMD Protocol"); limits and the
handling of malformed requests follow OTP's ``erts/epmd/src/epmd_srv.c``.
A request is the body after the 2-byte length prefix. A decoder raises
``EpmdRequestError`` for a request that OTP's epmd answers by closing the
connection without a reply.
"""

from collections.abc import Iterable
from dataclasses import dataclass
from struct import pack, unpack_from

from epmd.errors import EpmdRequestError

# Request and reply codes (OTP 29 names, erts/epmd/src/epmd.h).
EPMD_ALIVE2_REQ = 120  # 'x'
EPMD_ALIVE2_RESP = 121  # 'y': 16-bit creation, node with HighestVersion < 6
EPMD_ALIVE2_X_RESP = 118  # 'v': 32-bit creation, since OTP 23
EPMD_PORT2_REQ = 122  # 'z'
EPMD_PORT2_RESP = 119  # 'w'
EPMD_NAMES_REQ = 110  # 'n'
EPMD_DUMP_REQ = 100  # 'd'
EPMD_KILL_REQ = 107  # 'k'
EPMD_STOP_REQ = 115  # 's'

# Longest node name or Extra in bytes: 255 characters of up to 4 bytes
# (MAXSYMLEN in epmd_int.h).
MAXSYMLEN = 255 * 4
# Longest node name in characters.
MAX_NAME_CHARS = 255
# OTP's receive buffer (INBUF_SIZE); a request whose length prefix plus body
# does not fit in it closes the connection.
INBUF_SIZE = 3 * MAXSYMLEN
# Largest accepted request body (length prefix value).
MAX_REQUEST_LEN = INBUF_SIZE - 3

# Fixed part of ALIVE2_REQ before NodeName: code, PortNo, NodeType,
# Protocol, HighestVersion, LowestVersion, Nlen.
_ALIVE2_HEAD = ">BHBBHHH"
_ALIVE2_HEAD_LEN = 11


def name_chars(name: bytes) -> int:
    """Number of characters in a node name, or -1 if it is not valid UTF-8
    (overlong forms and surrogates are invalid, as in OTP's verify_utf8)."""
    try:
        return len(name.decode("utf-8"))
    except UnicodeDecodeError:
        return -1


# A parsed ALIVE2_REQ: what a node registers.
@dataclass(frozen=True)
class Alive2Req:
    port: int
    node_type: int
    proto: int
    hi_ver: int
    lo_ver: int
    name: bytes
    extra: bytes


def decode_alive2_req(body: bytes) -> Alive2Req:
    """Parse an ALIVE2_REQ body. Bytes after ``Extra`` are ignored.

    :raises EpmdRequestError: too short, a length field beyond the end, or a
        NUL byte in the name (OTP closes the connection without a reply).
    """
    # At least one byte of node name plus the 2-byte Elen.
    if len(body) <= _ALIVE2_HEAD_LEN + 2:
        raise EpmdRequestError("ALIVE2_REQ too short (%d bytes)" % len(body))
    _, port, node_type, proto, hi_ver, lo_ver, nlen = unpack_from(_ALIVE2_HEAD, body)
    if _ALIVE2_HEAD_LEN + nlen + 2 > len(body):
        raise EpmdRequestError("ALIVE2_REQ node name length %d too large" % nlen)
    name = body[_ALIVE2_HEAD_LEN : _ALIVE2_HEAD_LEN + nlen]
    extra_at = _ALIVE2_HEAD_LEN + nlen + 2
    (elen,) = unpack_from(">H", body, extra_at - 2)
    if extra_at + elen > len(body):
        raise EpmdRequestError("ALIVE2_REQ extra length %d too large" % elen)
    if b"\0" in name:
        raise EpmdRequestError("ALIVE2_REQ node name contains a NUL byte")
    return Alive2Req(
        port=port,
        node_type=node_type,
        proto=proto,
        hi_ver=hi_ver,
        lo_ver=lo_ver,
        name=name,
        extra=body[extra_at : extra_at + elen],
    )


def encode_alive2_resp(ok: bool, creation: int, hi_ver: int) -> bytes:
    """ALIVE2_X_RESP (32-bit creation) to a node with HighestVersion >= 6,
    else ALIVE2_RESP (16-bit creation)."""
    result = 0 if ok else 1
    if hi_ver >= 6:
        return pack(">BBI", EPMD_ALIVE2_X_RESP, result, creation & 0xFFFFFFFF)
    return pack(">BBH", EPMD_ALIVE2_RESP, result, creation & 0xFFFF)


def decode_port2_req(body: bytes) -> bytes:
    """The node name asked for in a PORT2_REQ body. One trailing NUL is
    dropped, as old clients send it.

    :raises EpmdRequestError: empty name, a NUL inside it, invalid UTF-8 or
        more than 255 characters (OTP closes without a reply).
    """
    name = body[1:]
    if name.endswith(b"\0"):
        name = name[:-1]
    if not name:
        raise EpmdRequestError("PORT2_REQ without a node name")
    if b"\0" in name:
        raise EpmdRequestError("PORT2_REQ node name contains a NUL byte")
    if not 1 <= name_chars(name) <= MAX_NAME_CHARS:
        raise EpmdRequestError("PORT2_REQ node name is invalid")
    return name


# What a PORT2_RESP describes: one registered node.
@dataclass(frozen=True)
class Port2Info:
    port: int
    node_type: int
    proto: int
    hi_ver: int
    lo_ver: int
    name: bytes


def encode_port2_resp(node: Port2Info | None) -> bytes:
    """PORT2_RESP: the node's entry, or result 1 if it is not registered."""
    if node is None:
        return pack(">BB", EPMD_PORT2_RESP, 1)
    return (
        pack(
            ">BBHBBHHH",
            EPMD_PORT2_RESP,
            0,
            node.port,
            node.node_type,
            node.proto,
            node.hi_ver,
            node.lo_ver,
            len(node.name),
        )
        + node.name
    )


def encode_names_resp(epmd_port: int, nodes: Iterable[tuple[bytes, int]]) -> bytes:
    """NAMES_RESP: EPMDPortNo:32, then ``name N at port P\\n`` per
    ``(name, port)``. Parsed by ``erl_epmd``; keep the text exact."""
    lines = b"".join(b"name %s at port %d\n" % (n, p) for n, p in nodes)
    return pack(">I", epmd_port) + lines


def encode_dump_resp(
    epmd_port: int,
    active: Iterable[tuple[bytes, int, int]],
    old: Iterable[tuple[bytes, int, int]],
) -> bytes:
    """DUMP_RESP: EPMDPortNo:32, then one NUL-terminated line per
    ``(name, port, fd)``: registered nodes, then names kept from earlier
    registrations. The text, the NULs included, is what OTP's epmd sends."""
    lines = [b"active name     <%s> at port %d, fd = %d\n\0" % a for a in active]
    lines += [b"old/unused name <%s>, port = %d, fd = %d \n\0" % o for o in old]
    return pack(">I", epmd_port) + b"".join(lines)
