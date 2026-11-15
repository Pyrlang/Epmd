# Copyright 2026, Erlang Solutions Ltd, and S2HC Sweden AB
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
"""``python -m epmd``: run the EPMD server in the foreground, configured
like OTP's ``epmd``: ``ERL_EPMD_PORT``, ``ERL_EPMD_ADDRESS`` and
``ERL_EPMD_RELAXED_COMMAND_CHECK`` apply unless an option overrides them."""

import argparse
import asyncio
import logging
import os
import re
import sys
from collections.abc import Sequence
from typing import Optional

from epmd.epmd_server import Epmd
from epmd.errors import EpmdError


def _parser() -> argparse.ArgumentParser:
    env_port = os.environ.get("ERL_EPMD_PORT")
    parser = argparse.ArgumentParser(
        prog="python -m epmd",
        description="Erlang Port Mapper Daemon (EPMD) in Python.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(env_port) if env_port else Epmd.EPMD_DEFAULT_PORT,
        help="port to listen on (default: $ERL_EPMD_PORT or 4369)",
    )
    parser.add_argument(
        "--address",
        default=os.environ.get("ERL_EPMD_ADDRESS", ""),
        help="comma- or space-separated IP addresses to listen on; loopback "
        "is always added (default: $ERL_EPMD_ADDRESS, else all addresses)",
    )
    parser.add_argument(
        "--relaxed-command-check",
        action="store_true",
        default="ERL_EPMD_RELAXED_COMMAND_CHECK" in os.environ,
        help="allow kill with live nodes and stop of any name "
        "(default: set if $ERL_EPMD_RELAXED_COMMAND_CHECK exists)",
    )
    parser.add_argument(
        "--packet-timeout",
        type=float,
        default=Epmd.DEFAULT_PACKET_TIMEOUT,
        help="seconds a client may take to send its request (default 60)",
    )
    parser.add_argument(
        "--max-connections",
        type=int,
        default=Epmd.DEFAULT_MAX_CONNECTIONS,
        help="open client connections at most (default 1024)",
    )
    parser.add_argument("-d", "--debug", action="store_true", help="log every request")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the server until interrupted or killed; the exit status."""
    try:
        args = _parser().parse_args(argv)
    except ValueError as e:  # a malformed ERL_EPMD_PORT
        print("epmd: ERL_EPMD_PORT: %s" % e, file=sys.stderr)
        return 2
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(name)s: %(message)s",
    )
    server = Epmd(
        port=args.port,
        addresses=[a for a in re.split(r"[ ,]+", args.address) if a],
        packet_timeout=args.packet_timeout,
        relaxed_command_check=args.relaxed_command_check,
        max_connections=args.max_connections,
    )
    try:
        asyncio.run(server.start_server())
    except KeyboardInterrupt:
        pass
    except (OSError, EpmdError) as e:
        print("epmd: %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
