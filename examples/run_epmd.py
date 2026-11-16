"""Serve EPMD on port 4370 until interrupted.

Erlang nodes use it when they are started with the same port:
``ERL_EPMD_PORT=4370 erl -start_epmd false -name a@127.0.0.1``.
"""

import asyncio
import logging
import sys

from epmd import Epmd


def main(port: int = 4370) -> None:
    # A port other than 4369 leaves an EPMD of Erlang/OTP on this host alone.
    logging.basicConfig(level=logging.INFO)
    server = Epmd(port=port)
    asyncio.run(server.start_server())


if __name__ == "__main__":
    main(*(int(arg) for arg in sys.argv[1:2]))
