"""Run EPMD inside an asyncio program: start it, use it, stop it."""

import asyncio

from epmd import Epmd


async def main() -> int:
    server = Epmd(host="127.0.0.1", port=0)
    await server.start()
    try:
        # Erlang nodes started with ERL_EPMD_PORT=<port> register here.
        print("EPMD listens on port", server.port)
        return server.port
    finally:
        await server.stop()


if __name__ == "__main__":
    asyncio.run(main())
