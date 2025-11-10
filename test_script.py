import asyncio
import logging

from epmd import Epmd

logging.basicConfig(level=logging.INFO)

server = Epmd(port=5000)
asyncio.run(server.start_server())
