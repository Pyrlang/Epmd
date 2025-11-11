import asyncio
import logging

from epmd import Epmd

logging.basicConfig(level=logging.INFO)

server = Epmd(port=4377)
asyncio.run(server.start_server())
