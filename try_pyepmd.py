import asyncio
import logging

from epmd import Epmd

logging.basicConfig(level=logging.DEBUG)

# You can use a custom EPMD port, for example 4370, to not interfere with a regular EPMD possibly running
# Using a custom EPMD port requires running Erlang with environment containing ERL_EPMD_PORT=4370
# in Linux/MacOS this would look like: ERL_EPMD_PORT=4370 erl
server = Epmd(port=4369)
asyncio.run(server.start_server())
