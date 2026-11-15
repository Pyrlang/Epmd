## Installation
Currently the package is in development and can be installed by:

```sh
pip install .
```

## Give A Quick Try
Please check [try_pyepmd.py](try_pyepmd.py) for a quick usage detail. The script starts a `epmd` server written in this package and listens at the given port.

```sh
from epmd import Epmd

# use a custom EPMD port to not interfere with a regular EPMD possibly running
server = Epmd(port=4370) 
asyncio.run(server.start_server())
```

To run it next to other asyncio code, `await server.start()` returns once the
server listens (`Epmd(port=0)` picks a free port, then `server.port` has it)
and `await server.stop()` shuts it down.

`Epmd()` listens on every IPv4 and IPv6 address. `Epmd(host="127.0.0.1")`
listens on that address only; `Epmd(addresses=["10.0.0.5"])` listens there
and on the loopback addresses, as OTP's epmd does with `ERL_EPMD_ADDRESS`.
Other options: `packet_timeout`, `max_connections`, `relaxed_command_check`
(see the `Epmd` docstring). Behaviour that differs from OTP's epmd is listed
in [KNOWN-DIFFERENCES.md](KNOWN-DIFFERENCES.md).

From the command line, configured like OTP's `epmd` through
`ERL_EPMD_PORT`, `ERL_EPMD_ADDRESS` and `ERL_EPMD_RELAXED_COMMAND_CHECK`,
or options (`python -m epmd --help`):

```sh
python -m epmd --port 4370 --address 127.0.0.1
```

Now, use your erlang module with the custom epmd started (running at port 4370) above by:
```sh
ERL_EPMD_PORT=<custom_epmd_port> erl -name <node_name>
```
Example:

1. Starting node `a@127.0.0.1`:
    ```sh
    ERL_EPMD_PORT=4370 erl -name a@127.0.0.1
    ```

2. Starting node `b@127.0.0.1`:
    ```sh
    ERL_EPMD_PORT=4370 erl -name b@127.0.0.1
    ```

3. Connect nodes `a@127.0.0.1` and `b@127.0.0.1`:
    ```erl
    (a@127.0.0.1)1> net_kernel:connect_node('b@127.0.0.1').
    ```
    or, ping by:
    ```erl
    (a@127.0.0.1)1> net_adm:ping('b@127.0.0.1').
    ```

## Ackhowledgements

Thanks to Amit Garu (amitgaru2@gmail.com) for contributing the initial version of Epmd.
