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
