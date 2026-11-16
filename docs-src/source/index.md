# Epmd

An Erlang Port Mapper Daemon (EPMD) in Python on asyncio. Erlang nodes
register their name and port in it and look each other up through it, as
they do with the `epmd` program that ships with Erlang/OTP. It follows the
EPMD protocol of Erlang/OTP 25 to 29 and needs Python 3.11 or newer and
nothing outside the standard library.

It is one of three projects that work together and can be used apart:

- [Pyrlang]({{ pyrlang_url }}): an Erlang node in Python.
- [Term]({{ term_url }}): Erlang terms and the External Term Format codec.
- Epmd: this project.

## Installing

```sh
pip install .
```

in a clone of <https://github.com/Pyrlang/Epmd>.

## Running it

From the command line, configured like OTP's `epmd` through the environment
variables `ERL_EPMD_PORT`, `ERL_EPMD_ADDRESS` and
`ERL_EPMD_RELAXED_COMMAND_CHECK`, or through options
(`python -m epmd --help`):

```sh
python -m epmd --port 4370 --address 127.0.0.1
```

Erlang nodes find it through the same variable. Start them with
`-start_epmd false`, or `erl` starts OTP's own `epmd` if nothing answers on
the port:

```sh
ERL_EPMD_PORT=4370 erl -start_epmd false -name a@127.0.0.1
ERL_EPMD_PORT=4370 erl -start_epmd false -name b@127.0.0.1
```

```erlang
(a@127.0.0.1)1> net_adm:ping('b@127.0.0.1').
pong
```

## Using it from Python

`examples/run_epmd.py` serves until it is interrupted:

```{literalinclude} ../../examples/run_epmd.py
:language: python
```

Next to other asyncio code, `await server.start()` returns once the server
listens and `await server.stop()` shuts it down. `Epmd(port=0)` picks a free
port; `server.port` has it after `start()`:

```{literalinclude} ../../examples/embedded_epmd.py
:language: python
```

Where it listens:

- `Epmd()` listens on every IPv4 and IPv6 address.
- `Epmd(host="127.0.0.1")` listens on that address only.
- `Epmd(addresses=["10.0.0.5"])` listens there and on the loopback
  addresses, as OTP's `epmd` does with `ERL_EPMD_ADDRESS`.

The other options (`packet_timeout`, `max_connections`,
`relaxed_command_check`) are described with {py:class}`epmd.Epmd`.

Registering, and the `DUMP`, `KILL` and `STOP` requests, are served only to
clients on the same host, as in OTP.

```{toctree}
:maxdepth: 2
:caption: Contents

reference
known-differences
changelog
```
