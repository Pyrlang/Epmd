# Changelog

## Unreleased

- Packaging moved from `setup.py` to `pyproject.toml`; Python 3.11 or newer.
- `Epmd.start()` returns once the server listens (`Epmd(port=0)` picks a free
  port, readable as `.port` afterwards); `Epmd.stop()` stops listening and
  closes client connections, and is safe to call twice. `start_server()`
  still serves until cancelled.
- Tests: real Erlang/OTP nodes register in, and find each other through, the
  Python EPMD (`pytest`; `-m erlang` needs Erlang/OTP).
- Requests are handled as OTP's epmd does: one request per connection;
  malformed, unknown, oversized (body above 3057 bytes) or pipelined
  requests close the connection without a reply and never raise out of the
  protocol; a connection without a complete request is closed after
  `Epmd(packet_timeout=60.0)` seconds. A refused ALIVE2_REQ (invalid
  UTF-8 or longer than 255 characters, name taken) gets result 1 and
  creation 99; the reply is `ALIVE2_X_RESP` only to nodes with
  HighestVersion 6 or more. Closing a refused registration no longer
  unregisters the node that holds the name.
- `NAMES_RESP` and `DUMP_RESP` list the newest registration first;
  `DUMP_RESP` uses OTP's text (`active name     <N> at port P, fd = F`, NUL
  after each line).
- Loggers are named after their modules and no longer set their own level;
  `EpmdError` no longer logs when it is created.
