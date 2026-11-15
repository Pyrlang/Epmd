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
- `PORT2_RESP` ends with `Elen`/`Extra` as registered (it stopped after the
  name). `PORT2_REQ` drops one trailing NUL and is closed without a reply
  for an empty name, a NUL inside it, invalid UTF-8 or more than 255
  characters. `EpmdNode` has `extra` and `fd`.
- Creation as in OTP's epmd: a 32-bit counter per name (4..2^32-1, random
  start) that grows by one each time the name registers again (up to 1000
  unregistered names are remembered, and `DUMP_RESP` lists them as
  `old/unused name`); nodes with HighestVersion below 6 get 1..3. It was
  `int(time.time())`, equal for two registrations within a second and 0 in
  the 16-bit reply now and then. See `KNOWN-DIFFERENCES.md`.
- Local-only rules as OTP's epmd: ALIVE2, DUMP, KILL and STOP are served
  only to peers on loopback (127.0.0.0/8, `::1`, IPv4-mapped) or on the
  address they connected to; the old check compared strings and raised
  `TypeError` for other peers. KILL_REQ no longer calls `sys.exit()`: it
  answers `OK` and stops the server (`start_server()` returns), but answers
  `NO` while nodes are registered. STOP_REQ is ignored unless the new
  `Epmd(relaxed_command_check=True)`; then it also closes the node's
  connection, and an unknown name gets `NOEXISTSTOPPED`, as from OTP.
- `NAMES_RESP` and `DUMP_RESP` list the newest registration first;
  `DUMP_RESP` uses OTP's text (`active name     <N> at port P, fd = F`, NUL
  after each line).
- Loggers are named after their modules and no longer set their own level;
  `EpmdError` no longer logs when it is created.
