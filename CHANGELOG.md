# Changelog

## Unreleased

- Packaging moved from `setup.py` to `pyproject.toml`; Python 3.11 or newer.
- `Epmd.start()` returns once the server listens (`Epmd(port=0)` picks a free
  port, readable as `.port` afterwards); `Epmd.stop()` stops listening and
  closes client connections, and is safe to call twice. `start_server()`
  still serves until cancelled.
- Tests: real Erlang/OTP nodes register in, and find each other through, the
  Python EPMD (`pytest`; `-m erlang` needs Erlang/OTP).
