# Known differences from OTP's epmd

Where the Python EPMD behaves differently from `epmd` of the newest
supported OTP release (`erts/epmd/src`). One bullet per difference.

## Registration

- **Start of the creation counter**: a name seen for the first time starts
  from a random 32-bit value; OTP starts from `time()`. Both then add one per
  re-registration of the name (4..2^32-1; 1..3 in `ALIVE2_RESP`). Example:
  `ALIVE2_REQ` for `a` with HighestVersion 6 gets `v, 0, <random>` here and
  `v, 0, <seconds since 1970 + 1>` from OTP. By design (EPMD-04): two
  servers started in the same second do not hand out equal creations.

## Text replies

- **`fd` in `DUMP_RESP`**: the number is the Python socket's `fileno()` (a
  `SOCKET` handle on Windows), not a C file descriptor numbered like OTP's.
  `active name     <a> at port 4370, fd = 812`. Informational only.
