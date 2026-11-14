"""Fixtures for the EPMD server tests (plan step EPMD-01).

- ``epmd_server``: the Python ``Epmd`` listening on a free port of
  127.0.0.1 in the test's event loop; stopped afterwards.
- ``epmd_request``: open a TCP connection, send one length-prefixed request,
  read the reply until the server closes the connection.
- ``otp``: one Erlang/OTP release, parametrized over the test matrix. In WSL
  the matrix comes from ``tools/otp-matrix.sh`` in the Pyrlang workspace
  root, and a missing release fails the tests that need it.
  ``PYRLANG_OTP_BINS="25=/path/bin 26=/path/bin"`` overrides the matrix.
  Elsewhere the ``erl`` on ``PATH`` is used, or the tests skip.
- ``erl_nodes``: starts ``erl -name`` nodes of that release that register
  in ``epmd_server`` and evaluate expressions sent by the test.

The Python server runs in the test's loop, so a test talks to an Erlang node
through ``await node.eval(...)``, which keeps the loop serving EPMD requests.
"""

import asyncio
import itertools
import os
import platform
import queue
import shutil
import struct
import subprocess
import threading
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path

import pytest
import pytest_asyncio

from epmd import Epmd

# The Pyrlang workspace root holds tools/otp-matrix.sh; this repository is
# one level down.
MATRIX_SCRIPT = Path(__file__).resolve().parents[2] / "tools" / "otp-matrix.sh"
EVALUATOR_SRC = Path(__file__).parent / "erl" / "py_eval.erl"

COOKIE = "EPMD_TEST_COOKIE"

# Seconds to wait for a node, a reply or an evaluated expression.
TIMEOUT = 20.0

_names = itertools.count()


def unique_name(prefix: str) -> str:
    """A node name no other test of this run uses."""
    return "%s%d_%d" % (prefix, os.getpid(), next(_names))


IN_WSL = "microsoft" in platform.release().lower() or "WSL_DISTRO_NAME" in os.environ


@pytest_asyncio.fixture
async def epmd_server() -> AsyncIterator[Epmd]:
    """The Python EPMD on a free port of 127.0.0.1 (``.port`` after start)."""
    server = Epmd(host="127.0.0.1", port=0)
    await server.start()
    try:
        yield server
    finally:
        await server.stop()


async def epmd_request(port: int, request: bytes) -> bytes:
    """Send ``request`` with its 2-byte length to EPMD; read until EOF."""
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection("127.0.0.1", port), TIMEOUT
    )
    try:
        writer.write(struct.pack(">H", len(request)) + request)
        await writer.drain()
        return await asyncio.wait_for(reader.read(), TIMEOUT)
    finally:
        writer.close()


# One Erlang/OTP release of the test matrix.
@dataclass(frozen=True)
class OtpRelease:
    label: str  # the test id: major release ("27"), or "path"
    bin_dir: Path | None  # holds erl, erlc; None if unusable
    problem: str = ""  # why bin_dir is None


def _discover() -> list[OtpRelease]:
    env = os.environ.get("PYRLANG_OTP_BINS")
    if env:
        pairs = [p.partition("=") for p in env.replace(",", " ").split()]
        return [OtpRelease(label, Path(path)) for label, _, path in pairs]
    if IN_WSL:
        if not MATRIX_SCRIPT.exists():
            return [OtpRelease("matrix", None, "%s is missing" % MATRIX_SCRIPT)]
        proc = subprocess.run(
            ["bash", "-lc", str(MATRIX_SCRIPT)],
            capture_output=True,
            text=True,
            timeout=60,
        )
        releases = []
        for line in proc.stdout.splitlines():
            label, _, path = line.partition("\t")
            releases.append(OtpRelease(label, Path(path)))
        for line in proc.stderr.splitlines():
            if "is not installed" in line:
                version = line.split()[2]
                releases.append(OtpRelease(version.split(".")[0], None, line))
        return releases or [OtpRelease("matrix", None, "no output: " + proc.stderr)]
    erl = shutil.which("erl")
    if erl is None:
        return [OtpRelease("path", None, "erl (Erlang/OTP) is not on PATH")]
    return [OtpRelease("path", Path(erl).parent)]


RELEASES = _discover()


# A usable release and the directory with py_eval.beam compiled by it.
@dataclass(frozen=True)
class Otp:
    label: str
    bin_dir: Path
    beam_dir: Path

    def tool(self, name: str) -> str:
        """Path of an OTP executable of this release. A Windows install
        keeps ``epmd`` only in ``erts-<vsn>/bin``."""
        dirs = [self.bin_dir] + sorted(self.bin_dir.parent.glob("erts-*/bin"))
        for d in dirs:
            for candidate in (name, name + ".exe"):
                if (d / candidate).exists():
                    return str(d / candidate)
        raise FileNotFoundError("%s not in %s" % (name, self.bin_dir))


@pytest.fixture(scope="session", params=RELEASES, ids=[r.label for r in RELEASES])
def otp(
    request: pytest.FixtureRequest, tmp_path_factory: pytest.TempPathFactory
) -> Otp:
    """One Erlang/OTP release of the matrix (see the module docstring)."""
    release: OtpRelease = request.param
    if release.bin_dir is None:
        if IN_WSL or os.environ.get("PYRLANG_OTP_BINS"):
            pytest.fail(
                "OTP release %s unusable: %s" % (release.label, release.problem)
            )
        pytest.skip(release.problem)
    otp = Otp(release.label, release.bin_dir, tmp_path_factory.mktemp("beam"))
    subprocess.run(
        [otp.tool("erlc"), "-o", str(otp.beam_dir), str(EVALUATOR_SRC)],
        check=True,
        timeout=TIMEOUT,
    )
    return otp


# An expression evaluated by ErlNode raised; the text is the {Class, Reason}.
class ErlEvalError(Exception):
    pass


# A distributed erl process running py_eval, driven over stdin/stdout.
class ErlNode:
    _MARK = "<<<py_eval>>> "

    def __init__(self, otp: Otp, epmd_port: int) -> None:
        self.name = unique_name("erl") + "@127.0.0.1"
        env = dict(os.environ, ERL_EPMD_PORT=str(epmd_port))
        # -start_epmd false: never let erl start an OTP epmd next to ours.
        self.proc_ = subprocess.Popen(
            [otp.tool("erl"), "-noshell", "-start_epmd", "false"]
            + ["-name", self.name, "-setcookie", COOKIE]
            + ["-pa", str(otp.beam_dir), "-s", "py_eval", "main"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            env=env,
        )
        self.replies_: queue.Queue[str | None] = queue.Queue()
        self.log_: list[str] = []
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self) -> None:
        assert self.proc_.stdout is not None
        for line in self.proc_.stdout:
            if line.startswith(self._MARK):
                self.replies_.put(line[len(self._MARK) :].rstrip("\n"))
            else:
                self.log_.append(line.rstrip("\n"))
        self.replies_.put(None)

    def _eval(self, expr: str) -> str:
        assert self.proc_.stdin is not None
        self.proc_.stdin.write(expr.replace("\n", " ") + "\n")
        self.proc_.stdin.flush()
        try:
            reply = self.replies_.get(timeout=TIMEOUT)
        except queue.Empty:
            raise TimeoutError("erl did not answer %r; log: %s" % (expr, self.log()))
        if reply is None:
            raise RuntimeError("erl exited; log: %s" % self.log())
        status, _, text = reply.partition(" ")
        if status != "ok":
            raise ErlEvalError(text)
        return text

    async def eval(self, expr: str) -> str:
        """Evaluate ``expr`` (one line, ending in ``.``); its result as ``~0tp``.

        Runs in a thread so the loop keeps serving EPMD meanwhile.

        :raises ErlEvalError: the expression raised
        """
        return await asyncio.to_thread(self._eval, expr)

    def log(self) -> str:
        """What the node printed besides replies (logger reports)."""
        return "\n".join(self.log_)

    def _stop(self) -> None:
        if self.proc_.stdin is not None and not self.proc_.stdin.closed:
            self.proc_.stdin.close()  # py_eval halts at end of input
        try:
            self.proc_.wait(timeout=TIMEOUT)
        except subprocess.TimeoutExpired:
            self.proc_.kill()
            self.proc_.wait()

    async def stop(self) -> None:
        """Halt the node and wait for the process to exit."""
        await asyncio.to_thread(self._stop)


# What the erl_nodes fixture gives a test: start one more node.
StartNode = Callable[[], Awaitable[ErlNode]]


@pytest_asyncio.fixture
async def erl_nodes(otp: Otp, epmd_server: Epmd) -> AsyncIterator[StartNode]:
    """Start ``erl`` nodes registered in ``epmd_server``: ``await start()``.
    Every node is stopped at the end of the test."""
    started: list[ErlNode] = []

    async def start() -> ErlNode:
        node = ErlNode(otp, epmd_server.port)
        started.append(node)
        assert await node.eval("node().") == "'%s'" % node.name, node.log()
        return node

    try:
        yield start
    finally:
        for node in started:
            await node.stop()
