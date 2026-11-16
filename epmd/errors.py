# Copyright 2018, Erlang Solutions Ltd, and S2HC Sweden AB
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Exceptions of the ``epmd`` package."""

from typing import Any


class EpmdError(Exception):
    """Base class of every error the ``epmd`` package raises."""

    # Extra arguments are passed through to Exception unchanged, hence Any.
    def __init__(self, msg: str, *args: Any, **kwargs: Any) -> None:
        Exception.__init__(self, msg, *args, **kwargs)


class EpmdRequestError(EpmdError):
    """A request a client sent cannot be parsed; the server closes that
    connection without a reply, as OTP's epmd does."""
