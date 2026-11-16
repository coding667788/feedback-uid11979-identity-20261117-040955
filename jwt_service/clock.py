"""Injectable clocks.

Time based security decisions (``nbf``/``exp`` and snapshot lifetime) only
ever use these objects.  Wall-clock time is deliberately not consulted in the
verifier so tests can move time exactly and deterministically.
"""

from __future__ import annotations

import threading
import time
from typing import Protocol


class Clock(Protocol):
    def now(self) -> int:
        """Current time as integer seconds since the Unix epoch."""


class SystemClock:
    def now(self) -> int:
        return int(time.time())


class ManualClock:
    """Thread-safe clock whose value only changes when the test says so."""

    def __init__(self, start: int = 1_800_000_000) -> None:
        if type(start) is not int:
            raise TypeError("start must be an int")
        self._now = start
        self._lock = threading.Lock()

    def now(self) -> int:
        with self._lock:
            return self._now

    def set(self, value: int) -> None:
        if type(value) is not int:
            raise TypeError("clock value must be an int")
        with self._lock:
            self._now = value

    def advance(self, seconds: int) -> int:
        if type(seconds) is not int:
            raise TypeError("advance must be an int")
        with self._lock:
            self._now += seconds
            return self._now
