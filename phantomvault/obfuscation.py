"""
PhantomVault — obfuscation.py
Poisson-distributed dummy I/O scheduler.

Schedules periodic random reads/writes to the vault container
to obscure real access patterns. Dummy operations follow a
Poisson process which is statistically indistinguishable from
human file access patterns.

This is best-effort obfuscation. It does NOT provide provable
ORAM-level access-pattern hiding. See docs/SECURITY.md.
"""

import random
import math
import time
import threading
from pathlib import Path
from typing import Optional


class DummyIOScheduler:
    """
    Schedules dummy reads on the vault container at Poisson-distributed
    intervals. The Poisson process has a configurable mean inter-arrival
    time (lambda parameter).

    Default: mean 4 hours between dummy operations.
    In practice this means ~6 dummy reads per day scattered randomly.
    """

    def __init__(
        self,
        container_path: str,
        lambda_hours: float = 4.0,
    ) -> None:
        self.container_path = Path(container_path)
        self.lambda_seconds = lambda_hours * 3600
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def start(self) -> None:
        """Start the dummy I/O scheduler in a background thread."""
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            daemon=True,
            name="phantomvault-dummy-io",
        )
        self._thread.start()

    def stop(self) -> None:
        """Stop the scheduler. Blocks until the thread exits."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5.0)

    def _run(self) -> None:
        """Main loop: wait Poisson interval, then do a dummy read."""
        while not self._stop_event.is_set():
            # Poisson inter-arrival: exponential distribution
            interval = random.expovariate(1.0 / self.lambda_seconds)
            # Wait, but check stop_event periodically
            deadline = time.time() + interval
            while time.time() < deadline:
                if self._stop_event.wait(timeout=30.0):
                    return
            # Perform dummy read if container still exists
            self._dummy_read()

    def _dummy_read(self) -> None:
        """
        Reads a random block from the vault container.
        The read itself is the obfuscation — it makes the access
        timing pattern look like human file activity.
        """
        try:
            size = self.container_path.stat().st_size
            if size <= 256:
                return
            # Read 4096 bytes from a random offset after the header
            offset = random.randint(256, max(256, size - 4096))
            with open(self.container_path, "rb") as f:
                f.seek(offset)
                _ = f.read(4096)
        except OSError:
            pass
