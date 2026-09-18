"""Periodic status for the single command running in this process."""

import sys
import threading
import time
from contextlib import contextmanager


class Progress:
    def __init__(self, interval=5):
        self.interval = interval
        self.message = "Starting"
        self.lock = threading.Lock()
        self.stopped = threading.Event()
        self.thread = None

    def update(self, message):
        # Updating a counter does not print a line per file or buffer.
        with self.lock:
            self.message = message

    def heartbeat(self, command, started, output):
        while not self.stopped.wait(self.interval):
            with self.lock:
                message = self.message
            elapsed = int(time.monotonic() - started)
            try:
                output.write(f"[{command} {elapsed}s elapsed] {message}\n")
                output.flush()
            except (OSError, ValueError):
                # A closed progress stream must not interrupt archive work.
                return

    @contextmanager
    def reporting(self, command):
        self.update("Starting")
        self.stopped.clear()
        self.thread = threading.Thread(
            target=self.heartbeat, args=(command, time.monotonic(), sys.stderr),
            name="archivator-progress", daemon=True)
        self.thread.start()
        try:
            yield
        finally:
            self.stopped.set()
            self.thread.join()
            self.thread = None


# The CLI runs one command at a time. This thread only displays status; all
# filesystem, compression, crypto, and recovery work stays on its existing path.
progress = Progress()
