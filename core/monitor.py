import queue
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from core.scanner import scan_path
from utils.logger import logger

SETTLE_SECONDS = 2.0   # a file must be quiet this long before we scan it
SEEN_LIMIT = 5000
IGNORED_SUFFIXES = frozenset(
    {".tmp", ".temp", ".crdownload", ".part", ".partial", ".download"}
)


@dataclass
class MonitorEvent:
    kind: str                 # "scan" or "error"
    path: str
    result: object = None     # the scanner's result object
    error: str = ""


class _Handler(FileSystemEventHandler):
    """Translates watchdog events into 'this path changed' notifications."""

    def __init__(self, callback):
        self._callback = callback

    def on_created(self, event):
        if not event.is_directory:
            self._callback(str(event.src_path))

    def on_modified(self, event):
        if not event.is_directory:
            self._callback(str(event.src_path))

    def on_moved(self, event):
        # Browsers download to "x.crdownload", then rename to the real file.
        if not event.is_directory:
            self._callback(str(event.dest_path))


class RealTimeMonitor:
    def __init__(self, exclude=()):
        self.events = queue.Queue()
        self._exclude = [Path(p).resolve() for p in exclude]
        self._observer = None
        self._pending = {}     # path -> time of the latest change event
        self._seen = {}        # path -> (mtime, size) of the last scanned version
        self._lock = threading.Lock()

    @property
    def running(self):
        return self._observer is not None

    def start(self, folders):
        if self.running:
            return

        valid = [Path(f) for f in folders if Path(f).is_dir()]

        if not valid:
            raise ValueError("Add at least one existing folder to protect.")

        handler = _Handler(self._queue_path)
        observer = Observer()

        for folder in valid:
            observer.schedule(handler, str(folder), recursive=True)

        observer.start()
        self._observer = observer

        # Each run gets its own stop flag so an old worker can never
        # be revived by a quick stop -> start.
        stop_flag = threading.Event()
        self._stop_flag = stop_flag
        threading.Thread(target=self._run, args=(stop_flag,), daemon=True).start()

        logger.info("Real-time monitor watching: %s", [str(f) for f in valid])

    def stop(self):
        if not self.running:
            return

        self._stop_flag.set()
        self._observer.stop()
        self._observer.join(timeout=3)
        self._observer = None

        with self._lock:
            self._pending.clear()

    # ---------- internals ----------

    def _is_ignored(self, path):
        file = Path(path)

        if file.suffix.lower() in IGNORED_SUFFIXES or file.name.startswith("~$"):
            return True

        try:
            resolved = file.resolve()
        except OSError:
            return True

        return any(resolved.is_relative_to(ex) for ex in self._exclude)

    def _queue_path(self, path):
        if self._is_ignored(path):
            return

        with self._lock:
            self._pending[path] = time.monotonic()

    def _run(self, stop_flag):
        # wait() returns True when stopped, so this loop ticks twice a second.
        while not stop_flag.wait(0.5):
            now = time.monotonic()

            with self._lock:
                ready = [
                    p for p, t in self._pending.items()
                    if now - t >= SETTLE_SECONDS
                ]
                for p in ready:
                    del self._pending[p]

            for path in ready:
                if stop_flag.is_set():
                    return
                self._scan(path)

    def _scan(self, path):
        try:
            file = Path(path)

            if not file.is_file():      # deleted or renamed before it settled
                return

            stat = file.stat()
            signature = (stat.st_mtime_ns, stat.st_size)

            if self._seen.get(path) == signature:
                return                  # unchanged since we last scanned it

            results = scan_path(path)

            if len(self._seen) > SEEN_LIMIT:
                self._seen.clear()
            self._seen[path] = signature

            for result in results:
                self.events.put(MonitorEvent("scan", path, result))

        except Exception as exc:
            logger.error("Real-time scan failed for %s: %s", path, exc)
            self.events.put(MonitorEvent("error", path, error=str(exc)))