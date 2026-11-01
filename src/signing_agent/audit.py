"""The audit log: one JSON line per signing request, appended and flushed at once.

It records who asked, when, with which certificate, the SHA-256 of the signed bytes and the
result. It never records the PIN, the API key or the bytes themselves.
"""

from __future__ import annotations

import json
import os
import threading
from datetime import UTC, datetime
from pathlib import Path


class AuditLog:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        path.parent.mkdir(parents=True, exist_ok=True)
        # Created readable by this user only; the log says which certificates signed what.
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        self._file = os.fdopen(fd, "a", encoding="utf-8")

    def record(self, **fields: object) -> None:
        line = json.dumps({"time": datetime.now(UTC).isoformat(timespec="milliseconds"), **fields}, ensure_ascii=False)
        with self._lock:
            self._file.write(line + "\n")
            self._file.flush()

    def close(self) -> None:
        with self._lock:
            self._file.close()
