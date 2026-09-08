from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any, Optional


class AuditLogger:
    """Append-only JSONL logger that deliberately excludes raw prompt text."""

    def __init__(self, path: Optional[Path]) -> None:
        self.path = path
        self._lock = Lock()

    def record(self, event_type: str, payload: dict[str, Any]) -> None:
        if self.path is None:
            return
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            **payload,
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock, self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, sort_keys=True) + "\n")
