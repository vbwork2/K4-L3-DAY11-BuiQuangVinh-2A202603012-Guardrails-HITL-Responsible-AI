"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[int, dict] = {}
        self._next_entry_id = 0

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Store the original request and its UTC/performance start times."""
        self._next_entry_id += 1
        self._open[self._next_entry_id] = {
            "user_id": user_id,
            "request_id": request_id,
            "input": text,
            "started_at": utc_now_iso(),
            "started_monotonic": perf_counter(),
        }

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Complete the matching request and append one forensic record."""
        entry_id = None
        if request_id is not None:
            entry_id = next(
                (
                    key
                    for key, entry in self._open.items()
                    if entry["user_id"] == user_id
                    and entry["request_id"] == request_id
                ),
                None,
            )
        else:
            entry_id = next(
                (
                    key
                    for key, entry in reversed(list(self._open.items()))
                    if entry["user_id"] == user_id
                ),
                None,
            )

        pending = self._open.pop(entry_id, None) if entry_id is not None else None
        completed_at = utc_now_iso()
        completed_monotonic = perf_counter()
        latency_ms = (
            max(0.0, completed_monotonic - pending["started_monotonic"]) * 1000
            if pending
            else 0.0
        )

        self.logs.append(
            {
                "user_id": user_id,
                "request_id": (
                    request_id if request_id is not None else
                    pending["request_id"] if pending else None
                ),
                "input": pending["input"] if pending else None,
                "output": text,
                "blocked": bool(blocked),
                "layer": layer,
                "started_at": pending["started_at"] if pending else None,
                "completed_at": completed_at,
                "latency_ms": latency_ms,
            }
        )

    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.logs, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        return path


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
