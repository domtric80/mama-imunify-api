#!/usr/bin/env python3
"""Persist only matching scan-finished metadata for the gateway to consume."""

from __future__ import annotations

import json
import os
import sys
import uuid
from pathlib import Path


def main() -> int:
    request_root = Path(os.environ.get("SCAN_TMP_ROOT", "/run/mama-imunify/requests")).resolve()
    event_root = Path(os.environ.get("SCAN_EVENT_ROOT", "/run/mama-imunify/events")).resolve()
    try:
        event = json.load(sys.stdin)
    except (ValueError, OSError):
        return 1
    if not isinstance(event, dict):
        return 1
    path = event.get("path")
    if not isinstance(path, str):
        return 0
    try:
        resolved = Path(path).resolve(strict=True)
        resolved.relative_to(request_root)
    except (OSError, ValueError):
        return 0
    if not resolved.is_dir() or event.get("status") not in ("ok", "failed", "has_errors"):
        return 0

    total_files = event.get("total_files", event.get("total_resources"))
    total_malicious = event.get("total_malicious")
    scan_id = event.get("scan_id")
    if type(total_files) is not int or type(total_malicious) is not int:
        return 0
    if not isinstance(scan_id, (str, int)) or len(str(scan_id)) > 64:
        return 0

    # Keep only fields needed to correlate and normalize the result.
    payload = {
        "path": str(resolved),
        "status": event["status"],
        "scan_id": str(scan_id),
        "total_files": total_files,
        "total_malicious": total_malicious,
        "errors": event.get("errors", event.get("error")),
        "malicious_files": event.get("malicious_files", event.get("files", [])),
    }
    if not isinstance(payload["malicious_files"], list):
        return 0

    event_root.mkdir(mode=0o770, parents=True, exist_ok=True)
    name = f"{uuid.uuid4().hex}.json"
    temporary = event_root / f".{name}.tmp"
    destination = event_root / name
    encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, destination)
    except OSError:
        temporary.unlink(missing_ok=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
