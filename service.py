#!/usr/bin/env python3
"""Small mTLS gateway from MaMa to a local ImunifyAV installation."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import ssl
import subprocess
import tempfile
import time
try:
    import grp
except ImportError:  # pragma: no cover - Linux runtime only
    grp = None
from threading import BoundedSemaphore
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Protocol


LOG = logging.getLogger("mama_imunify")
MAX_FILE_BYTES = int(os.environ.get("MAX_FILE_BYTES", str(32 * 1024 * 1024)))
SCAN_TIMEOUT_SECONDS = int(os.environ.get("SCAN_TIMEOUT_SECONDS", "180"))
START_TIMEOUT_SECONDS = int(os.environ.get("START_TIMEOUT_SECONDS", "20"))
MAX_CONCURRENT_SCANS = max(1, int(os.environ.get("MAX_CONCURRENT_SCANS", "2")))
REQUEST_TIMEOUT_SECONDS = int(os.environ.get("REQUEST_TIMEOUT_SECONDS", "30"))
ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
SHA_RE = re.compile(r"^[a-f0-9]{64}$")
ID_FIELDS = ("tenant", "site", "environment", "batch", "observation")
IMUNIFY_GROUP = os.environ.get("IMUNIFY_GROUP", "_imunify")


class BackendFailure(Exception):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


class ScannerBackend(Protocol):
    def scan(self, path: Path) -> dict[str, Any]: ...


def _event_findings(event: dict[str, Any]) -> list[dict[str, str]]:
    raw = event.get("malicious_files", event.get("files", []))
    if not isinstance(raw, list):
        raise BackendFailure("invalid_scanner_result")
    findings = []
    for item in raw:
        if not isinstance(item, dict):
            raise BackendFailure("invalid_scanner_result")
        rule = item.get("type")
        if not isinstance(rule, str) or not rule or len(rule) > 256:
            raise BackendFailure("invalid_scanner_result")
        findings.append({"rule": rule})
    return findings


class ImunifyCliBackend:
    """Uses documented on-demand scans and a CUSTOM_SCAN_FINISHED hook spool."""

    def __init__(self, cli: str, request_root: Path, event_root: Path,
                 timeout: int = SCAN_TIMEOUT_SECONDS,
                 start_timeout: int = START_TIMEOUT_SECONDS):
        self.cli = cli
        self.request_root = request_root.resolve()
        self.event_root = event_root.resolve()
        self.timeout = timeout
        self.start_timeout = start_timeout

    def scan(self, path: Path) -> dict[str, Any]:
        scan_dir = path.parent.resolve()
        if self.request_root not in scan_dir.parents or not path.is_file() or path.is_symlink():
            raise BackendFailure("invalid_scan_path")

        try:
            started = subprocess.run(
                [self.cli, "malware", "on-demand", "start", "--path", str(scan_dir),
                 "--no-follow-symlinks", "--intensity-cpu", "1", "--intensity-io", "1"],
                stdin=subprocess.DEVNULL, capture_output=True, text=True,
                timeout=self.start_timeout, check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise BackendFailure("engine_start_timeout") from exc
        except OSError as exc:
            raise BackendFailure("engine_unavailable") from exc
        if started.returncode != 0:
            raise BackendFailure("engine_start_failed")

        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            for event_file in self.event_root.glob("*.json"):
                try:
                    event = json.loads(event_file.read_text(encoding="utf-8"))
                    event_path = event.get("path")
                    if not isinstance(event_path, str) or Path(event_path).resolve() != scan_dir:
                        self._discard_orphan_event(event_file, event)
                        continue
                    event_file.unlink(missing_ok=True)
                    return self._normalize(event)
                except (OSError, json.JSONDecodeError):
                    continue
            time.sleep(0.2)
        raise BackendFailure("engine_timeout")

    def _discard_orphan_event(self, event_file: Path, event: Any) -> None:
        if not isinstance(event, dict) or not isinstance(event.get("path"), str):
            return
        try:
            event_path = Path(event["path"]).resolve()
            event_path.relative_to(self.request_root)
            if not event_path.exists():
                event_file.unlink(missing_ok=True)
        except (OSError, ValueError):
            return

    @staticmethod
    def _normalize(event: dict[str, Any]) -> dict[str, Any]:
        status = event.get("status")
        errors = event.get("errors", event.get("error"))
        total_files = event.get("total_files", event.get("total_resources"))
        total_malicious = event.get("total_malicious")
        if status != "ok" or errors not in (None, [], ""):
            return {"status": "not_evaluated", "reason": "engine_scan_failed",
                    "scan_id": _safe_scan_id(event.get("scan_id")), "findings": []}
        if type(total_files) is not int or total_files != 1:
            return {"status": "not_evaluated", "reason": "engine_file_count_mismatch",
                    "scan_id": _safe_scan_id(event.get("scan_id")), "findings": []}
        if type(total_malicious) is not int or total_malicious < 0:
            return {"status": "not_evaluated", "reason": "invalid_scanner_result",
                    "scan_id": _safe_scan_id(event.get("scan_id")), "findings": []}
        findings = _event_findings(event)
        if len(findings) != total_malicious:
            return {"status": "not_evaluated", "reason": "finding_count_mismatch",
                    "scan_id": _safe_scan_id(event.get("scan_id")), "findings": []}
        scan_id = _safe_scan_id(event.get("scan_id"))
        if scan_id is None:
            return {"status": "not_evaluated", "reason": "missing_scan_id", "scan_id": None,
                    "findings": []}
        return {"status": "infected" if findings else "clean", "reason": None,
                "scan_id": scan_id, "findings": findings}


def _safe_scan_id(value: Any) -> str | None:
    return value if isinstance(value, str) and ID_RE.fullmatch(value) else None


def _set_imunify_group(path: Path, mode: int) -> None:
    if grp is None:  # Test hosts without Unix groups do not run the daemon.
        os.chmod(path, mode)
        return
    try:
        group_id = grp.getgrnam(IMUNIFY_GROUP).gr_gid
    except KeyError as exc:
        raise RuntimeError("imunify_group_missing") from exc
    os.chown(path, -1, group_id)
    os.chmod(path, mode)


def scan_upload(body: bytes, identifiers: dict[str, str], expected_sha: str,
                backend: ScannerBackend, temp_root: Path,
                max_bytes: int = MAX_FILE_BYTES) -> tuple[int, dict[str, Any]]:
    if any(not ID_RE.fullmatch(identifiers.get(key, "")) for key in ID_FIELDS):
        return 400, {"error": "invalid_identifiers"}
    if not SHA_RE.fullmatch(expected_sha):
        return 400, {"error": "invalid_sha256"}
    if not body:
        return 400, {"error": "empty_file"}
    if len(body) > max_bytes:
        return 413, {"error": "file_too_large"}

    actual_sha = hashlib.sha256(body).hexdigest()
    if actual_sha != expected_sha:
        return 422, {"error": "sha256_mismatch"}

    request_dir: Path | None = None
    file_path: Path | None = None
    result: dict[str, Any] = {"status": "not_evaluated", "reason": "engine_internal_error",
                              "scan_id": None, "findings": []}
    try:
        request_dir = Path(tempfile.mkdtemp(prefix="scan-", dir=temp_root))
        _set_imunify_group(request_dir, 0o750)
        file_path = request_dir / "payload.bin"
        fd = os.open(file_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(body)
            output.flush()
            os.fsync(output.fileno())
        try:
            result = backend.scan(file_path)
        except BackendFailure as exc:
            result = {"status": "not_evaluated", "reason": exc.reason,
                      "scan_id": None, "findings": []}
        except Exception:
            LOG.error("scanner_backend_internal_error request=%s sha256=%s",
                      identifiers["observation"], actual_sha)
            result = {"status": "not_evaluated", "reason": "engine_internal_error",
                      "scan_id": None, "findings": []}
    finally:
        try:
            if file_path is not None:
                file_path.unlink(missing_ok=True)
            if request_dir is not None:
                request_dir.rmdir()
        except OSError:
            LOG.error("temporary_cleanup_failed request=%s sha256=%s",
                      identifiers["observation"], actual_sha)
            result = {"status": "not_evaluated", "reason": "temporary_cleanup_failed",
                      "scan_id": None, "findings": []}

    payload = {
        **identifiers,
        "engine": "imunifyav",
        "status": result["status"],
        "reason": result["reason"],
        "sha256": actual_sha,
        "size_bytes": len(body),
        "scan_id": result["scan_id"],
        "engine_version": None,
        "signature_revision": None,
        "findings": result["findings"],
    }
    LOG.info("scan_result %s", json.dumps({k: payload[k] for k in (
        *ID_FIELDS, "engine", "status", "reason", "sha256", "size_bytes", "scan_id"
    )}, separators=(",", ":")))
    return 200, payload


class ApiHandler(BaseHTTPRequestHandler):
    server_version = "MaMaImunifyGateway"
    sys_version = ""

    def log_message(self, _format: str, *_args: Any) -> None:
        return

    def _reply(self, status: int, payload: dict[str, Any]) -> None:
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self._reply(200, {"status": "ok"})
        else:
            self._reply(404, {"error": "not_found"})

    def do_POST(self) -> None:
        if self.path != "/v1/scan":
            self._reply(404, {"error": "not_found"})
            return
        if self.headers.get("Transfer-Encoding"):
            self._reply(400, {"error": "transfer_encoding_not_supported"})
            return
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            length = -1
        if length <= 0:
            self._reply(400, {"error": "invalid_content_length"})
            return
        if length > MAX_FILE_BYTES:
            self._reply(413, {"error": "file_too_large"})
            return
        if self.headers.get_content_type() != "application/octet-stream":
            self._reply(415, {"error": "unsupported_media_type"})
            return
        if not self.server.scan_slots.acquire(blocking=False):  # type: ignore[attr-defined]
            self._reply(503, {"error": "scanner_busy"})
            return
        try:
            body = self.rfile.read(length)
            if len(body) != length:
                self._reply(400, {"error": "incomplete_body"})
                return
            identifiers = {key: self.headers.get(f"X-MaMa-{key.title()}", "") for key in ID_FIELDS}
            sha = self.headers.get("X-MaMa-Sha256", "")
            status, payload = scan_upload(body, identifiers, sha, self.server.backend,
                                          self.server.temp_root)  # type: ignore[attr-defined]
            self._reply(status, payload)
        finally:
            self.server.scan_slots.release()  # type: ignore[attr-defined]


class GatewayServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], backend: ScannerBackend, temp_root: Path):
        super().__init__(address, ApiHandler)
        self.backend = backend
        self.temp_root = temp_root
        self.scan_slots = BoundedSemaphore(MAX_CONCURRENT_SCANS)

    def get_request(self):
        request, address = super().get_request()
        request.settimeout(REQUEST_TIMEOUT_SECONDS)
        return request, address


def require_tmpfs(path: Path) -> None:
    """Fail closed unless path resolves beneath a tmpfs mount on Linux."""
    resolved = path.resolve()
    mounts = Path("/proc/mounts")
    if not mounts.is_file():
        raise RuntimeError("cannot_verify_tmpfs")
    candidates: list[tuple[int, Path]] = []
    for line in mounts.read_text(encoding="utf-8").splitlines():
        fields = line.split()
        if len(fields) < 3 or fields[2] != "tmpfs":
            continue
        mountpoint = Path(fields[1].replace("\\040", " ")).resolve()
        try:
            resolved.relative_to(mountpoint)
            candidates.append((len(str(mountpoint)), mountpoint))
        except ValueError:
            continue
    if not candidates:
        raise RuntimeError("scan_temp_not_tmpfs")


def main() -> None:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(message)s")
    request_root = Path(os.environ.get("SCAN_TMP_ROOT", "/run/mama-imunify/requests"))
    event_root = Path(os.environ.get("SCAN_EVENT_ROOT", "/run/mama-imunify/events"))
    require_tmpfs(request_root)
    require_tmpfs(event_root)
    request_root.mkdir(mode=0o750, parents=True, exist_ok=True)
    event_root.mkdir(mode=0o770, parents=True, exist_ok=True)
    _set_imunify_group(request_root, 0o750)
    _set_imunify_group(event_root, 0o770)
    backend = ImunifyCliBackend(os.environ.get("IMUNIFY_CLI", "/usr/bin/imunify-antivirus"),
                                request_root, event_root)

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(os.environ["TLS_CERT_FILE"], os.environ["TLS_KEY_FILE"])
    context.load_verify_locations(cafile=os.environ["TLS_CLIENT_CA_FILE"])
    context.verify_mode = ssl.CERT_REQUIRED
    server = GatewayServer((os.environ.get("LISTEN_HOST", "127.0.0.1"),
                             int(os.environ.get("LISTEN_PORT", "8443"))), backend, request_root)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
