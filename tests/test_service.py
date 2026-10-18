from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from service import (BackendFailure, ClamAvBackend, ImunifyCliBackend, MultiEngineBackend,
                     PhpMalwareScannerBackend, clear_tmpfs_directory, scan_upload)


IDS = {"tenant": "1", "site": "2", "environment": "3", "batch": "4", "observation": "5",
       "file_version": "6"}


class FakeBackend:
    def __init__(self, result=None, failure=None):
        self.result = result or {"results": [{"engine": "clamav", "status": "no_findings", "reason": None,
            "findings": [], "engine_version": None, "signature_revision": None,
            "profile": "mama-node-v1", "elapsed_ms": 1}]}
        self.failure = failure
        self.seen_path = None

    def scan(self, path: Path):
        self.seen_path = path
        if self.failure:
            raise self.failure
        return self.result


class ScanUploadTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.body = b"synthetic sample"
        self.sha = hashlib.sha256(self.body).hexdigest()

    def tearDown(self):
        self.temp.cleanup()

    def test_clean_result_deletes_uploaded_file_and_directory(self):
        backend = FakeBackend()
        status, result = scan_upload(self.body, IDS, self.sha, backend, self.root)
        self.assertEqual(status, 200)
        self.assertEqual(result["results"][0]["status"], "no_findings")
        self.assertEqual(result["results"][0]["engine"], "clamav")
        self.assertEqual(result["file_version"], "6")
        self.assertEqual(result["sha256"], self.sha)
        self.assertFalse(backend.seen_path.exists())
        self.assertEqual(list(self.root.iterdir()), [])

    def test_finding_is_returned_without_file_path(self):
        backend = FakeBackend({"results": [{"engine": "clamav", "status": "findings", "reason": None,
            "findings": [{"rule": "EICAR-Test", "severity": "unknown", "line": None}],
            "engine_version": None, "signature_revision": None, "profile": "mama-node-v1", "elapsed_ms": 1}]})
        status, result = scan_upload(self.body, IDS, self.sha, backend, self.root)
        self.assertEqual(status, 200)
        self.assertEqual(result["results"][0]["findings"][0]["rule"], "EICAR-Test")
        self.assertNotIn("path", json.dumps(result))
        self.assertEqual(list(self.root.iterdir()), [])

    def test_backend_timeout_fails_closed_and_deletes_file(self):
        backend = FakeBackend(failure=BackendFailure("engine_timeout"))
        status, result = scan_upload(self.body, IDS, self.sha, backend, self.root)
        self.assertEqual(status, 200)
        self.assertEqual(result["results"][0]["status"], "not_evaluated")
        self.assertEqual(result["results"][0]["reason"], "engine_timeout")
        self.assertEqual(list(self.root.iterdir()), [])

    def test_bad_hash_and_invalid_ids_are_rejected_before_scan(self):
        backend = FakeBackend()
        status, result = scan_upload(self.body, IDS, "0" * 64, backend, self.root)
        self.assertEqual((status, result["error"]), (422, "sha256_mismatch"))
        bad_ids = {**IDS, "site": "../2"}
        status, result = scan_upload(self.body, bad_ids, self.sha, backend, self.root)
        self.assertEqual((status, result["error"]), (400, "invalid_identifiers"))
        self.assertIsNone(backend.seen_path)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_oversize_upload_never_reaches_backend(self):
        backend = FakeBackend()
        status, result = scan_upload(self.body, IDS, self.sha, backend, self.root, max_bytes=4)
        self.assertEqual((status, result["error"]), (413, "file_too_large"))
        self.assertIsNone(backend.seen_path)
        self.assertEqual(list(self.root.iterdir()), [])


class StartupCleanupTest(unittest.TestCase):
    def test_removes_stale_files_without_following_symlinks(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            nested = root / "interrupted-request"
            nested.mkdir()
            (nested / "payload.bin").write_bytes(b"synthetic interrupted upload")
            sentinel = Path(outside) / "must-remain"
            sentinel.write_text("outside the scan root", encoding="utf-8")
            link = root / "stale-link"
            try:
                link.symlink_to(sentinel)
            except (OSError, NotImplementedError):
                link = None

            clear_tmpfs_directory(root)

            self.assertEqual(list(root.iterdir()), [])
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "outside the scan root")
            if link is not None:
                self.assertFalse(link.exists())


class ResultNormalizationTest(unittest.TestCase):
    def test_clean_requires_success_and_exactly_one_file(self):
        result = ImunifyCliBackend._normalize({"status": "ok", "total_files": 1,
                                               "total_malicious": 0, "scan_id": "scan_1"})
        self.assertEqual(result["status"], "clean")
        for event in (
            {"status": "failed", "total_files": 1, "total_malicious": 0},
            {"status": "ok", "total_files": 0, "total_malicious": 0},
            {"status": "ok", "total_files": 1, "total_malicious": 1},
            {"status": "ok", "total_files": 1, "total_malicious": 0,
             "malicious_files": [{"type": "Unexpected-Finding"}]},
            {"status": "ok", "total_files": 1, "total_malicious": 0},
        ):
            self.assertEqual(ImunifyCliBackend._normalize(event)["status"], "not_evaluated")

    def test_findings_require_rule_names_and_match_count(self):
        event = {"status": "ok", "total_files": 1, "total_malicious": 1,
                 "scan_id": "scan_2", "malicious_files": [{"type": "EICAR-Test"}]}
        result = ImunifyCliBackend._normalize(event)
        self.assertEqual(result["status"], "infected")
        self.assertEqual(result["findings"], [{"rule": "EICAR-Test", "severity": "unknown", "line": None}])
        self.assertEqual(result["scan_id"], "scan_2")
        event["malicious_files"] = []
        self.assertEqual(ImunifyCliBackend._normalize(event)["status"], "not_evaluated")

    def test_clean_requires_a_correlatable_scan_id(self):
        event = {"status": "ok", "total_files": 1, "total_malicious": 0}
        result = ImunifyCliBackend._normalize(event)
        self.assertEqual(result["status"], "not_evaluated")
        self.assertEqual(result["reason"], "missing_scan_id")


class EngineAdapterTest(unittest.TestCase):
    def test_clamav_parses_detection_without_returning_local_path(self):
        path = Path("/run/mama-imunify/requests/scan-a/payload.bin")
        completed = type("Completed", (), {"returncode": 1,
            "stdout": f"{path}: Eicar-Test-Signature FOUND\n", "stderr": ""})()
        with patch("service.subprocess.run", return_value=completed) as run:
            result = ClamAvBackend().scan(path)
        self.assertEqual(result["findings"][0]["rule"], "Eicar-Test-Signature")
        self.assertNotIn(str(path), json.dumps(result))
        self.assertIn("--stream", run.call_args.args[0])
        self.assertIn("--infected", run.call_args.args[0])

    def test_php_malware_scanner_parses_pattern_and_line_without_path(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "payload.bin"
            path.write_bytes(b"synthetic")
            completed = type("Completed", (), {"returncode": 0,
                "stdout": "ER|synthetic-rule|12\n", "stderr": ""})()
            with patch("service.subprocess.run", return_value=completed):
                result = PhpMalwareScannerBackend("php", "scan.php").scan(path)
        self.assertEqual(result["findings"], [{"rule": "synthetic-rule", "severity": "unknown", "line": 12}])

    def test_php_malware_scanner_fails_closed_on_unparseable_output(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "payload.bin"
            path.write_bytes(b"synthetic")
            completed = type("Completed", (), {"returncode": 0,
                "stdout": f"ER # {{{path}}} (unreadable)\n", "stderr": ""})()
            with patch("service.subprocess.run", return_value=completed):
                with self.assertRaises(BackendFailure) as error:
                    PhpMalwareScannerBackend("php", "scan.php").scan(path)
        self.assertEqual(error.exception.reason, "invalid_scanner_result")

    def test_engine_failures_are_isolated_and_each_result_is_reported(self):
        class Engine(FakeBackend):
            def __init__(self, result=None, failure=None):
                super().__init__(result, failure)
            def scan(self, path):
                if self.failure:
                    raise self.failure
                return {"status": "clean", "findings": []}

        suite = MultiEngineBackend({
            "clamav": Engine(failure=BackendFailure("engine_unavailable")),
            "imunifyav": Engine(),
            "php-malware-scanner": Engine(),
        })
        result = suite.scan(Path("synthetic"))["results"]
        self.assertEqual([item["engine"] for item in result], ["clamav", "imunifyav", "php-malware-scanner"])
        self.assertEqual(result[0]["status"], "not_evaluated")
        self.assertEqual(result[0]["reason"], "engine_unavailable")
        self.assertEqual(result[1]["status"], "no_findings")

    def test_signature_metadata_is_returned_when_configured(self):
        suite = MultiEngineBackend({"clamav": FakeBackend()}, {"clamav": {
            "engine_version": "1.2.3", "signature_revision": "456"}})
        result = suite.scan(Path("synthetic"))["results"][0]
        self.assertEqual(result["engine_version"], "1.2.3")
        self.assertEqual(result["signature_revision"], "456")


if __name__ == "__main__":
    unittest.main()
