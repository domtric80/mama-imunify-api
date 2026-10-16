from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from service import BackendFailure, ImunifyCliBackend, scan_upload


IDS = {"tenant": "1", "site": "2", "environment": "3", "batch": "4", "observation": "5"}


class FakeBackend:
    def __init__(self, result=None, failure=None):
        self.result = result or {"status": "clean", "reason": None, "scan_id": "scan_1", "findings": []}
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
        self.assertEqual(result["status"], "clean")
        self.assertEqual(result["engine"], "imunifyav")
        self.assertEqual(result["sha256"], self.sha)
        self.assertFalse(backend.seen_path.exists())
        self.assertEqual(list(self.root.iterdir()), [])

    def test_finding_is_returned_without_file_path(self):
        backend = FakeBackend({"status": "infected", "reason": None, "scan_id": "s2",
                               "findings": [{"rule": "EICAR-Test"}]})
        status, result = scan_upload(self.body, IDS, self.sha, backend, self.root)
        self.assertEqual(status, 200)
        self.assertEqual(result["findings"], [{"rule": "EICAR-Test"}])
        self.assertNotIn("path", json.dumps(result))
        self.assertEqual(list(self.root.iterdir()), [])

    def test_backend_timeout_fails_closed_and_deletes_file(self):
        backend = FakeBackend(failure=BackendFailure("engine_timeout"))
        status, result = scan_upload(self.body, IDS, self.sha, backend, self.root)
        self.assertEqual(status, 200)
        self.assertEqual(result["status"], "not_evaluated")
        self.assertEqual(result["reason"], "engine_timeout")
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
        self.assertEqual(result["findings"], [{"rule": "EICAR-Test"}])
        self.assertEqual(result["scan_id"], "scan_2")
        event["malicious_files"] = []
        self.assertEqual(ImunifyCliBackend._normalize(event)["status"], "not_evaluated")

    def test_clean_requires_a_correlatable_scan_id(self):
        event = {"status": "ok", "total_files": 1, "total_malicious": 0}
        result = ImunifyCliBackend._normalize(event)
        self.assertEqual(result["status"], "not_evaluated")
        self.assertEqual(result["reason"], "missing_scan_id")


if __name__ == "__main__":
    unittest.main()
