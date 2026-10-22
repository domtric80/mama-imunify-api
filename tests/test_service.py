from __future__ import annotations

import hashlib
import http.client
import json
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from service import (BackendFailure, ClamAvBackend, ImunifyCliBackend, MultiEngineBackend,
                     PhpMalwareScannerBackend, clear_tmpfs_directory, parse_requested_engines,
                     GatewayServer, MAX_CONCURRENT_SCANS, REQUEST_QUEUE_SIZE, scan_upload)


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
        status, result = scan_upload(self.body, IDS, self.sha, backend, self.root, ["clamav"])
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
        status, result = scan_upload(self.body, IDS, self.sha, backend, self.root, ["clamav"])
        self.assertEqual(status, 200)
        self.assertEqual(result["results"][0]["findings"][0]["rule"], "EICAR-Test")
        self.assertNotIn("path", json.dumps(result))
        self.assertEqual(list(self.root.iterdir()), [])

    def test_backend_timeout_fails_closed_and_deletes_file(self):
        backend = FakeBackend(failure=BackendFailure("engine_timeout"))
        status, result = scan_upload(self.body, IDS, self.sha, backend, self.root, ["clamav"])
        self.assertEqual(status, 200)
        self.assertEqual(result["results"][0]["status"], "not_evaluated")
        self.assertEqual(result["results"][0]["reason"], "engine_timeout")
        self.assertEqual(list(self.root.iterdir()), [])

    def test_bad_hash_and_invalid_ids_are_rejected_before_scan(self):
        backend = FakeBackend()
        status, result = scan_upload(self.body, IDS, "0" * 64, backend, self.root, ["clamav"])
        self.assertEqual((status, result["error"]), (422, "sha256_mismatch"))
        bad_ids = {**IDS, "site": "../2"}
        status, result = scan_upload(self.body, bad_ids, self.sha, backend, self.root, ["clamav"])
        self.assertEqual((status, result["error"]), (400, "invalid_identifiers"))
        self.assertIsNone(backend.seen_path)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_oversize_upload_never_reaches_backend(self):
        backend = FakeBackend()
        status, result = scan_upload(self.body, IDS, self.sha, backend, self.root, ["clamav"], max_bytes=4)
        self.assertEqual((status, result["error"]), (413, "file_too_large"))
        self.assertIsNone(backend.seen_path)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_empty_payload_with_matching_sha_is_scanned_and_cleaned(self):
        completed = type("Completed", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        suite = MultiEngineBackend({
            "clamav": ClamAvBackend(),
            "php-malware-scanner": PhpMalwareScannerBackend("php", "scan.php"),
        })
        empty_sha = hashlib.sha256(b"").hexdigest()

        with patch("service.subprocess.run", return_value=completed) as scanner_run:
            status, result = scan_upload(b"", IDS, empty_sha, suite, self.root,
                                         ["clamav", "php-malware-scanner"])

        self.assertEqual(status, 200)
        self.assertEqual(result["size_bytes"], 0)
        self.assertEqual(result["sha256"], empty_sha)
        self.assertEqual([item["status"] for item in result["results"]], ["no_findings", "no_findings"])
        self.assertEqual(scanner_run.call_count, 2)
        self.assertIn("clamdscan", scanner_run.call_args_list[0].args[0][0])
        self.assertEqual(scanner_run.call_args_list[1].args[0][:2], ["php", "scan.php"])
        self.assertEqual(list(self.root.iterdir()), [])

    def test_http_accepts_zero_content_length_and_scans_only_requested_engines(self):
        calls = []
        class Engine:
            def __init__(self, name):
                self.name = name
            def scan(self, path):
                calls.append((self.name, path.stat().st_size))
                return {"status": "clean", "findings": []}

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            backend = MultiEngineBackend({"clamav": Engine("clamav"),
                                          "php-malware-scanner": Engine("php-malware-scanner")})
            server = GatewayServer(("127.0.0.1", 0), backend, root)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                headers = {**{f"X-MaMa-{key.replace('_', '-').title()}": value for key, value in IDS.items()},
                    "X-MaMa-Sha256": hashlib.sha256(b"").hexdigest(),
                    "X-MaMa-Engines": "php-malware-scanner", "Content-Length": "0",
                    "Content-Type": "application/octet-stream"}
                connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
                connection.request("POST", "/v1/scan", body=b"", headers=headers)
                response = connection.getresponse()
                payload = json.loads(response.read())
                self.assertEqual(response.status, 200)
                self.assertEqual(payload["size_bytes"], 0)
                self.assertEqual([item["engine"] for item in payload["results"]], ["php-malware-scanner"])
                self.assertEqual(calls, [("php-malware-scanner", 0)])
                self.assertEqual(list(root.iterdir()), [])
                connection.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


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

    def test_clamav_limit_alert_is_not_evaluated(self):
        path = Path("/run/mama-imunify/requests/scan-a/payload.bin")
        for rule in (
            "Heuristics.Limits.Exceeded.MaxFileSize",
            "Heuristics.Limits.Exceeded.MaxFiles",
            "Heuristics.Limits.Exceeded.MaxRecursion",
        ):
            completed = type("Completed", (), {"returncode": 1,
                "stdout": f"{path}: {rule} FOUND\n", "stderr": ""})()
            with self.subTest(rule=rule), patch("service.subprocess.run", return_value=completed):
                result = ClamAvBackend().scan(path)
            self.assertEqual(result, {
                "status": "not_evaluated",
                "reason": "engine_size_limit",
                "findings": [],
            })

    def test_php_malware_scanner_parses_pattern_and_line_without_path(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "payload.bin"
            path.write_bytes(b"synthetic")
            completed = type("Completed", (), {"returncode": 0,
                "stdout": "ER|synthetic-rule|12\n", "stderr": ""})()
            with patch("service.subprocess.run", return_value=completed) as run:
                result = PhpMalwareScannerBackend("php", "scan.php").scan(path)
        self.assertEqual(run.call_args.args[0][:3], ["php", "scan.php", "-d"])
        self.assertNotIn("--", run.call_args.args[0][2:])
        self.assertIn("-L", run.call_args.args[0])
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
        result = suite.scan(Path("synthetic"), ["clamav", "php-malware-scanner"])["results"]
        self.assertEqual([item["engine"] for item in result], ["clamav", "php-malware-scanner"])
        self.assertEqual(result[0]["status"], "not_evaluated")
        self.assertEqual(result[0]["reason"], "engine_unavailable")
        self.assertEqual(result[1]["status"], "no_findings")

    def test_signature_metadata_is_returned_when_configured(self):
        suite = MultiEngineBackend({"clamav": FakeBackend()}, {"clamav": {
            "engine_version": "1.2.3", "signature_revision": "456"}})
        result = suite.scan(Path("synthetic"), ["clamav"])["results"][0]
        self.assertEqual(result["engine_version"], "1.2.3")
        self.assertEqual(result["signature_revision"], "456")


class RequestedEnginesTest(unittest.TestCase):
    def setUp(self):
        self.enabled = {"clamav": FakeBackend(), "php-malware-scanner": FakeBackend()}

    def test_requires_explicit_nonempty_known_enabled_ordered_list(self):
        for value in (None, "", "clamav,", ",clamav", "clamav,clamav", "clamav,unknown",
                      "clamav, imunifyav", "clamav\r\nX-Evil:yes"):
            with self.subTest(value=value):
                self.assertIsNone(parse_requested_engines(value, self.enabled))
        self.assertEqual(parse_requested_engines("php-malware-scanner,clamav", self.enabled),
                         ["php-malware-scanner", "clamav"])

    def test_backend_runs_only_requested_engines_in_requested_order(self):
        calls = []
        class Engine:
            def __init__(self, name):
                self.name = name
            def scan(self, path):
                calls.append(self.name)
                return {"status": "clean", "findings": []}
        suite = MultiEngineBackend({name: Engine(name) for name in self.enabled})
        results = suite.scan(Path("synthetic"), ["php-malware-scanner"])["results"]
        self.assertEqual(calls, ["php-malware-scanner"])
        self.assertEqual([item["engine"] for item in results], ["php-malware-scanner"])

    def test_http_rejects_bad_selection_before_body_read_or_staging(self):
        calls = []
        class Engine:
            def scan(self, path):
                calls.append(path)
                return {"status": "clean", "findings": []}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            backend = MultiEngineBackend({"clamav": Engine(), "php-malware-scanner": Engine()})
            server = GatewayServer(("127.0.0.1", 0), backend, root)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
                connection.request("POST", "/v1/scan", body=b"synthetic",
                    headers={"Content-Length": "9", "Content-Type": "application/octet-stream"})
                response = connection.getresponse()
                self.assertEqual(response.status, 400)
                self.assertEqual(json.loads(response.read()), {"error": "invalid_engines"})
                connection.close()
                self.assertEqual(calls, [])
                self.assertEqual(list(root.iterdir()), [])

                body = b"synthetic"
                headers = {**{f"X-MaMa-{key.replace('_', '-').title()}": value for key, value in IDS.items()},
                    "X-MaMa-Sha256": hashlib.sha256(body).hexdigest(),
                    "X-MaMa-Engines": "php-malware-scanner",
                    "Content-Type": "application/octet-stream"}
                connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
                connection.request("POST", "/v1/scan", body=body, headers=headers)
                response = connection.getresponse()
                payload = json.loads(response.read())
                self.assertEqual(response.status, 200)
                self.assertEqual([item["engine"] for item in payload["results"]], ["php-malware-scanner"])
                self.assertEqual(len(calls), 1)
                self.assertEqual(list(root.iterdir()), [])
                connection.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


class GatewayCapacityTest(unittest.TestCase):
    def test_queue_is_explicitly_bounded_and_saturation_returns_retryable_429(self):
        self.assertGreaterEqual(REQUEST_QUEUE_SIZE, 32)
        self.assertLessEqual(REQUEST_QUEUE_SIZE, 256)
        self.assertEqual(GatewayServer.request_queue_size, REQUEST_QUEUE_SIZE)
        calls = []
        class Engine:
            def scan(self, path):
                calls.append(path)
                return {"status": "clean", "findings": []}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            server = GatewayServer(("127.0.0.1", 0), MultiEngineBackend({"clamav": Engine()}), root)
            held_slots = 0
            for _ in range(MAX_CONCURRENT_SCANS):
                self.assertTrue(server.scan_slots.acquire(blocking=False))
                held_slots += 1
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                body = b"synthetic"
                headers = {**{f"X-MaMa-{key.replace('_', '-').title()}": value for key, value in IDS.items()},
                    "X-MaMa-Sha256": hashlib.sha256(body).hexdigest(),
                    "X-MaMa-Engines": "clamav", "Content-Type": "application/octet-stream"}
                connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
                connection.request("POST", "/v1/scan", body=body, headers=headers)
                response = connection.getresponse()
                self.assertEqual(response.status, 429)
                self.assertEqual(response.getheader("Retry-After"), "15")
                self.assertEqual(json.loads(response.read()), {"error": "scanner_busy"})
                self.assertEqual(calls, [])
                self.assertEqual(list(root.iterdir()), [])
                connection.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)
                for _ in range(held_slots):
                    server.scan_slots.release()

    def test_concurrent_http_load_never_exceeds_scanner_limit_and_leaves_no_files(self):
        active = 0
        maximum = 0
        guard = threading.Lock()
        class SlowEngine:
            def scan(self, path):
                nonlocal active, maximum
                with guard:
                    active += 1
                    maximum = max(maximum, active)
                try:
                    time.sleep(0.12)
                    return {"status": "clean", "findings": []}
                finally:
                    with guard:
                        active -= 1
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            server = GatewayServer(("127.0.0.1", 0), MultiEngineBackend({"clamav": SlowEngine()}), root)
            server_thread = threading.Thread(target=server.serve_forever, daemon=True)
            server_thread.start()
            barrier = threading.Barrier(8)
            def request_one(index):
                body = f"sample-{index}".encode()
                headers = {**{f"X-MaMa-{key.replace('_', '-').title()}": value for key, value in IDS.items()},
                    "X-MaMa-Sha256": hashlib.sha256(body).hexdigest(), "X-MaMa-Engines": "clamav",
                    "Content-Type": "application/octet-stream"}
                barrier.wait(timeout=2)
                connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
                connection.request("POST", "/v1/scan", body=body, headers=headers)
                response = connection.getresponse()
                status = response.status
                response.read()
                connection.close()
                return status
            try:
                with ThreadPoolExecutor(max_workers=8) as pool:
                    statuses = list(pool.map(request_one, range(8)))
                self.assertTrue(all(status in (200, 429) for status in statuses), statuses)
                self.assertIn(200, statuses)
                self.assertLessEqual(maximum, MAX_CONCURRENT_SCANS)
                self.assertEqual(active, 0)
                self.assertEqual(list(root.iterdir()), [])
            finally:
                server.shutdown()
                server.server_close()
                server_thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
