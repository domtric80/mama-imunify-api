from pathlib import Path
import importlib.util
import subprocess
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "verify_runtime_mount", ROOT / "deploy" / "verify_runtime_mount.py"
)
VERIFY_RUNTIME_MOUNT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY_RUNTIME_MOUNT)


class GatewayUnitTest(unittest.TestCase):
    def setUp(self):
        self.unit = (ROOT / "deploy" / "mama-imunify-api.service").read_text()
        self.service_section = self.unit.split("[Service]", 1)[1].split("[Install]", 1)[0]

    def test_mount_is_required_before_gateway_start(self):
        self.assertIn("After=network.target clamav-daemon.service run-mama\\x2dimunify.mount", self.unit)
        self.assertIn("Requires=run-mama\\x2dimunify.mount", self.unit)
        self.assertNotIn("RuntimeDirectory=mama-imunify", self.service_section)

    def test_tmpfs_verification_precedes_runtime_directory_creation(self):
        checks = [
            line
            for line in self.service_section.splitlines()
            if line.startswith("ExecStartPre=")
        ]
        self.assertIn("verify_runtime_mount.py", checks[0])
        self.assertIn("requests", checks[1])
        self.assertIn("events", checks[2])
        self.assertIn("ReadWritePaths=/run/mama-imunify", self.service_section)

    @patch.object(
        VERIFY_RUNTIME_MOUNT.subprocess,
        "run",
        return_value=subprocess.CompletedProcess([], 1, "", ""),
    )
    def test_missing_mount_refuses_gateway_start(self, run):
        valid, reason = VERIFY_RUNTIME_MOUNT.verify_mount()

        self.assertFalse(valid)
        self.assertIn("not a mounted filesystem", reason)

    @patch.object(
        VERIFY_RUNTIME_MOUNT.subprocess,
        "run",
        return_value=subprocess.CompletedProcess(
            [], 0, "tmpfs rw,relatime,size=262144k,nosuid,nodev,noexec\n", ""
        ),
    )
    def test_dedicated_hardened_tmpfs_is_accepted(self, run):
        valid, reason = VERIFY_RUNTIME_MOUNT.verify_mount()

        self.assertTrue(valid)
        self.assertEqual("", reason)

    @patch.object(
        VERIFY_RUNTIME_MOUNT.subprocess,
        "run",
        return_value=subprocess.CompletedProcess([], 0, "tmpfs rw,relatime\n", ""),
    )
    def test_tmpfs_without_required_options_is_rejected(self, run):
        valid, reason = VERIFY_RUNTIME_MOUNT.verify_mount()

        self.assertFalse(valid)
        self.assertIn("nosuid", reason)
        self.assertIn("nodev", reason)
        self.assertIn("noexec", reason)


if __name__ == "__main__":
    unittest.main()
