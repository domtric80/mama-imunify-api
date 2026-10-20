from pathlib import Path
import unittest


class GatewayUnitTest(unittest.TestCase):
    def test_runtime_directory_exists_before_namespace_setup(self):
        unit = (Path(__file__).resolve().parents[1] / "deploy" / "mama-imunify-api.service").read_text()
        service_section = unit.split("[Service]", 1)[1].split("[Install]", 1)[0]

        self.assertIn("RuntimeDirectory=mama-imunify", service_section)
        self.assertIn("RuntimeDirectoryMode=0750", service_section)
        self.assertIn("ReadWritePaths=/run/mama-imunify", service_section)


if __name__ == "__main__":
    unittest.main()
