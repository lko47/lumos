from __future__ import annotations

import os
import subprocess
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FAKE_NMAP = ROOT / "tests" / "fake_nmap" / "nmap"
FIXTURES = ROOT / "tests" / "fixtures" / "nmap"


class FakeNmapTests(unittest.TestCase):
    def test_version_is_synthetic_and_offline(self) -> None:
        result = subprocess.run([str(FAKE_NMAP), "--version"], capture_output=True, text=True, check=True)
        self.assertIn("synthetic test executable", result.stdout)

    def test_replays_xml_fixture_without_scanning(self) -> None:
        env = os.environ.copy()
        env["NMAP_FAKE_FIXTURE"] = str(FIXTURES / "normal.xml")
        env["NMAP_FAKE_CHUNK_SIZE"] = "128"
        result = subprocess.run(
            [str(FAKE_NMAP), "-sV", "-oX", "-", "192.0.2.10"],
            env=env,
            capture_output=True,
            check=True,
        )
        root = ET.fromstring(result.stdout)
        self.assertEqual(root.tag, "nmaprun")
        self.assertEqual(root.find("host/address").attrib["addr"], "192.0.2.10")

    def test_missing_fixture_fails_closed(self) -> None:
        env = os.environ.copy()
        env.pop("NMAP_FAKE_FIXTURE", None)
        result = subprocess.run(
            [str(FAKE_NMAP), "-oX", "-", "192.0.2.1"],
            env=env,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("NMAP_FAKE_FIXTURE is required", result.stderr)


if __name__ == "__main__":
    unittest.main()
