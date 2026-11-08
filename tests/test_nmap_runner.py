from __future__ import annotations

import gzip
import os
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from lumos.core.nmap.runner import (
    NmapRunnerError,
    build_nmap_argv,
    inspect_nmap,
    parse_manual_options,
    redacted_argv,
    resolve_hostnames_with_nmap,
    run_nmap,
)

ROOT = Path(__file__).resolve().parents[1]
FAKE = ROOT / "tests" / "fake_nmap" / "nmap"
FIXTURE = ROOT / "tests" / "fixtures" / "nmap" / "normal.xml"


class NmapRunnerTests(unittest.TestCase):
    def test_command_is_argument_vector_and_owns_xml_stdout(self) -> None:
        argv = build_nmap_argv("/usr/bin/nmap", ["192.0.2.1", "2001:db8::1"], options=["-p", "22"])
        self.assertEqual(argv, ["/usr/bin/nmap", "-sT", "-sV", "-n", "-p", "22", "-oX", "-", "192.0.2.1", "2001:db8::1"])

    def test_traceroute_requires_a_compatible_explicit_scan_type(self) -> None:
        with self.assertRaisesRegex(ValueError, "choose -sS or -sU"):
            build_nmap_argv("/usr/bin/nmap", ["192.0.2.1"], options=["--traceroute"])
        with self.assertRaisesRegex(ValueError, "incompatible"):
            build_nmap_argv("/usr/bin/nmap", ["192.0.2.1"], options=["-sT", "--traceroute"])
        argv = build_nmap_argv("/usr/bin/nmap", ["192.0.2.1"], options=["-sS", "--traceroute"])
        self.assertIn("-sS", argv)
        self.assertIn("--traceroute", argv)
        self.assertNotIn("-sT", argv)

    def test_manual_options_strip_leading_nmap_but_reject_shell_and_output_controls(self) -> None:
        self.assertEqual(parse_manual_options("nmap -p '22,443' -T4"), ["-p", "22,443", "-T4"])
        for text in ("-oX /tmp/out.xml", "--script=intrusive", "-iL targets.txt", "-A", "-sN"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                parse_manual_options(text)

    def test_credential_like_values_are_redacted_before_storage(self) -> None:
        self.assertEqual(
            redacted_argv(["nmap", "--password", "secret", "--api-key=abc", "192.0.2.1"]),
            ["nmap", "--password", "<REDACTED>", "--api-key=<REDACTED>", "192.0.2.1"],
        )

    def test_fake_nmap_xml_is_streamed_and_evidence_is_compressed(self) -> None:
        env = os.environ.copy()
        env["NMAP_FAKE_FIXTURE"] = str(FIXTURE)
        hosts = []

        def factory(*args, **kwargs):
            return subprocess.Popen(*args, **kwargs, env=env)

        result = run_nmap(
            [str(FAKE), "-sT", "-oX", "-", "192.0.2.10"],
            on_host=hosts.append,
            process_factory=factory,
        )
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.hosts_seen, 1)
        self.assertEqual(hosts[0].addresses[0].value, "192.0.2.10")
        self.assertGreater(result.xml_bytes, 0)
        self.assertEqual(gzip.decompress(result.compressed_xml), FIXTURE.read_bytes())
        self.assertFalse(result.parse_error)

    def test_malformed_xml_preserves_completed_hosts_and_reports_parse_error(self) -> None:
        # The existing truncated fixture has no complete host; this checks safe error reporting.
        env = os.environ.copy()
        env["NMAP_FAKE_FIXTURE"] = str(ROOT / "tests" / "fixtures" / "nmap" / "truncated.xml")

        def factory(*args, **kwargs):
            return subprocess.Popen(*args, **kwargs, env=env)

        result = run_nmap([str(FAKE), "-oX", "-", "192.0.2.20"], on_host=lambda host: None, process_factory=factory)
        self.assertEqual(result.exit_code, 0)
        self.assertTrue(result.parse_error)

    def test_positional_target_cannot_hide_inside_manual_options(self) -> None:
        with self.assertRaisesRegex(ValueError, "Unexpected positional token"):
            parse_manual_options("-p 22 203.0.113.44")

    def test_hostname_resolution_uses_nmap_list_scan_and_returns_numeric_targets(self) -> None:
        from lumos.core.nmap.runner import NmapRunResult
        from lumos.core.nmap.xml_stream import parse_nmap_xml

        records = list(parse_nmap_xml([FIXTURE.read_bytes()]))
        result = NmapRunResult(0, 1, "", "", 1, "0" * 64, None)

        def fake_run(argv, *, on_host, **kwargs):
            self.assertEqual(argv[1:3], ["-sL", "-oX"])
            self.assertEqual(argv[-1], "demo-host.example.invalid")
            for record in records:
                on_host(record)
            return result

        with patch("lumos.core.nmap.runner.run_nmap", side_effect=fake_run):
            self.assertEqual(
                resolve_hostnames_with_nmap(str(FAKE), ["demo-host.example.invalid"]),
                ["192.0.2.10"],
            )

    def test_user_text_outputs_can_coexist_but_xml_file_conflicts_are_explicit(self) -> None:
        options = parse_manual_options("-oN scan.nmap -oG scan.gnmap")
        argv = build_nmap_argv("/usr/bin/nmap", ["192.0.2.1"], options=options)
        self.assertIn("-oN", argv)
        self.assertIn("scan.nmap", argv)
        self.assertIn("-oG", argv)
        self.assertIn("scan.gnmap", argv)
        env = os.environ.copy()
        env["NMAP_FAKE_FIXTURE"] = str(FIXTURE)
        with self.assertRaisesRegex(ValueError, "conflicts"):
            parse_manual_options("-oX saved.xml")
        with self.assertRaisesRegex(ValueError, "stdout"):
            parse_manual_options("-oN -")

        def factory(*args, **kwargs):
            return subprocess.Popen(*args, **kwargs, env=env)

        result = run_nmap(
            [str(FAKE), "-oN", "saved.nmap", "-oX", "-", "192.0.2.10"],
            on_host=lambda host: None,
            process_factory=factory,
        )
        self.assertEqual(result.exit_code, 0)
        with self.assertRaisesRegex(ValueError, "exactly one"):
            run_nmap([str(FAKE), "-oX", "saved.xml", "-oX", "-"], on_host=lambda host: None)


if __name__ == "__main__":
    unittest.main()
