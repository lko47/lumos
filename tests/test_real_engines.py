"""Real binaries, when they are installed: parsers must survive actual output.

Everything else in the suite replays recorded fixtures, which is why a parser can
look correct for months. These tests skip unless the binary is on PATH, and they
only ever talk to 127.0.0.1 — the loopback interface, no network involved.

Run them deliberately with the real tools available:

    PATH="$HOME/go/bin:$HOME/.cargo/bin:$PATH" \
        PYTHONPATH=src python3 -m unittest tests.test_real_engines -v
"""

from __future__ import annotations

import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path

from lumos.core import engine_scan, engines
from lumos.core.database import initialize_database
from lumos.core.scope_store import add_scope_rule

PORTS = "22,631"


class RealEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.database = Path(self.tmp.name) / "real.sqlite"
        initialize_database(self.database, "real engine test")
        add_scope_rule(self.database, "loopback", "127.0.0.1/32", included=True)

    def _run(self, name: str) -> tuple[str, int, str]:
        return engine_scan.scan_with_engine(
            self.database, "loopback", name, "127.0.0.1",
            engine_scan.EngineOptions(ports=PORTS, operator="test"),
        )

    def _rows(self) -> list[tuple[str, int]]:
        conn = sqlite3.connect(self.database)
        try:
            return [
                (str(row[0]), int(row[1]))
                for row in conn.execute(
                    "SELECT a.display_value, p.port FROM port_observations p"
                    " JOIN host_observations h ON h.id = p.host_observation_id"
                    " JOIN observation_addresses oa ON oa.host_observation_id = h.id"
                    " JOIN addresses a ON a.id = oa.address_id"
                    " ORDER BY p.port"
                )
            ]
        finally:
            conn.close()

    def _assert_recorded(self, message: str) -> None:
        rows = self._rows()
        self.assertTrue(rows, f"no ports recorded: {message}")
        self.assertTrue(all(address == "127.0.0.1" for address, _ in rows), rows)
        self.assertTrue(
            {port for _, port in rows} & {22, 631},
            f"expected an open loopback port in {rows}",
        )

    @unittest.skipUnless(shutil.which("naabu"), "naabu is not installed")
    def test_naabu_json_lines_become_observations(self) -> None:
        _scan_id, hosts, message = self._run("naabu")
        self.assertGreaterEqual(hosts, 1)
        self._assert_recorded(message)
        conn = sqlite3.connect(self.database)
        try:
            argv = conn.execute(
                "SELECT exact_args_json FROM scans ORDER BY started_at DESC LIMIT 1"
            ).fetchone()[0]
        finally:
            conn.close()
        self.assertIn("naabu", argv, "the scan records which binary ran")

    @unittest.skipUnless(shutil.which("rustscan"), "rustscan is not installed")
    def test_rustscan_greppable_becomes_observations(self) -> None:
        _scan_id, hosts, message = self._run("rustscan")
        self.assertGreaterEqual(hosts, 1)
        self._assert_recorded(message)


if __name__ == "__main__":
    unittest.main()
