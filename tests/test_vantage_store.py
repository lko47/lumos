from __future__ import annotations

import io
import socket
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from lumos.cli import main
from lumos.core.database import initialize_database, open_database
from lumos.core.nmap.iflist import InterfaceEntry, InterfaceSnapshot, RouteEntry
from lumos.core.vantage_store import MAX_INTERFACES, VantageStoreError, save_interfaces
from lumos.services.map_view import load_map_snapshot

SNAPSHOT = InterfaceSnapshot(
    interfaces=(
        InterfaceEntry("lo", "lo", "127.0.0.1/8", "loopback", True, 65536, ""),
        InterfaceEntry("wlan0", "wlan0", "192.0.2.12/24", "ethernet", True, 1500, "02:00:00:00:00:02"),
        InterfaceEntry("wlan0", "wlan0", "2001:db8::12/64", "ethernet", True, 1500, "02:00:00:00:00:02"),
        InterfaceEntry("eth0", "eth0", None, "ethernet", False, 1500, ""),
    ),
    routes=(RouteEntry("0.0.0.0/0", "wlan0", 100, "192.0.2.1"),),
)


class SaveInterfacesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / "engagement.sqlite"
        initialize_database(self.db, "vantage test")

    def test_save_creates_the_scanner_root_and_its_interfaces(self) -> None:
        vantage_id, saved = save_interfaces(self.db, SNAPSHOT, scanner_name="scanner-a", operator="analyst")
        self.assertEqual(saved, 4)
        self.assertTrue(vantage_id)

        snapshot = load_map_snapshot(self.db)
        self.assertEqual(len(snapshot.nodes), 1)
        self.assertEqual(snapshot.nodes[0].kind, "root")
        self.assertEqual(snapshot.nodes[0].label, "scanner-a")
        self.assertEqual(snapshot.root_label, "scanner-a")
        self.assertIn("wlan0 192.0.2.12/24", snapshot.root_interfaces)
        self.assertIn("wlan0 2001:db8::12/64", snapshot.root_interfaces)
        self.assertIn("eth0", snapshot.root_interfaces)

    def test_saving_again_replaces_instead_of_duplicating(self) -> None:
        save_interfaces(self.db, SNAPSHOT, scanner_name="scanner-a")
        vantage_id, saved = save_interfaces(self.db, SNAPSHOT, scanner_name="scanner-a")
        self.assertEqual(saved, 4)
        conn = open_database(self.db, readonly=True)
        try:
            count = conn.execute(
                "SELECT COUNT(*) FROM vantage_interfaces WHERE vantage_point_id = ?", (vantage_id,)
            ).fetchone()[0]
            roots = conn.execute("SELECT COUNT(*) FROM topology_nodes WHERE kind = 'root'").fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(count, 4)
        self.assertEqual(roots, 1)

    def test_defaults_to_the_local_hostname(self) -> None:
        vantage_id, _saved = save_interfaces(self.db, SNAPSHOT)
        snapshot = load_map_snapshot(self.db)
        self.assertEqual(snapshot.root_label, socket.gethostname())
        self.assertTrue(vantage_id)

    def test_rejects_an_empty_scanner_name(self) -> None:
        with self.assertRaisesRegex(VantageStoreError, "scanner name"):
            save_interfaces(self.db, SNAPSHOT, scanner_name="   ")

    def test_enforces_the_interface_cap(self) -> None:
        too_many = InterfaceSnapshot(
            interfaces=tuple(
                InterfaceEntry(f"eth{index}", f"eth{index}", None, "ethernet", True, 1500, "")
                for index in range(MAX_INTERFACES + 1)
            ),
            routes=(),
        )
        with self.assertRaisesRegex(VantageStoreError, "more than"):
            save_interfaces(self.db, too_many, scanner_name="scanner-a")

    def test_cli_saves_after_printing_the_table(self) -> None:
        output = io.StringIO()
        with patch("lumos.cli.discover_interfaces", return_value=SNAPSHOT), redirect_stdout(output):
            code = main(["interfaces", str(self.db), "--save"])
        self.assertEqual(code, 0)
        self.assertIn("Interfaces:", output.getvalue())
        self.assertIn("Saved 4 interface(s) to vantage point", output.getvalue())
        self.assertTrue(load_map_snapshot(self.db).root_interfaces)

    def test_cli_save_requires_a_database_argument(self) -> None:
        errors = io.StringIO()
        with patch("lumos.cli.discover_interfaces", return_value=SNAPSHOT), \
                patch("sys.stderr", errors), redirect_stdout(io.StringIO()):
            code = main(["interfaces", "--save"])
        self.assertEqual(code, 2)
        self.assertIn("--save requires an engagement database path", errors.getvalue())

    def test_json_output_still_works_with_a_database(self) -> None:
        output = io.StringIO()
        with patch("lumos.cli.discover_interfaces", return_value=SNAPSHOT), redirect_stdout(output):
            code = main(["interfaces", str(self.db), "--json"])
        self.assertEqual(code, 0)
        self.assertIn('"interfaces"', output.getvalue())
        # Printing alone must not persist anything.
        self.assertEqual(load_map_snapshot(self.db).root_interfaces, ())


if __name__ == "__main__":
    unittest.main()
