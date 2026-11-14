"""Duplicate proposals: the scanner suspects, a human decides, the record stays."""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from lumos.services import demo, duplicates


class DuplicateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / "eng.sqlite"
        demo.build_demo(self.db)

    def _count(self, table: str) -> int:
        conn = sqlite3.connect(self.db)
        try:
            return int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
        finally:
            conn.close()

    def test_the_demo_records_a_proposal_without_merging_anything(self) -> None:
        proposals = duplicates.list_proposals(self.db)
        self.assertEqual(len(proposals), 1)
        self.assertEqual(proposals[0].decision, "")
        self.assertIn("candidate only", str(proposals[0].evidence))
        self.assertEqual(self._count("devices"), self._count(
            "topology_nodes"
        ) - 4, "one device node each, plus root and three zones")

    def test_accepting_merges_the_pair_and_keeps_the_evidence(self) -> None:
        proposal = duplicates.list_proposals(self.db)[0]
        before_devices = self._count("devices")
        before_observations = self._count("host_observations")
        self.assertTrue(
            duplicates.decide(self.db, proposal.id, "accepted_link", author="tester")
        )
        self.assertEqual(self._count("devices"), before_devices - 1)
        self.assertEqual(self._count("host_observations"), before_observations)
        self.assertEqual(duplicates.list_proposals(self.db), ())
        decided = duplicates.list_proposals(self.db, include_decided=True)
        self.assertEqual(decided[0].decision, "accepted_link")

    def test_a_decision_cannot_be_taken_twice(self) -> None:
        proposal = duplicates.list_proposals(self.db)[0]
        duplicates.decide(self.db, proposal.id, "rejected", author="tester")
        with self.assertRaises(duplicates.DuplicateError):
            duplicates.decide(self.db, proposal.id, "accepted_link", author="tester")

    def test_rejecting_leaves_both_devices_alone(self) -> None:
        proposal = duplicates.list_proposals(self.db)[0]
        before = self._count("devices")
        self.assertFalse(duplicates.decide(self.db, proposal.id, "rejected", author="tester"))
        self.assertEqual(self._count("devices"), before)

    def test_bad_input_is_refused_with_a_sentence(self) -> None:
        proposal = duplicates.list_proposals(self.db)[0]
        with self.assertRaises(duplicates.DuplicateError):
            duplicates.decide(self.db, "no-such-id", "rejected", author="tester")
        with self.assertRaises(duplicates.DuplicateError):
            duplicates.decide(self.db, proposal.id, "maybe", author="tester")
        with self.assertRaises(duplicates.DuplicateError):
            duplicates.decide(self.db, proposal.id, "rejected", author="  ")


if __name__ == "__main__":
    unittest.main()
