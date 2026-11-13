"""The scan queue is a plan on disk: validated, atomic, never evidence."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from lumos.services import queue


class QueueTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / "eng.sqlite"
        self.db.write_bytes(b"")

    def _add(self, *targets: str, **kwargs) -> queue.Job:
        return queue.add_job(
            self.db, network=kwargs.get("network", "lab"), targets=list(targets),
            nmap_options=kwargs.get("nmap_options", ""),
            engine=kwargs.get("engine", "nmap"),
        )

    def test_the_queue_lives_beside_the_database(self) -> None:
        self.assertEqual(queue.queue_path(self.db).name, "eng.sqlite.queue.json")

    def test_an_absent_queue_is_empty_not_an_error(self) -> None:
        self.assertEqual(queue.load_jobs(self.db), ())

    def test_a_job_round_trips(self) -> None:
        job = self._add("192.0.2.10", "192.0.2.0/24", nmap_options="-sn")
        loaded = queue.load_jobs(self.db)[0]
        self.assertEqual(loaded.id, job.id)
        self.assertEqual(loaded.targets, ("192.0.2.10", "192.0.2.0/24"))
        self.assertEqual(loaded.nmap_options, "-sn")
        self.assertIn("2 target(s)", loaded.summary)

    def test_duplicate_targets_collapse_and_identical_jobs_are_refused(self) -> None:
        job = self._add("192.0.2.10", "192.0.2.10")
        self.assertEqual(job.targets, ("192.0.2.10",))
        with self.assertRaises(queue.QueueError):
            self._add("192.0.2.10")

    def test_the_queue_file_is_owner_only_and_written_atomically(self) -> None:
        self._add("192.0.2.10")
        path = queue.queue_path(self.db)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(os.listdir(self.tmp.name).count("eng.sqlite.queue.json"), 1)

    def test_removal_accepts_a_unique_id_prefix(self) -> None:
        job = self._add("192.0.2.10")
        self.assertTrue(queue.remove_job(self.db, job.id[:8]))
        self.assertEqual(queue.load_jobs(self.db), ())

    def test_removal_of_a_stranger_is_false(self) -> None:
        self._add("192.0.2.10")
        self.assertFalse(queue.remove_job(self.db, "not-a-job"))

    def test_clearing_reports_the_count(self) -> None:
        self._add("192.0.2.10")
        self._add("192.0.2.11")
        self.assertEqual(queue.clear(self.db), 2)
        self.assertEqual(queue.load_jobs(self.db), ())

    def test_a_bad_target_is_refused_before_it_is_stored(self) -> None:
        # A dotted quad outside every range parses as a hostname, which the
        # scope guard then requires an exact allow rule for; these three are
        # refusals at the syntax layer.
        for bad in ("not a host", "", "192.0.2.0/33"):
            with self.assertRaises(queue.QueueError):
                self._add(bad)

    def test_a_corrupt_file_is_a_sentence(self) -> None:
        queue.queue_path(self.db).write_text("{not json", encoding="utf-8")
        with self.assertRaises(queue.QueueError):
            queue.load_jobs(self.db)

    def test_a_foreign_json_file_is_refused(self) -> None:
        queue.queue_path(self.db).write_text(json.dumps({"jobs": []}), encoding="utf-8")
        with self.assertRaises(queue.QueueError):
            queue.load_jobs(self.db)

    def test_hostile_fields_are_sanitised_on_load(self) -> None:
        queue.queue_path(self.db).write_text(
            json.dumps({
                "format": "lumos-queue",
                "jobs": [{
                    "id": "j\x1b[2J1",
                    "network": "lab",
                    "targets": ["192.0.2.10"],
                    "nmap_options": "-sn\x1b[0m",
                    "engine": "rm -rf /",
                }],
            }),
            encoding="utf-8",
        )
        job = queue.load_jobs(self.db)[0]
        self.assertNotIn("\x1b", job.id)
        self.assertNotIn("\x1b", job.nmap_options)
        self.assertEqual(job.engine, "nmap", "an unknown engine falls back to nmap")

    def test_the_queue_is_capped(self) -> None:
        for index in range(queue.MAX_QUEUE_JOBS):
            self._add(f"192.0.2.{index}")
        with self.assertRaises(queue.QueueError):
            self._add("192.0.2.200")

    def test_next_job_is_the_first_added(self) -> None:
        first = self._add("192.0.2.10")
        self._add("192.0.2.11")
        self.assertEqual(queue.next_job(self.db).id, first.id)


if __name__ == "__main__":
    unittest.main()
