"""Bare `lumos` opens the interface; subcommands keep working."""

from __future__ import annotations

import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lumos.cli import main
from lumos.core.database import initialize_database


class DefaultCommandTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.db = self.dir / "engagement.sqlite"
        initialize_database(self.db, "default command")
        patcher = patch.dict(os.environ, {"XDG_STATE_HOME": str(self.dir / "state")}, clear=False)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_bare_lumos_uses_lumos_db(self) -> None:
        with patch.dict(os.environ, {"LUMOS_DB": str(self.db)}):
            with patch("lumos.tui.app.run_tui", return_value=0) as runner:
                self.assertEqual(main([]), 0)
        runner.assert_called_once()
        self.assertEqual(Path(runner.call_args[0][0]).resolve(), self.db.resolve())

    def test_path_argument_opens_that_database(self) -> None:
        with patch.dict(os.environ, {"LUMOS_DB": ""}):
            with patch("lumos.tui.app.run_tui", return_value=0) as runner:
                self.assertEqual(main([str(self.db)]), 0)
        self.assertEqual(Path(runner.call_args[0][0]).resolve(), self.db.resolve())

    def test_extra_arguments_after_a_path_are_a_usage_error(self) -> None:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            self.assertEqual(main([str(self.db), "--oops"]), 2)
        self.assertIn("unexpected arguments", stderr.getvalue())

    def test_missing_database_path_reports_and_returns_two(self) -> None:
        stderr = io.StringIO()
        with patch.dict(os.environ, {"LUMOS_DB": ""}):
            with contextlib.redirect_stderr(stderr):
                self.assertEqual(main([str(self.dir / "nope.sqlite")]), 2)
        self.assertIn("no engagement database", stderr.getvalue())

    def test_bare_lumos_without_a_database_or_tty_explains_itself(self) -> None:
        stderr = io.StringIO()
        with patch.dict(os.environ, {"LUMOS_DB": ""}):
            with contextlib.redirect_stderr(stderr):
                self.assertEqual(main([]), 0)
        self.assertIn("no database selected", stderr.getvalue())

    def test_version_option_still_works(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            with self.assertRaises(SystemExit) as raised:
                main(["--version"])
        self.assertEqual(raised.exception.code, 0)
        self.assertIn("lumos", stdout.getvalue())

    def test_tui_subcommand_is_still_accepted(self) -> None:
        with patch("lumos.tui.app.run_tui", return_value=0) as runner:
            self.assertEqual(main(["tui", str(self.db)]), 0)
        runner.assert_called_once()

    def test_db_check_still_reports_a_valid_database(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            self.assertEqual(main(["db", "check", str(self.db)]), 0)
        self.assertIn("Valid Lumos database", stdout.getvalue())
