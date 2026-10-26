import csv
import importlib.util
import os
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch


def load_script_module():
    script_path = Path(__file__).with_name("failed_logins.py")
    spec = importlib.util.spec_from_file_location("failed_logins", script_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load {script_path}")

    module = importlib.util.module_from_spec(spec)
    original_directory = os.getcwd()
    with tempfile.TemporaryDirectory() as temporary_directory:
        try:
            os.chdir(temporary_directory)
            with patch("builtins.print"):
                spec.loader.exec_module(module)
        finally:
            os.chdir(original_directory)

    return module


failed_logins = load_script_module()


class AnalyzeLoginCsvTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.csv_path = Path(self.temporary_directory.name) / "events.csv"

    def make_event(self, username, result, minutes_ago):
        event_time = datetime.now() - timedelta(minutes=minutes_ago)
        return {
            "username": username,
            "result": result,
            "event_time": event_time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    def write_events(self, events):
        with self.csv_path.open("w", newline="", encoding="utf-8") as csv_file:
            writer = csv.DictWriter(
                csv_file,
                fieldnames=["username", "result", "event_time"],
            )
            writer.writeheader()
            writer.writerows(events)

    def test_five_recent_failed_logins_print_alert(self):
        self.write_events(
            [
                self.make_event("john", "failed", 10),
                self.make_event("john", "failed", 20),
                self.make_event("john", "failed", 30),
                self.make_event("john", "failed", 40),
                self.make_event("john", "failed", 50),
            ]
        )

        with patch("builtins.print") as mock_print:
            failed_logins.analyze_login_csv(str(self.csv_path))

        mock_print.assert_called_once_with(
            "ALERT: john has 5 failed login attempts"
        )

    def test_four_recent_failed_logins_do_not_print_alert(self):
        self.write_events(
            [
                self.make_event("john", "failed", 10),
                self.make_event("john", "failed", 20),
                self.make_event("john", "failed", 30),
                self.make_event("john", "failed", 40),
            ]
        )

        with patch("builtins.print") as mock_print:
            failed_logins.analyze_login_csv(str(self.csv_path))

        mock_print.assert_not_called()

    def test_successful_login_is_not_counted_as_failure(self):
        self.write_events(
            [
                self.make_event("john", "failed", 10),
                self.make_event("john", "failed", 20),
                self.make_event("john", "failed", 30),
                self.make_event("john", "failed", 40),
                self.make_event("john", "success", 5),
            ]
        )

        with patch("builtins.print") as mock_print:
            failed_logins.analyze_login_csv(str(self.csv_path))

        mock_print.assert_not_called()

    def test_failed_login_older_than_60_minutes_is_ignored(self):
        self.write_events(
            [
                self.make_event("john", "failed", 10),
                self.make_event("john", "failed", 20),
                self.make_event("john", "failed", 30),
                self.make_event("john", "failed", 40),
                self.make_event("john", "failed", 90),
            ]
        )

        with patch("builtins.print") as mock_print:
            failed_logins.analyze_login_csv(str(self.csv_path))

        mock_print.assert_not_called()

    def test_missing_csv_prints_warning_without_raising(self):
        missing_path = self.csv_path.parent / "missing.csv"

        with patch("builtins.print") as mock_print:
            failed_logins.analyze_login_csv(str(missing_path))

        mock_print.assert_called_once_with(
            f"WARNING: CSV file '{missing_path}' was not found."
        )


if __name__ == "__main__":
    unittest.main()