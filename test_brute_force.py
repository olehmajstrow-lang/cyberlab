import csv
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import brute_force


class AnalyzeLoginCsvTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.csv_path = Path(self.temporary_directory.name) / "events.csv"

    def make_event(self, username, result, minutes_ago, source_ip="203.0.113.10"):
        event_time = datetime.now() - timedelta(minutes=minutes_ago)
        return {
            "username": username,
            "result": result,
            "source_ip": source_ip,
            "event_time": event_time.strftime(brute_force.TIME_FORMAT),
        }


    def write_events(self, events):
        with self.csv_path.open("w", newline="", encoding="utf-8") as csv_file:
            writer = csv.DictWriter(
                csv_file,
                fieldnames=["username", "result", "source_ip", "event_time"],
            )
            writer.writeheader()
            writer.writerows(events)

    def test_five_failed_logins_within_ten_minutes_print_alert(self):
        self.write_events(
            [
                self.make_event("jane", "failed", 1),
                self.make_event("jane", "failed", 2),
                self.make_event("jane", "failed", 3),
                self.make_event("jane", "failed", 4),
                self.make_event("jane", "failed", 5),
            ]
        )

        with patch("builtins.print") as mock_print:
            brute_force.analyze_login_csv(str(self.csv_path))

        mock_print.assert_called_once_with(
            "ALERT: jane had 5 failed login attempts within 10 minutes"
        )

    def test_four_failed_logins_within_ten_minutes_do_not_alert(self):
        self.write_events(
            [
                self.make_event("jane", "failed", 1),
                self.make_event("jane", "failed", 2),
                self.make_event("jane", "failed", 3),
                self.make_event("jane", "failed", 4),
            ]
        )

        with patch("builtins.print") as mock_print:
            brute_force.analyze_login_csv(str(self.csv_path))

        mock_print.assert_not_called()

    def test_five_failed_logins_across_twenty_minutes_do_not_alert(self):
        self.write_events(
            [
                self.make_event("jane", "failed", 1),
                self.make_event("jane", "failed", 6),
                self.make_event("jane", "failed", 11),
                self.make_event("jane", "failed", 16),
                self.make_event("jane", "failed", 20),
            ]
        )

        with patch("builtins.print") as mock_print:
            brute_force.analyze_login_csv(str(self.csv_path))

        mock_print.assert_not_called()

    def test_successful_logins_are_ignored(self):
        self.write_events(
            [
                self.make_event("jane", "failed", 1),
                self.make_event("jane", "failed", 2),
                self.make_event("jane", "failed", 3),
                self.make_event("jane", "failed", 4),
                self.make_event("jane", "success", 5),
            ]
        )

        with patch("builtins.print") as mock_print:
            brute_force.analyze_login_csv(str(self.csv_path))

        mock_print.assert_not_called()

    def test_successful_login_does_not_count_toward_distinct_usernames(self):
        self.write_events(
            [
                self.make_event("jane", "failed", 1),
                self.make_event("alex", "failed", 2),
                self.make_event("sam", "success", 3),
            ]
        )

        with patch("builtins.print") as mock_print:
            brute_force.analyze_login_csv(str(self.csv_path))

        mock_print.assert_not_called()

    
    def test_three_failed_logins_followed_by_success_prints_alert(self):
        self.write_events(
            [
                self.make_event("alex", "failed", 9),
                self.make_event("alex", "failed", 7),
                self.make_event("alex", "failed", 5),
                self.make_event("alex", "success", 2),
            ]
        )

        with patch("builtins.print") as mock_print:
            brute_force.analyze_login_csv(str(self.csv_path))

        self.assertTrue(
            any(
                "failed login attempts followed by a successful login"
                in str(call)
                for call in mock_print.call_args_list
            )
        )

    
    def test_success_after_ten_minute_window_does_not_trigger_new_alert(self):
        self.write_events(
            [
                self.make_event("alex", "failed", 20),
                self.make_event("alex", "failed", 18),
                self.make_event("alex", "failed", 16),
                self.make_event("alex", "success", 2),
            ]
        )

        with patch("builtins.print") as mock_print:
            brute_force.analyze_login_csv(str(self.csv_path))

        self.assertFalse(
            any(
                "failed login attempts followed by a successful login"
                in str(call)
                for call in mock_print.call_args_list
            )
        )

    def test_missing_csv_prints_warning_without_raising(self):
        missing_path = self.csv_path.parent / "missing.csv"

        with patch("builtins.print") as mock_print:
            brute_force.analyze_login_csv(str(missing_path))

        mock_print.assert_called_once_with(
            f"WARNING: CSV file '{missing_path}' was not found."
        )


if __name__ == "__main__":
    unittest.main()