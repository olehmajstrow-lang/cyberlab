import csv
from datetime import datetime, timedelta


TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
WINDOW = timedelta(minutes=10)
MIN_FAILED_ATTEMPTS = 5
MIN_DISTINCT_USERNAMES = 3


def generate_test_csv(filename):
	now = datetime.now()
	events = [
		{
            "username": "mark",
            "result": "failed",
		    "source_ip": "198.51.100.20",
		    "event_time": (now - timedelta(minutes=1)).strftime(TIME_FORMAT),
		},
		{
		    "username": "mark",
		    "result": "failed",
		    "source_ip": "198.51.100.20",
		    "event_time": (now - timedelta(minutes=6)).strftime(TIME_FORMAT),
		},
		{
		    "username": "mark",
		    "result": "failed",
		    "source_ip": "198.51.100.20",
		    "event_time": (now - timedelta(minutes=11)).strftime(TIME_FORMAT),
		},
		{
		    "username": "mark",
		    "result": "failed",
		    "source_ip": "198.51.100.20",
		    "event_time": (now - timedelta(minutes=16)).strftime(TIME_FORMAT),
		},
		{
		    "username": "mark",
		    "result": "failed",
		    "source_ip": "198.51.100.20",
		    "event_time": (now - timedelta(minutes=20)).strftime(TIME_FORMAT),
		},
		{
			"username": "alice",
			"result": "failed",
			"source_ip": "203.0.113.10",
			"event_time": (now - timedelta(minutes=1)).strftime(TIME_FORMAT),
		},
		{
			"username": "alice",
			"result": "failed",
			"source_ip": "203.0.113.10",
			"event_time": (now - timedelta(minutes=3)).strftime(TIME_FORMAT),
		},
		{
			"username": "alice",
			"result": "failed",
			"source_ip": "203.0.113.10",
			"event_time": (now - timedelta(minutes=5)).strftime(TIME_FORMAT),
		},
		{
			"username": "alice",
			"result": "failed",
			"source_ip": "203.0.113.10",
			"event_time": (now - timedelta(minutes=7)).strftime(TIME_FORMAT),
		},
		{
			"username": "alice",
			"result": "failed",
			"source_ip": "203.0.113.10",
			"event_time": (now - timedelta(minutes=9)).strftime(TIME_FORMAT),
		},
		{
			"username": "alice",
			"result": "success",
			"source_ip": "203.0.113.10",
			"event_time": (now - timedelta(minutes=4)).strftime(TIME_FORMAT),
		},
		{
			"username": "bob",
			"result": "failed",
			"source_ip": "203.0.113.10",
			"event_time": (now - timedelta(minutes=1)).strftime(TIME_FORMAT),
		},
		{
			"username": "bob",
			"result": "failed",
			"source_ip": "203.0.113.10",
			"event_time": (now - timedelta(minutes=4)).strftime(TIME_FORMAT),
		},
		{
			"username": "bob",
			"result": "failed",
			"source_ip": "203.0.113.10",
			"event_time": (now - timedelta(minutes=8)).strftime(TIME_FORMAT),
		},
		{
			"username": "carol",
			"result": "failed",
			"source_ip": "203.0.113.10",
			"event_time": (now - timedelta(minutes=6)).strftime(TIME_FORMAT),
		},
	]

	with open(filename, "w", newline="", encoding="utf-8") as csv_file:
		fieldnames = ["username", "result", "source_ip", "event_time"]
		writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
		writer.writeheader()
		writer.writerows(events)


def analyze_login_csv(filename):
	failed_times_by_user = {}
	login_events_by_user = {}
	failed_users_by_source_ip = {}

	try:
		with open(filename, "r", newline="", encoding="utf-8") as csv_file:
			reader = csv.DictReader(csv_file)

			for row_number, row in enumerate(reader, start=2):
				username = (row.get("username") or "").strip()
				result = (row.get("result") or "").strip().lower()
				source_ip = (row.get("source_ip") or "").strip()
				event_time_text = (row.get("event_time") or "").strip()

				if not username or not result or not event_time_text:
					print(f"WARNING: row {row_number} is missing required data.")
					continue

				if result not in ("failed", "success"):
					continue

				try:
					event_time = datetime.strptime(event_time_text, TIME_FORMAT)
				except ValueError:
					print(f"WARNING: row {row_number} has an invalid event_time.")
					continue

				login_events_by_user.setdefault(username, []).append((event_time, result))
				if result == "failed":
					failed_times_by_user.setdefault(username, []).append(event_time)
				if source_ip:
					failed_users_by_source_ip.setdefault(source_ip, []).append(
						(event_time, username)
					)
	except FileNotFoundError:
		print(f"WARNING: CSV file '{filename}' was not found.")
		return

	for username, event_times in failed_times_by_user.items():
		event_times.sort()
		window_start = 0
		largest_window_count = 0

		for window_end, event_time in enumerate(event_times):
			while event_time - event_times[window_start] > WINDOW:
				window_start += 1

			attempts_in_window = window_end - window_start + 1
			largest_window_count = max(largest_window_count, attempts_in_window)

		if largest_window_count >= MIN_FAILED_ATTEMPTS:
			print(
				f"ALERT: {username} had {largest_window_count} failed login "
				"attempts within 10 minutes"
			)

	for source_ip, failed_events in failed_users_by_source_ip.items():
		failed_events.sort()
		window_start = 0
		user_counts_in_window = {}
		largest_distinct_user_count = 0

		for window_end, (event_time, username) in enumerate(failed_events):
			while event_time - failed_events[window_start][0] > WINDOW:
				old_username = failed_events[window_start][1]
				user_counts_in_window[old_username] -= 1
				if user_counts_in_window[old_username] == 0:
					del user_counts_in_window[old_username]
				window_start += 1

			user_counts_in_window[username] = (
				user_counts_in_window.get(username, 0) + 1
			)
			largest_distinct_user_count = max(
				largest_distinct_user_count, len(user_counts_in_window)
			)

		if largest_distinct_user_count >= MIN_DISTINCT_USERNAMES:
			print(
				f"ALERT: source IP {source_ip} had failed login attempts "
				f"against {largest_distinct_user_count} distinct usernames "
				"within 10 minutes"
			)
	# Detect failed logins followed by a successful login.
	for username, events in login_events_by_user.items():
		events.sort(key=lambda event: event[0])

		for success_index, (success_time, result) in enumerate(events):
			if result != "success":
				continue

			window_start = success_time - WINDOW
			failed_before_success = [
				event_time
				for event_time, event_result in events[:success_index]
				if event_result == "failed"
				and window_start <= event_time < success_time
			]

			if len(failed_before_success) >= 3:
				print(
					f"ALERT: {username} had {len(failed_before_success)} "
					"failed login attempts followed by a successful login "
					"within 10 minutes"
				)
				break


if __name__ == "__main__":
	sample_file = "sample_login_events.csv"
	generate_test_csv(sample_file)
	analyze_login_csv(sample_file)
