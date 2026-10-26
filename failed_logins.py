import csv
from datetime import datetime, timedelta


def generate_test_csv(filename):
    now = datetime.now()

    events = [
        {
            "username": "john",
            "result": "failed",
            "event_time": (now - timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S"),
        },
        {
            "username": "john",
            "result": "failed",
            "event_time": (now - timedelta(minutes=20)).strftime("%Y-%m-%d %H:%M:%S"),
        },
        {
            "username": "john",
            "result": "failed",
            "event_time": (now - timedelta(minutes=30)).strftime("%Y-%m-%d %H:%M:%S"),
        },
        {
            "username": "john",
            "result": "failed",
            "event_time": (now - timedelta(minutes=90)).strftime("%Y-%m-%d %H:%M:%S"),
        },
        {
            "username": "anna",
            "result": "success",
            "event_time": (now - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S"),
        },
    ]

    with open(filename, "w", newline="", encoding="utf-8") as csv_file:
        fieldnames = ["username", "result", "event_time"]
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(events)


def analyze_login_csv(filename):
    now = datetime.now()
    cutoff = now - timedelta(minutes=60)
    failed_by_user = {}

    try:
        with open(filename, "r", newline="", encoding="utf-8") as csv_file:
            reader = csv.DictReader(csv_file)

            for row_number, row in enumerate(reader, start=2):
                username = (row.get("username") or "").strip()
                result = (row.get("result") or "").strip().lower()
                event_time_text = (row.get("event_time") or "").strip()

                missing_fields = []
                if not username:
                    missing_fields.append("username")
                if not result:
                    missing_fields.append("result")
                if not event_time_text:
                    missing_fields.append("event_time")

                if missing_fields:
                    print(
                        f"WARNING: row {row_number} is missing: "
                        f"{', '.join(missing_fields)}"
                    )
                    continue

                if result not in ("failed", "success"):
                    print(f"WARNING: row {row_number} has an invalid result")
                    continue

                try:
                    event_time = datetime.strptime(
                        event_time_text, "%Y-%m-%d %H:%M:%S"
                    )
                except ValueError:
                    print(f"WARNING: row {row_number} has an invalid event_time")
                    continue

                if result == "failed" and cutoff <= event_time <= now:
                    failed_by_user[username] = failed_by_user.get(username, 0) + 1
    except FileNotFoundError:
        print(f"WARNING: CSV file '{filename}' was not found.")
        return

    for username, count in failed_by_user.items():
        if count >= 5:
            print(f"ALERT: {username} has {count} failed login attempts")


generate_test_csv("login_events.csv")
analyze_login_csv("login_events.csv")