# Python SOC Login Monitoring Lab

A beginner SOC Analyst learning project for practicing basic login-event analysis with Python's standard library. The scripts read or generate CSV login events and print alerts when configured activity thresholds are met.

## Detection Rules

`brute_force.py` evaluates login events using these rules:

1. **Repeated failures for one username:** Alert when one username has five or more failed login attempts within a rolling 10-minute window.
2. **One source IP targeting multiple usernames:** Alert when one source IP has failed login attempts against three or more distinct usernames within a rolling 10-minute window.
3. **Failures followed by success:** Alert when at least three failed attempts for one username occur before a successful login for that same username, with those failures falling within the 10-minute window immediately preceding the success.

All three rules count failed events where applicable; successful logins do not contribute to failed-attempt thresholds. The analyzer also warns about missing required row data, invalid timestamps, and missing CSV files.

## Project Files

- `brute_force.py` — Generates `sample_login_events.csv` with `username`, `result`, `source_ip`, and `event_time` fields, then analyzes it with the three rules above.
- `failed_logins.py` — Generates `login_events.csv` and analyzes it for five or more failed attempts per username in the most recent 60 minutes. This is a separate, simpler detector from `brute_force.py`.
- `test_brute_force.py` — Unit tests for the `brute_force.py` analyzer, including threshold, time-window, successful-login, and missing-file behavior.
- `test_failed_logins.py` — Unit tests for the `failed_logins.py` analyzer, including its recent-failure threshold, successful-login exclusion, 60-minute cutoff, and missing-file behavior.

## Prerequisites

- Python 3
- No third-party packages; the scripts use Python's standard library.

## Setup and Usage

Run commands from the project directory. Check that Python is available:

```powershell
python --version
```

Run the three-rule analyzer (generates or overwrites `sample_login_events.csv` in the current directory):

```powershell
python brute_force.py
```

Run the 60-minute failed-login analyzer (generates or overwrites `login_events.csv` in the current directory):

```powershell
python failed_logins.py
```

Run all unit tests:

```powershell
python -m unittest discover -v
```

## Example Alert Output

Running `brute_force.py` with its generated sample data produced:

```text
ALERT: alice had 5 failed login attempts within 10 minutes
ALERT: source IP 203.0.113.10 had failed login attempts against 3 distinct usernames within 10 minutes
ALERT: alice had 3 failed login attempts followed by a successful login within 10 minutes
```

The generated timestamps vary each time the sample CSV is created. The generated sample for `failed_logins.py` does not meet its five-failures-in-60-minutes threshold, so it does not produce an alert by default.

## Interpreting Alerts

These alerts identify activity that may warrant investigation; they do **not** prove an account was compromised. A SOC analyst should review the surrounding events and other available context before drawing a conclusion.
