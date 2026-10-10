# Detection Engineering

This section documents the detection logic and telemetry used to investigate the simulated Windows compromise in Microsoft Sentinel.

> **Scope:** All activity described here was generated in an isolated lab. Results are lab evidence, not production incidents.

## Primary Sentinel analytics rule

**Rule:** `Successful Logon Following Multiple Failed Attempts (Brute Force)`

The rule correlates failed Windows logons (`4625`) and a successful logon (`4624`) for the same account and source IP within a five-minute time bucket. The lab evidence included eight failed attempts followed by a successful protocol-level authentication from the attacker host.

**Important:** Because the query uses `bin(TimeGenerated, 5m)`, it identifies events in the same five-minute bucket. It does not independently prove that the successful logon occurred immediately after the failures.

## Telemetry used

| Activity | Source | Event ID |
|---|---|---:|
| Failed logon | Windows Security | 4625 |
| Successful logon | Windows Security | 4624 |
| Session logoff | Windows Security | 4634 |
| Local account creation | Windows Security | 4720 |
| Local group membership change | Windows Security | 4732 |
| Scheduled task creation/deletion | Windows Security | 4698 / 4699 |
| Process creation | Sysmon | 1 |
| Network connection | Sysmon | 3 |
| Remote-thread event investigated for false positive | Sysmon | 8 |
| File creation/deletion | Sysmon | 11 / 23 |
| PowerShell script block | PowerShell | 4104 |
| Task Scheduler activity | Task Scheduler | 106, 140, 200, 201 |

## Repository contents

- `sentinel-rules/01-successful-logon-after-failed-attempts.kql` — primary analytics-rule query.
- `sentinel-rules/02-supporting-hunts.kql` — queries used to investigate and correlate the simulated activity.
- `sysmon/coverage.md` — telemetry coverage, process attribution, network visibility, and the file-monitoring gap.

## Screenshots to include

Save selected evidence in the main repository's `screenshots/` folder:

1. `03-detection/01-analytics-rule-configuration.png`
2. `03-detection/02-sentinel-incident.png`
3. `03-detection/03-authentication-correlation-query.png`
4. `04-hunting/01-powershell-hunt.png`
5. `04-hunting/02-account-creation-hunt.png`
6. `04-hunting/03-master-correlation-timeline.png`

Use screenshots of your actual workspace and query results. Avoid including credentials, access tokens, subscription identifiers, or unrelated personal information.
