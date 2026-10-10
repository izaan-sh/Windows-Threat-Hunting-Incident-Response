# Sysmon Detection Coverage

Sysmon supplied process, network, and file-system telemetry used to reconstruct the simulated compromise.

## Event IDs used

| Event ID | Investigation use |
|---:|---|
| 1 | Process creation and process ancestry |
| 3 | Network connection |
| 8 | CreateRemoteThread event reviewed during false-positive triage |
| 11 | File creation |
| 23 | File deletion |

PowerShell Script Block Logging (`4104`) was collected separately from the PowerShell event source.

## Process attribution

Sysmon Event ID 1 helped investigate the `runas.exe` pivot:

```text
j.carter session
    └── powershell.exe
          └── runas.exe
                └── cmd.exe
```

The process ancestry added context that was not obvious from the Windows Security event alone.

## File telemetry gap

The initial file activity involving `C:\Temp\Finance\financial_report.txt` did not produce the expected Sysmon Event 11/23 telemetry.

The investigation identified that the Sysmon configuration did not cover generic file activity in that location. A targeted rule for `C:\Temp\Finance\*` was added, and the activity was repeated. The later test generated the expected file telemetry at approximately 12:05:38 UTC.

This was treated as a telemetry-coverage finding. Missing initial events did not prove the activity had not occurred.

## Network activity

Sysmon Event ID 3 was used to correlate `powershell.exe` with a connection to `10.10.1.20:8080`.

This was simulated C2-style outbound HTTP communication inside the isolated lab, not a real command-and-control channel or confirmed data exfiltration.

## Detection approach

The investigation correlated multiple sources rather than relying on a single event:

- Windows Security for authentication and account/group changes.
- Sysmon for process ancestry, network connections and targeted file telemetry.
- PowerShell Event 4104 for script-block visibility.
- Task Scheduler logs for persistence activity.
- Microsoft Sentinel KQL for correlation and hunting.
