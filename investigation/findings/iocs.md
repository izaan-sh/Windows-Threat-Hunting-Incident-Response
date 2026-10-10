# Lab Indicators and Investigation Pivots

These are **simulation-specific pivots**, not confirmed indicators of compromise from a real environment. Do not submit them to public threat-intelligence feeds as real malicious infrastructure.

| Type | Value | Context | Handling note |
|---|---|---|---|
| Attacker-host IP | `10.10.1.20` | Kali attacker host on the isolated lab subnet | Private lab address; not an external internet host. |
| Windows endpoint IP | `10.10.1.10` | `WKS-FIN-01` | Lab endpoint. |
| Local account | `j.carter` | Initial simulated user context | Validate exact casing and event fields in raw records. |
| Local account | `labadmin` | Account context used in the `runas` pivot | Do not infer original initiator from subject alone. |
| Local account | `lab_attacker` | Simulated account creation and group modification | Correlate Event 4720 and 4732. |
| Scheduled task | `SystemHealthCheck` | Simulated persistence behavior | Review action and task definition; name alone is not proof. |
| File path | `C:\Temp\Finance\financial_report.txt` | Simulated file-staging behavior | Dummy lab file; no actual sensitive data should be included. |
| Network destination | `10.10.1.20:8080` | Python HTTP server on Kali | Simulated C2-style HTTP only; not proof of actual C2/exfiltration. |
| Sysmon coverage path | `C:\Temp\Finance\*` | Targeted file-event coverage added after a gap was found | Document the configuration version used for the repeated test. |

## Recommended investigation pivots

- Account + time range: review 4624, 4625, 4720, and 4732.
- Process ancestry: correlate Sysmon Event 1 with the user/session and `runas.exe` activity.
- PowerShell: review Event 4104 and process-creation evidence together.
- Persistence: correlate task-creation and Task Scheduler operational events with the task action and process events.
- Network: correlate Sysmon Event 3 with process image, destination, and the Kali HTTP access log.
- File activity: review Event 11 / Event 23 only within the verified Sysmon configuration and collection window.
