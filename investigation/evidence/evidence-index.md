# Evidence Index

Use this index to keep screenshots and exported event records organized. Include only evidence actually captured from the lab; do not create placeholder screenshots or present illustrative evidence as real output.

| Suggested filename | Evidence to capture | Why it matters |
|---|---|---|
| `01-authentication-sequence.png` | Relevant failed and successful logons in Sentinel | Establishes the authentication timeline. |
| `02-powershell-activity.png` | PowerShell script-block/process evidence | Supports reconnaissance analysis. |
| `03-runas-process-tree.png` | Process ancestry showing `runas.exe` and child process | Provides context for the account-context pivot. |
| `04-account-creation-4720.png` | Event 4720 with relevant account fields | Supports local account creation. |
| `05-group-change-4732.png` | Event 4732 with group/target details | Supports administrative group modification. |
| `06-scheduled-task-evidence.png` | Task details and matching Task Scheduler/security events | Supports persistence analysis. |
| `07-file-coverage-gap.png` | Initial missing-event query and targeted configuration change | Documents the visibility gap and correction. |
| `08-file-events-after-fix.png` | Later file-event results after repeating the test | Shows improved telemetry coverage. |
| `09-http-network-correlation.png` | Sysmon Event 3 and Kali HTTP access log | Correlates the simulated HTTP request. |
| `10-master-timeline.png` | Final correlated timeline | Gives reviewers a single chronology. |

## Evidence hygiene

- Preserve the source query and selected time range where practical.
- Keep timezone explicit (UTC vs local time).
- Redact credentials, tokens, personal data, and unrelated tenant identifiers.
- For each finding, record the supporting event IDs and the screenshot or export filename.
- If a query returns no results, note the exact time range and table searched; absence of results is not proof that the behavior did not occur.
