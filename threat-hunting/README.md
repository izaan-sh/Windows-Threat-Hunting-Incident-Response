# Threat Hunting — Windows Threat Hunting & Incident Response Lab

This folder contains the eight investigative hunts used during the simulated Windows endpoint compromise. The hunts are designed to move from individual signals to a correlated timeline in Microsoft Sentinel.

## Environment

- Windows endpoint: `WKS-FIN-01` (`10.10.1.10`)
- Attacker-controlled Kali host: `KALI-ATT-01` (`10.10.1.20`)
- SIEM: Microsoft Sentinel / Log Analytics
- Primary tables: `SecurityEvent` for Windows Security Events via AMA; `Event` for Sysmon and other collected Windows event channels.
- Incident date used in the original lab queries: **7 October 2026 (UTC)**.

> **Important:** These queries are based on the lab's Phase 6 hunt set. Validate each query against the actual table schema and collected event fields in your workspace before running it or describing it as tested. Event field extraction can vary with the event source and DCR configuration. The queries are not a guarantee that every field will be populated in every environment.

## Hunt workflow

1. Run each query separately in Sentinel Logs.
2. Use the incident date/time window shown in the query; adjust it if your workspace uses a different investigation window.
3. Inspect the raw event alongside the query output when an extracted field is empty or unexpected.
4. Correlate findings by timestamp, account, source IP, process, and event ID rather than treating a single event as conclusive.
5. Save useful results and capture screenshots of the key hunts for the portfolio.
6. Run Hunt 8 last to review the chronological narrative across the incident window.

## Hunts included

| File | Investigative question | Primary telemetry |
|---|---|---|
| `queries/01-failed-authentication.kql` | Which users experienced multiple failed authentication attempts? | Security Event 4625 |
| `queries/02-success-after-failures.kql` | Which accounts successfully authenticated after repeated failures? | Security Events 4624, 4625 |
| `queries/03-powershell-activity.kql` | What PowerShell script-block activity occurred? | PowerShell 4104 in `Event` |
| `queries/04-new-accounts.kql` | Were any new accounts created? | Security Event 4720 |
| `queries/05-administrative-privileges.kql` | Did newly created accounts receive administrative privileges? | Security Event 4732, cross-check with 4720 |
| `queries/06-scheduled-tasks.kql` | Were scheduled tasks created or run? | Security Event 4698; Task Scheduler 106/140/200/201 |
| `queries/07-network-connections.kql` | Which processes initiated network connections? | Sysmon Event 3 in `Event` |
| `queries/08-master-timeline.kql` | What happened before, during, and after suspicious activity? | Combined `SecurityEvent` and `Event` |

## Key investigation themes

- Repeated authentication failures and subsequent successful authentication.
- PowerShell script-block activity during the incident window.
- Local account creation and changes to local group membership.
- Scheduled-task activity as a possible persistence mechanism.
- Process-to-network correlation, including the simulated HTTP request to Kali on `10.10.1.20:8080`.
- Chronological correlation across Security, Sysmon, and Task Scheduler telemetry.

## Known query/telemetry caveats

- **Authentication correlation:** Hunt 2 compares a successful logon with the last failed logon for the same account and IP and uses a five-minute window. Validate that the account/IP fields are populated consistently and that the query matches the intended scenario.
- **Group membership:** Event 4732's `MemberName` may be represented as a SID instead of a readable username. Cross-check the event details and the Stage 4/5 evidence rather than relying only on text extraction or an assumed join.
- **PowerShell and Sysmon parsing:** Hunts 3 and 7 parse `EventData` XML. If the query errors or extracted values are empty, inspect a raw event and adapt the parser to the actual schema.
- **Network terminology:** The connection to `10.10.1.20:8080` is simulated C2-style outbound HTTP communication inside the isolated lab. It is not evidence of real command-and-control infrastructure or data exfiltration.
- **File telemetry gap:** The project found that the initial file activity did not produce the expected Sysmon file events until a targeted path rule was added and the activity was repeated. See the detection coverage notes in the `detections/` section.

## Portfolio screenshots

Suggested evidence to include (use screenshots from your own Sentinel workspace):

- `screenshots/04-hunting/01-failed-authentication-hunt.png`
- `screenshots/04-hunting/02-success-after-failures-hunt.png`
- `screenshots/04-hunting/03-powershell-hunt.png`
- `screenshots/04-hunting/04-account-creation-hunt.png`
- `screenshots/04-hunting/05-administrative-group-hunt.png`
- `screenshots/04-hunting/06-scheduled-task-hunt.png`
- `screenshots/04-hunting/07-network-connection-hunt.png`
- `screenshots/04-hunting/08-master-correlation-timeline.png`

Prioritize the authentication correlation, PowerShell activity, account/group changes, and master timeline if you want to keep the repository concise. Remove any credentials, tokens, or unrelated personal data from screenshots.
