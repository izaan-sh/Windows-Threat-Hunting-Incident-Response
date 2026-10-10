# Investigation

This folder documents the investigation of a controlled Windows endpoint compromise simulation in an isolated lab. It records the event timeline, findings, indicators, and ATT&CK mapping used to explain the activity observed in Microsoft Sentinel and endpoint telemetry.

> **Scope note:** This is a lab simulation, not a real-world incident. The Kali system (`10.10.1.20`) is the attacker host on the isolated lab subnet, not an external internet host. The HTTP activity is described as simulated C2-style outbound communication; it does not by itself demonstrate real command and control or data exfiltration.

## Investigation objectives

- Reconstruct the sequence of authentication and post-authentication activity.
- Correlate Windows Security events, Sysmon, PowerShell, and Task Scheduler telemetry.
- Distinguish observed evidence from interpretation and identify telemetry limitations.
- Record findings that can be reproduced and reviewed during an interview.

## Contents

- [`timeline/incident-timeline.md`](timeline/incident-timeline.md) — event sequence and interpretation.
- [`findings/investigation-findings.md`](findings/investigation-findings.md) — key findings, supporting evidence, and limitations.
- [`findings/iocs.md`](findings/iocs.md) — lab indicators and relevant paths/accounts.
- [`findings/mitre-mapping.md`](findings/mitre-mapping.md) — conservative ATT&CK mapping for simulated behaviors.
- [`evidence/evidence-index.md`](evidence/evidence-index.md) — suggested evidence index and screenshot naming.

## Investigation approach

1. Establish the time range and confirm whether timestamps are UTC or local time.
2. Review authentication events and identify failed and successful logons.
3. Pivot from the account and session into process, PowerShell, account-management, scheduled-task, file, and network telemetry.
4. Correlate events by timestamp, account, process ancestry, host, and relevant fields.
5. Record each conclusion with its evidence and confidence; do not treat a missing event as proof that an action did not occur.
6. Carry validated findings into the incident-response section.

## Important validation notes

- The project notes list several timestamps in UTC. Preserve the timezone when comparing events.
- Event fields and table schemas can vary by connector and collection configuration. Validate query fields in the workspace before reusing queries.
- A five-minute bucket correlation can show failures and a success in the same bucket, but it does not prove strict event ordering.
- The file-telemetry gap was identified during the simulation: the first activity did not produce the expected Sysmon file events until targeted coverage for `C:\Temp\Finance\*` was added and the activity was repeated.
