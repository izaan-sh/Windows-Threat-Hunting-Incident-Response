# Investigation Findings

## Finding 1 — Repeated authentication failures followed by access

**Observation:** The project notes record eight failed RDP logons between approximately 09:18:49 and 09:19:17 UTC, followed by a successful protocol-authentication record around 09:19:21 UTC. A later interactive logon (Event 4624, Logon Type 10) is noted around 10:07:34 UTC.

**Assessment:** This sequence warranted review of the account, source IP, and session details. The protocol-authentication event and later interactive logon should remain separate timeline entries unless raw evidence establishes they represent the same session.

**Evidence to retain:** Raw 4625 and 4624 events, the analytics-rule query/results, and a screenshot of the relevant Sentinel time range.

## Finding 2 — PowerShell activity and account-context pivot

**Observation:** PowerShell reconnaissance was recorded using process-creation and script-block telemetry. The notes describe `runas.exe` being used to launch a process under `labadmin` from the earlier `j.carter` session.

**Assessment:** Process ancestry provides useful context for understanding how activity moved into a different account context. A later Security event showing `labadmin` as the subject does not, by itself, prove who initiated the original process.

**Evidence to retain:** Sysmon Event 1 records, PowerShell Event 4104 records where available, and the process-tree screenshot.

## Finding 3 — Local account creation and administrative group modification

**Observation:** The project notes record creation of `lab_attacker` around 10:21:52 UTC (Security Event 4720) and addition to the local Administrators group around 10:22:14 UTC (Event 4732).

**Assessment:** The close sequence is consistent with simulated account creation followed by privilege assignment. Confirm the target account, group, and subject details in raw event data before using the events as definitive attribution evidence.

**Evidence to retain:** Events 4720 and 4732, command evidence, and local user/group verification screenshots.

## Finding 4 — Scheduled-task activity

**Observation:** A scheduled task named `SystemHealthCheck` was created around 10:34:19 UTC and execution was noted around 10:34:45 UTC. The project notes reference Security Event 4698 and Task Scheduler events 106/140/200/201.

**Assessment:** The task name alone is not a malicious indicator. Review its task definition, executable/action, run context, and process telemetry. The notes also identify an attribution discrepancy across sources, which should be documented rather than silently resolved.

**Evidence to retain:** Task XML/details, relevant event records, and process-creation evidence.

## Finding 5 — File telemetry coverage gap

**Observation:** Initial simulated activity involving `C:\Temp\Finance\financial_report.txt` did not produce the expected Sysmon file events. After targeted coverage for `C:\Temp\Finance\*` was added and the activity repeated, file events were observed around 12:05:38 UTC.

**Assessment:** This is a visibility/configuration finding, not evidence that the original file activity did not occur. It demonstrates the need to validate event coverage against expected behaviors and to record when evidence comes from a repeated test.

**Evidence to retain:** Original query showing no expected events, the relevant Sysmon configuration change, and the later Event 11 / Event 23 evidence as applicable.

## Finding 6 — Simulated outbound HTTP communication

**Observation:** The Windows endpoint made an HTTP request to `10.10.1.20:8080`, where a Python HTTP server was running on the Kali attacker host. The project notes record Sysmon Event 3 and a corresponding Kali access-log entry around 10:50:44–10:51:00 UTC.

**Assessment:** This supports that simulated outbound HTTP communication occurred in the lab. It does not demonstrate real command-and-control behavior, payload transfer, or data exfiltration.

**Evidence to retain:** Sysmon network event, Windows request output, and Kali server log.

## Overall assessment

The collected lab evidence supports a coherent simulated sequence and identifies a concrete telemetry gap in file-event coverage. Conclusions should remain tied to observed records, with explicit caveats where event schemas, timestamps, or attribution are uncertain.
