# Incident Timeline

**Scenario:** Simulated Windows endpoint compromise in an isolated lab  
**Endpoint:** `WKS-FIN-01` (`10.10.1.10`)  
**Attacker host:** `KALI-ATT-01` (`10.10.1.20`)  
**Timezone:** Times below are recorded as UTC in the project notes; verify against the original Sentinel records before publishing.

| Approx. time (UTC) | Activity | Evidence / source | Investigation note |
|---|---|---|---|
| 09:18:49–09:19:17 | Repeated failed RDP logons | Windows Security Event 4625 | The project notes record eight failed logons. Confirm account and source-IP fields from raw events. |
| ~09:19:21 | Successful protocol authentication noted | Windows Security telemetry | Distinguish protocol-level authentication from a later interactive logon event. |
| ~10:07:34 | Interactive logon recorded | Event 4624, Logon Type 10 | Review account, source address, and session context in the raw event. |
| Following access | PowerShell reconnaissance | Sysmon Event 1; PowerShell Event 4104 | Correlate command content with process creation and the logged-on user. |
| During privilege pivot | `runas.exe` used to start activity as `labadmin` | Process ancestry and related Security events | The process tree helps connect the new context to the earlier session; a later event's subject alone may not establish the original initiator. |
| ~10:21:52 | Local account `lab_attacker` created | Security Event 4720 | Verify target account and subject fields in the event. |
| ~10:22:14 | Account added to local Administrators | Security Event 4732 | Correlate with the account-creation event. |
| ~10:34:19 | Scheduled task `SystemHealthCheck` created | Security Event 4698; Task Scheduler telemetry | Review task definition, run context, and action. |
| ~10:34:45 | Scheduled task execution noted | Task Scheduler 200/201 and/or process telemetry | Validate the task's action and process evidence; task events alone do not prove malicious execution. |
| ~10:41–10:44 | Initial simulated file-staging activity | Endpoint activity; expected Sysmon file events initially absent | The gap prompted a review of Sysmon file-event coverage. |
| ~10:50:44–10:51:00 | HTTP request from Windows to Kali on port 8080 | Sysmon Event 3 and Kali HTTP server log | Simulated C2-style outbound HTTP communication; not proof of actual C2 or exfiltration. |
| ~12:05:38 | Repeated file activity after targeted Sysmon coverage was added | Sysmon file events, including Event 11 and Event 23 as recorded in project notes | Demonstrates improved visibility after the configuration change. |

## Timeline interpretation

The sequence supports an investigation narrative involving authentication attempts, interactive access, PowerShell activity, an account-context pivot, local account and group changes, scheduled-task activity, simulated file staging, and HTTP communication to the attacker host. Treat this as a reconstructed lab sequence, not proof of a real intrusion.

## Correlation cautions

- Confirm timestamps and timezone in raw records before final publication.
- Do not infer strict ordering from events merely appearing in the same five-minute aggregation bucket.
- Correlate `SecurityEvent` records with Sysmon and PowerShell records using the fields actually present in the workspace.
- Record uncertainty when a telemetry source does not provide direct attribution.
