# MITRE ATT&CK Mapping

This mapping describes simulated behaviors represented in the lab. It is not a claim that every technique was fully demonstrated or that the activity occurred in a real intrusion. Keep mappings conservative and tied to observed evidence.

| Observed/simulated behavior | ATT&CK technique | Rationale / limitation |
|---|---|---|
| Repeated failed logons | T1110 — Brute Force | The simulation included repeated authentication failures. Describe the exact method used rather than implying password spraying unless that was specifically tested. |
| Use of valid account context | T1078 — Valid Accounts | The lab used valid local account credentials. The `runas` pivot alone does not justify adding T1550 without separate evidence. |
| Remote Desktop access | T1021.001 — Remote Desktop Protocol | Use where RDP access is evidenced by the lab records. |
| PowerShell reconnaissance | T1059.001 — PowerShell | Supported by PowerShell process/script-block evidence, subject to the actual records retained. |
| Local account creation | T1136.001 — Create Account: Local Account | Supported by the simulated local account creation and Event 4720. |
| Administrative group modification | T1098 — Account Manipulation | Supported by the simulated addition of an account to the local Administrators group. |
| Scheduled task creation | T1053.005 — Scheduled Task | Supported by the simulated task creation; review the task action and execution evidence. |
| File creation/staging behavior | Describe as simulated data staging behavior | Do not map to a more specific technique unless the evidence supports that exact behavior. File creation alone does not establish collection or exfiltration. |
| HTTP request to the Kali host | Describe as simulated C2-style outbound HTTP communication | A simple HTTP request does not establish actual command and control or Ingress Tool Transfer (T1105). Avoid overmapping. |

## Mapping discipline

- Map behaviors, not assumptions or tool names alone.
- Distinguish observed telemetry from the analyst's interpretation.
- Do not claim exfiltration without evidence that data was transferred out.
- Revisit technique mappings if the final report's evidence or scenario changes.
