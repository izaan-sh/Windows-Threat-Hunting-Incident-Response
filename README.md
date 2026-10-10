# Windows Threat Hunting & Incident Response Lab

![Sentinel](https://img.shields.io/badge/Microsoft_Sentinel-0078D4?style=for-the-badge&logo=microsoft&logoColor=white)
![Azure](https://img.shields.io/badge/Azure-0089D6?style=for-the-badge&logo=microsoftazure&logoColor=white)
![Windows 11](https://img.shields.io/badge/Windows_11-0078D4?style=for-the-badge&logo=windows11&logoColor=white)
![Sysmon](https://img.shields.io/badge/Sysmon-v15.22-000000?style=for-the-badge&logo=shield&logoColor=white)
![KQL](https://img.shields.io/badge/Query-KQL-5C2D91?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Completed-brightgreen?style=for-the-badge)

> **A Self-Directed Purple-Team Exercise:** Engineered, executed, and investigated a multi-stage simulated compromise against an isolated Windows 11 workstation in Azure. Demonstrated end-to-end SOC Tier 1/2 workflow: detection engineering, threat hunting, cross-log correlation, MITRE ATT&CK mapping, telemetry gap remediation, and containment.

---

## 🎯 Scope & Progression

This project represents the third stage in my practical defensive security path:

1. **[SOC Home Lab (Wazuh)](https://github.com/izaan-sh/Wazuh-Home-SOC-Lab)** — Telemetry collection, endpoint monitoring, and detection fundamentals.
2. **[Cloud SOC Lab (Microsoft Sentinel)](https://github.com/izaan-sh/Cloud-SOC-Lab-Microsoft-Sentinel)** — Cloud SIEM, KQL detection rules, and SOAR response pipelines.
3. **Windows Threat Hunting & Incident Response Lab (This Repo)** — Deep-dive investigation, cross-log attribution, threat hunting, and containment post-alert.

> **Lab Safety Notice:** All attack simulations, investigations, and containment actions were executed inside an isolated Azure virtual network (`VNet-IR-Lab`) with zero external internet access. No live production environments or real credentials were involved.

---

## 💡 Why This Project?

Most portfolio labs stop once an alert fires. This lab focuses entirely on **what happens after the alert**:

- **Real Investigation Workflows:** Pivoted across disparate log sources (Security Events, PowerShell, Sysmon, TaskScheduler) to uncover hidden attack context.
- **Process Ancestry Attribution:** Traced `runas` privilege escalation that standard Security event logs misattributed.
- **Live Telemetry Remediation:** Discovered a default Sysmon coverage gap mid-investigation, authored a custom rule, and re-tested live.
- **False-Positive Analysis:** Investigated and ruled out benign Windows RDP process injection patterns during baseline validation.
- **Verified Containment:** Performed host containment and verified recovery against a cryptographic pre-incident baseline in under **2 minutes**.

---

## 🏗 System Architecture

```text

                      ┌─────────────────────────────────────────┐
                      │              Kali Linux VM              │
                      │               KALI-ATT-01               │
                      │               10.10.1.20                │
                      │          (Hydra, FreeRDP, C2)           │
                      └────────────────────┬────────────────────┘
                                           │
                                           │  RDP Brute Force / C2
                                           ▼
                      ┌─────────────────────────────────────────┐
                      │             Windows 11 VM               │
                      │               WKS-FIN-01                │
                      │               10.10.1.10                │
                      │       Sysmon v15.22 | Win Event Logs    │
                      └────────────────────┬────────────────────┘
                                           │
                                           │ Telemetry (AMA)
                                           ▼
                      ┌─────────────────────────────────────────┐
                      │           Microsoft Sentinel            │
                      │               LAW-ir-lab                │
                      │        (KQL, Analytics Rules, IR)       │
                      └─────────────────────────────────────────┘
```

## Lab Specifications

| Component | Detail |
|---|---|
| Resource group | `RG-IR-Lab` (Azure) |
| Virtual network | `VNet-IR-Lab`, subnet `10.10.1.0/24`, fully isolated, inbound internet access restricted to the analyst's own IP via NSG |
| Target host | `WKS-FIN-01`, Windows 11 Pro 25H2, static IP `10.10.1.10` |
| Attacker host | `KALI-ATT-01`, Kali Linux, static IP `10.10.1.20` |
| SIEM | Microsoft Sentinel, workspace `LAW-ir-lab` |
| Telemetry | Windows Security auditing, PowerShell Script Block Logging (4103/4104), Sysmon v15.22 (SwiftOnSecurity baseline + a custom rule added mid-investigation, see [Key findings](#key-findings)) |
| Time standard | Every system and every timestamp in this project is UTC |

Full setup walkthrough: [`setup/`](setup/) (Windows telemetry, Sentinel data collection, Kali attacker configuration).

## ⚔️ Attack chain simulated

| Stage | Action | MITRE technique | Details |
|---|---|---|---|
| 1 | Brute-force RDP against a standard user account, then an interactive session compromise displacing a legitimate admin session | T1110, T1078, T1021.001 | [`attack-simulation/01-rdp-authentication/`](attack-simulation/01-rdp-authentication/) |
| 2 | PowerShell-based reconnaissance | T1059.001 | [`attack-simulation/02-powershell/`](attack-simulation/02-powershell-reconnaissance/) |
| 3 | Privilege escalation via credential reuse (`runas`) | T1078 / T1550 | [`attack-simulation/03-runas-pivot/`](attack-simulation/03-runas-pivot/) |
| 4 | Backdoor local administrator account creation | T1136.001 | [`attack-simulation/04-account-creation/`](attack-simulation/04-account-creation/) |
| 5 | Privilege escalation to Administrators | T1098 | [`attack-simulation/05-admin-privilege/`](attack-simulation/05-administrator-group-modification/) |
| 6 | Persistence via a disguised scheduled task | T1053.005 | [`attack-simulation/06-scheduled-task/`](attack-simulation/06-scheduled-task-persistence/) |
| 7 | Staging and deletion of a simulated sensitive file | T1074.001, T1070.004 | [`attack-simulation/07-file-staging/`](attack-simulation/07-file-staging/) |
| 8 | Outbound connection consistent with command-and-control | T1071 / T1105 | [`attack-simulation/08-network-communication/`](attack-simulation/08-network-communication/) |

## 🛠 What I built

- **One Microsoft Sentinel Analytics Rule** correlating failed-then-successful logons, High severity, full entity mapping, verified firing correctly against the attack data. See [`detections/sentinel-rules/`](detections/sentinel-rules/).
- **Eight KQL threat-hunting queries**, each answering a specific investigative question, plus a master correlation query reconstructing the full chronological chain from multiple log sources. See [`threat-hunting/`](threat-hunting/).
- **A fully verified incident timeline**, cross-checked stage by stage against raw Sentinel data as it was generated. See [`investigation/timeline.md`](investigation/timeline/incident-timeline.md).
- **A complete MITRE ATT&CK mapping**: 12 techniques, each tied to specific evidence and event IDs, plus one false-positive technique investigated and ruled out. See [`investigation/mitre-mapping.md`](investigation/findings/mitre-mapping.md).
- **Full containment and recovery**, with a before/after comparison against a pre-incident baseline, completed in under two minutes of response time. See [`incident-response/`](incident-response/).

## 🔬 Key findings

The most interesting part of this project isn't the attack itself; it's what the investigation turned up. Full write-up: [`investigation/findings.md`](investigation/findings/).

1. **Attribution requires process-ancestry correlation, not just the Security log.** Account-creation and privilege-escalation events were logged under one administrator's name; tracing Sysmon's process tree revealed they actually originated from the already-compromised standard-user session, pivoted through `runas`.
2. **Two logs disagreed on who created the persistence task** — the Security log and the Task Scheduler Operational log attributed it to different identities. Cross-referencing both was necessary to attribute it correctly.
3. **A default Sysmon configuration had a real detection gap.** The SwiftOnSecurity baseline doesn't log generic file writes outside specific monitored paths. Caught during active verification, fixed with a targeted rule, and re-tested live mid-investigation.
4. **A real alert fired during the quiet baseline period and turned out to be a false positive** — a process-injection pattern between two trusted Windows system processes, tied to normal RDP session startup. Investigated and correctly ruled benign.

## 📄 Incident Report and Indicators of Compromise

Full list, accounts, network, host artifacts, timing: [`investigation/iocs.md`](investigation/findings/iocs.md).

The full written incident report, covering Executive Summary, Environment, Incident Overview, Attack Timeline, Detection, Investigation, MITRE ATT&CK Mapping, Indicators of Compromise, Containment, Recovery, Lessons Learned, and Detection Recommendations, is in [`report/Windows-Threat-Hunting-IR-Report.pdf`](report/).

## 🛠 Skills demonstrated

Windows Event Log analysis, Sysmon deployment and tuning, PowerShell Script Block Logging, Microsoft Sentinel (KQL, Analytics Rules, Hunting, Incidents), threat hunting methodology, MITRE ATT&CK mapping, indicator of compromise identification, timeline reconstruction, cross-log correlation and attribution, incident containment and recovery, detection engineering, and technical report writing.

## Related projects

- [SOC Home Lab (Wazuh)](https://github.com/izaan-sh/Wazuh-Home-SOC-Lab)
- [Cloud SOC Lab (Microsoft Sentinel)](https://github.com/izaan-sh/Cloud-SOC-Lab-Microsoft-Sentinel)
