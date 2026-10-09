# Windows Threat Hunting & Incident Response Lab

**A self-directed purple-team exercise.** I designed, built, and executed a full multi-stage simulated compromise against a Windows 11 workstation in an isolated Azure lab, then independently investigated it end to end as a SOC analyst would investigate a real incident: detection engineering, threat hunting, cross-log correlation, MITRE ATT&CK mapping, containment, and recovery, using Microsoft Sentinel, Sysmon, and native Windows auditing.

This is the third project in a progression:

1. [SOC Home Lab (Wazuh)](#) — telemetry collection and detection fundamentals
2. [Cloud SOC Lab (Microsoft Sentinel)](#) — cloud SIEM, detection-to-automation pipeline with SOAR response
3. **This project** — investigation and response, not just detection

Where the first two projects focused on building the pipeline that generates an alert, this one focuses on what happens *after* the alert fires.

> Every action described in this repo, both the attack and the investigation, was performed by me inside an isolated Azure lab network with no internet-facing exposure. No real systems, accounts, or data were involved at any point.

---

## Why this project

Most portfolio SOC labs stop at "I built a SIEM and wrote a detection rule." This one goes further: a full intrusion simulated end to end, then investigated the way a Tier 1/2 SOC analyst actually works, starting from an alert, pivoting across multiple log sources, correlating process ancestry to uncover a privilege-escalation technique the Security log alone didn't reveal, catching a false positive instead of either ignoring or over-reacting to it, discovering a real telemetry gap mid-investigation and fixing it live, and closing out with containment that was independently verified against a pre-incident baseline rather than just claimed.

## Architecture

```
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

Full diagrams: [`architecture/architecture-diagram.png`](architecture/), [`architecture/lab-network.png`](architecture/)

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

## Attack chain simulated

| Stage | Action | MITRE technique | Details |
|---|---|---|---|
| 1 | Brute-force RDP against a standard user account | T1110 | [`attack-simulation/01-rdp-authentication/`](attack-simulation/01-rdp-authentication/) |
| 2 | Interactive session compromise, displacing a legitimate admin session | T1078, T1021.001 | [`attack-simulation/01-rdp-authentication/`](attack-simulation/01-rdp-authentication/) |
| 3 | PowerShell-based reconnaissance | T1059.001 | [`attack-simulation/02-powershell/`](attack-simulation/02-powershell/) |
| 4 | Privilege escalation via credential reuse (`runas`) | T1078 / T1550 | [`attack-simulation/03-runas-pivot/`](attack-simulation/03-runas-pivot/) |
| 5 | Backdoor local administrator account creation | T1136.001 | [`attack-simulation/04-account-creation/`](attack-simulation/04-account-creation/) |
| 6 | Privilege escalation to Administrators | T1098 | [`attack-simulation/05-admin-privilege/`](attack-simulation/05-admin-privilege/) |
| 7 | Persistence via a disguised scheduled task | T1053.005 | [`attack-simulation/06-scheduled-task/`](attack-simulation/06-scheduled-task/) |
| 8 | Staging and deletion of a simulated sensitive file | T1074.001, T1070.004 | [`attack-simulation/07-file-staging/`](attack-simulation/07-file-staging/) |
| 9 | Outbound connection consistent with command-and-control | T1071 / T1105 | [`attack-simulation/08-network-communication/`](attack-simulation/08-network-communication/) |

## What I built

- **One Microsoft Sentinel Analytics Rule** correlating failed-then-successful logons, High severity, full entity mapping, verified firing correctly against the attack data. See [`detections/sentinel-rules/`](detections/sentinel-rules/).
- **Eight KQL threat-hunting queries**, each answering a specific investigative question, plus a master correlation query reconstructing the full chronological chain from multiple log sources. See [`threat-hunting/`](threat-hunting/).
- **A fully verified incident timeline**, cross-checked stage by stage against raw Sentinel data as it was generated. See [`investigation/timeline.md`](investigation/timeline.md).
- **A complete MITRE ATT&CK mapping**: 12 techniques, each tied to specific evidence and event IDs, plus one false-positive technique investigated and ruled out. See [`investigation/mitre-mapping.md`](investigation/mitre-mapping.md).
- **Full containment and recovery**, with a before/after comparison against a pre-incident baseline, completed in under two minutes of response time. See [`incident-response/`](incident-response/).

## Key findings

The most interesting part of this project isn't the attack itself; it's what the investigation turned up. Full write-up: [`investigation/findings.md`](investigation/findings.md).

1. **Attribution requires process-ancestry correlation, not just the Security log.** Account-creation and privilege-escalation events were logged under one administrator's name; tracing Sysmon's process tree revealed they actually originated from the already-compromised standard-user session, pivoted through `runas`.
2. **Two logs disagreed on who created the persistence task** — the Security log and the Task Scheduler Operational log attributed it to different identities. Cross-referencing both was necessary to attribute it correctly.
3. **A default Sysmon configuration had a real detection gap.** The SwiftOnSecurity baseline doesn't log generic file writes outside specific monitored paths. Caught during active verification, fixed with a targeted rule, and re-tested live mid-investigation.
4. **A real alert fired during the quiet baseline period and turned out to be a false positive** — a process-injection pattern between two trusted Windows system processes, tied to normal RDP session startup. Investigated and correctly ruled benign.

## Indicators of Compromise

Full list, accounts, network, host artifacts, timing: [`investigation/iocs.md`](investigation/iocs.md).

## Repository structure

```
windows-threat-hunting-ir/
├── README.md
├── report/
│   └── Windows-Threat-Hunting-IR-Report.pdf
├── architecture/
│   ├── architecture-diagram.png
│   └── lab-network.png
├── setup/
│   ├── windows/
│   │   ├── sysmon-config.xml
│   │   ├── powershell-logging.md
│   │   └── telemetry-setup.md
│   ├── sentinel/
│   │   ├── data-collection.md
│   │   ├── dcr-configuration.md
│   │   └── workspace-setup.md
│   └── kali/
│       └── attacker-setup.md
├── attack-simulation/
│   ├── 01-rdp-authentication/
│   ├── 02-powershell/
│   ├── 03-runas-pivot/
│   ├── 04-account-creation/
│   ├── 05-admin-privilege/
│   ├── 06-scheduled-task/
│   ├── 07-file-staging/
│   └── 08-network-communication/
├── detections/
│   ├── sentinel-rules/
│   │   ├── failed-logons.md
│   │   ├── account-creation.md
│   │   ├── privilege-escalation.md
│   │   └── ...
│   └── sysmon/
│       └── README.md              # points back to setup/windows/sysmon-config.xml
├── threat-hunting/
│   ├── failed-logons.kql
│   ├── successful-logons.kql
│   ├── powershell.kql
│   ├── account-creation.kql
│   ├── admin-group-changes.kql
│   ├── scheduled-tasks.kql
│   ├── network-connections.kql
│   └── master-correlation.kql
├── investigation/
│   ├── timeline.md
│   ├── findings.md
│   ├── iocs.md
│   └── mitre-mapping.md
├── incident-response/
│   ├── containment.md
│   └── recovery.md
└── screenshots/
    ├── 01-environment/
    ├── 02-attack/
    ├── 03-detection/
    ├── 04-hunting/
    ├── 05-investigation/
    └── 06-containment-recovery/
```

Each `attack-simulation/NN-*/` folder holds a `commands.md` (what was run) and the supporting evidence for that stage. `detections/sysmon/` intentionally does not duplicate the Sysmon config file; it links back to the single canonical copy in `setup/windows/`.

## Report

The full written incident report, covering Executive Summary, Environment, Incident Overview, Attack Timeline, Detection, Investigation, MITRE ATT&CK Mapping, Indicators of Compromise, Containment, Recovery, Lessons Learned, and Detection Recommendations, is in [`report/Windows-Threat-Hunting-IR-Report.pdf`](report/).

## Skills demonstrated

Windows Event Log analysis, Sysmon deployment and tuning, PowerShell Script Block Logging, Microsoft Sentinel (KQL, Analytics Rules, Hunting, Incidents), threat hunting methodology, MITRE ATT&CK mapping, indicator of compromise identification, timeline reconstruction, cross-log correlation and attribution, incident containment and recovery, detection engineering, and technical report writing.

## Related projects

- [SOC Home Lab (Wazuh)](#)
- [Cloud SOC Lab (Microsoft Sentinel)](#)
