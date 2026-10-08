# Windows Threat Hunting & Incident Response Lab

A self-directed purple-team exercise: I designed and executed a multi-stage simulated compromise against a Windows 11 workstation in an isolated Azure lab, then independently investigated it end-to-end as a SOC analyst — detection engineering, threat hunting, timeline reconstruction, MITRE ATT&CK mapping, containment, and recovery — using Microsoft Sentinel, Sysmon, and native Windows auditing.

This is the third project in a progression: [Wazuh SOC Home Lab](#) → [Cloud SOC Lab (Microsoft Sentinel)](#) → **this project**. Where the first two focused on building detection pipelines, this one focuses on what happens *after* an alert fires: investigation, correlation across multiple log sources, and response.

> All activity below was conducted by me, from both sides, inside an isolated lab network with no internet-facing exposure. No real systems, accounts, or data were involved.

---

## Why this project

Most portfolio SOC labs stop at "I built a SIEM and wrote a detection rule." This one goes further — simulating a full intrusion end to end and documenting the investigation the way a Tier 1/2 SOC analyst actually works: starting from an alert, pivoting across logs, correlating process ancestry, catching a false positive, finding a real telemetry gap mid-investigation and fixing it, and closing out with verified containment.

## Architecture

```
┌─────────────────────┐          ┌──────────────────────┐
│   Kali Linux VM     │          │   Windows 11 VM      │
│   KALI-ATT-01       │  brute   │   WKS-FIN-01         │
│   10.10.1.20        │ ─force─> │   10.10.1.10         │
│                     │  RDP     │   Sysmon             │
│   Hydra, FreeRDP    │ <──C2─── │   PowerShell logging │
│                     │          │   Windows auditing   │
└─────────────────────┘          └───────────┬──────────┘
                                             │ telemetry (AMA)
                                             ▼
                                  ┌─────────────────────────┐
                                  │   Microsoft Sentinel    │
                                  │   KQL · Analytics Rules │
                                  │   Incidents · Hunting   │
                                  └─────────────────────────┘
```

- **Network:** fully isolated Azure VNet (`10.10.1.0/24`), NSG locked to the analyst's own IP — no internet-facing exposure, unlike a honeypot.
- **Telemetry:** Windows Security auditing (logon, process creation with command line, account management, scheduled tasks), PowerShell Script Block Logging, and Sysmon (SwiftOnSecurity baseline + a custom rule added mid-investigation — see [Findings](#key-findings)).

## Attack chain simulated

1. Brute-force RDP against a standard user account
2. Interactive session compromise (displacing a legitimate admin session)
3. PowerShell-based reconnaissance
4. Privilege escalation via credential reuse (`runas` to a second, separately-obtained admin credential)
5. Backdoor local administrator account creation
6. Persistence via a disguised scheduled task
7. Staging and deletion of a simulated sensitive file
8. Outbound connection consistent with command-and-control

## What I built

- **One Sentinel Analytics Rule** correlating failed-then-successful logons (rather than a pile of low-value threshold rules) — High severity, full entity mapping, verified firing correctly against the attack data.
- **Eight KQL threat-hunting queries**, each answering a specific investigative question (who was targeted, what executed, what persisted, what connected out, and a master correlation query reconstructing the full chronological chain).
- **A fully verified incident timeline**, cross-checked stage by stage against raw Sentinel data — not reconstructed after the fact from memory.
- **A complete MITRE ATT&CK mapping** (12 techniques, each tied to specific evidence and event IDs).
- **Full containment and recovery**, with before/after comparison against a pre-incident system baseline proving the host was actually restored, not just claimed to be.

## Key findings

A few things surfaced during the investigation that I think are the most interesting part of this project:

- **Attribution requires process-ancestry correlation, not just the Security log.** The account-creation and privilege-escalation events were both logged under one admin account's name — but tracing Sysmon's process tree revealed they actually originated from the already-compromised session, pivoted via `runas`. Taking the Security log's subject field at face value would have been the wrong conclusion.
- **Two logs disagreed on who created the persistence task** — the Security log and the Task Scheduler Operational log attributed it to different identities, due to how the task's run-as context is recorded. Cross-referencing both was necessary to get it right.
- **A default Sysmon configuration had a real detection gap.** Generic file writes outside specific monitored paths weren't being logged at all. I caught this during verification (not before), built a targeted fix, and re-ran that stage of the attack to capture clean evidence — documented in the report as a finding, not hidden.
- **A real alert fired during the "quiet" baseline period and turned out to be a false positive** (a process-injection pattern between two trusted Windows system processes, tied to normal RDP session startup) — investigated and ruled out rather than either ignored or treated as confirmed malicious.

## Repository structure

```
├── README.md
├── report/
│   └── IR-Report-Windows-Threat-Hunting.docx      # full 12-section incident report
├── screenshots/
│   ├── 01-architecture-diagram.png
│   ├── 02-sysmon-config.png
│   ├── 03-04-bruteforce-success.png
│   ├── 05-powershell-reconnaissance.png
│   ├── 06-07-account-creation-privesc.png
│   ├── 08-scheduled-task.png
│   ├── 09-network-connection.png
│   ├── 10-sentinel-incident.png
│   ├── 11-12-13-kql-hunts.png
│   ├── 14-correlation-timeline.png
│   └── 15-containment-evidence.png
└── queries/
    ├── detection-rule-bruteforce.kql
    ├── hunt-01-failed-auth-by-user.kql
    ├── hunt-02-success-after-failures.kql
    ├── hunt-03-powershell-execution.kql
    ├── hunt-04-new-accounts.kql
    ├── hunt-05-privilege-escalation.kql
    ├── hunt-06-scheduled-tasks.kql
    ├── hunt-07-network-connections.kql
    └── hunt-08-master-correlation.kql
```

## Report

The full written incident report — Executive Summary, Environment, Attack Timeline, Detection, Investigation, MITRE ATT&CK Mapping, IOCs, Containment, Recovery, Lessons Learned, and Detection Recommendations — is in [`report/IR-Report-Windows-Threat-Hunting.docx`](report/).

## Skills demonstrated

Windows Event Log analysis · Sysmon deployment & tuning · PowerShell Script Block Logging · Microsoft Sentinel (KQL, Analytics Rules, Hunting, Incidents) · threat hunting methodology · MITRE ATT&CK mapping · IOC identification · timeline reconstruction · cross-log correlation and attribution · incident containment & recovery · detection engineering · technical report writing

## Related projects

- [SOC Home Lab (Wazuh)](#) — telemetry collection and detection fundamentals
- [Cloud SOC Lab (Microsoft Sentinel)](#) — cloud SIEM, detection-to-automation pipeline with SOAR response
