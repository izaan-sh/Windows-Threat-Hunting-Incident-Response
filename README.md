# Windows Threat Hunting & Incident Response: Simulated Endpoint Compromise

An end-to-end Incident Response (IR) and Threat Hunting exercise simulating a multi-stage Windows endpoint compromise in an isolated Azure lab environment. 

This project focuses on the **SOC Analyst investigation workflow**: analyzing raw telemetry across Windows Security Auditing, Sysmon, and PowerShell Script Block Logging in **Microsoft Sentinel (KQL)** to reconstruct an attack timeline, build correlation detection rules, perform threat hunting, map behaviors to the **MITRE ATT&CK** framework, and document containment/recovery.

---

## 🛠️ Environment & Architecture

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

| Component | Detail |
| :--- | :--- |
| **Target Workstation** | Windows 11 Pro (`WKS-FIN-01` / `10.10.1.10`) |
| **Attacker Workstation** | Kali Linux (`KALI-ATT-01` / `10.10.1.20`) |
| **SIEM & Analytics** | Microsoft Sentinel (`LAW-ir-lab`) |
| **Telemetry Agents** | Azure Monitor Agent (AMA), Sysmon v15.22 (SwiftOnSecurity baseline + custom path rule), PowerShell Script Block Logging (4103/4104) |
| **Network Security** | Azure Network Security Group (NSG) restricting internet access to analyst IP |

---

## 🎯 Simulated Attack Chain Summary

The attack chain models a realistic "Living-off-the-Land" (LotL) compromise without custom malware:

```
   [1. Initial Access]          [2. Execution]            [3. Escalation]
   RDP Brute-Force (Hydra)   ►  PowerShell Recon    ►     Credential Reuse (runas)
   8 Failures ➔ 1 Success       -ExecutionPolicy Bypass   `j.carter` ➔ `labadmin`
             │
             ▼
   [4. Persistence]             [5. Data Staging]         [6. Command & Control]
   Backdoor `lab_attacker`   ►  Created & deleted    ►    Outbound connection
   & Task `SystemHealthCheck`   `financial_report.txt`    `powershell.exe` ➔ 10.10.1.20:8080
```

---

## 📊 Correlated Attack Timeline

| Time (UTC) | Event | Event / Artifact | SOC Interpretation |
| :--- | :--- | :--- | :--- |
| **09:18:49 – 09:19:17** | 8 Failed RDP Logons | Security `4625` (LogonType 3) | Automated credential brute-force attack |
| **09:19:21** | Successful RDP Authentication | Security `4624` (LogonType 3) | Brute force succeeded; valid password identified |
| **10:07:34** | Interactive Session Established | Security `4624` (LogonType 10) | Attacker gains full interactive graphical desktop access |
| **10:07:59** | Admin Session Terminated | Security `4634` (`labadmin`) | Single-session limit displaced legitimate user session |
| **10:10 – 10:17** | PowerShell Reconnaissance | Sysmon `1` / PowerShell `4104` | Enumeration via `whoami`, `hostname`, `ipconfig`, `Get-Process` |
| **10:20:13** | Privilege Escalation Pivot | Sysmon `1` (`runas.exe`) | Attacker pivots from `j.carter` to `labadmin` credentials |
| **10:21:52** | Backdoor Account Created | Security `4720` (`lab_attacker`) | Persistence backdoor account established |
| **10:22:14** | Group Membership Escalation | Security `4732` (Administrators) | Backdoor account granted Local Administrator rights |
| **10:34:19** | Scheduled Task Created | Security `4698` / TaskScheduler `106` | Task `SystemHealthCheck` created to run as `SYSTEM` on logon |
| **10:50:46** | Outbound C2 Connection | Sysmon `3` (Port 8080) | `powershell.exe` establishes outbound socket to `10.10.1.20:8080` |
| **12:05:38** | File Staging & Deletion | Sysmon `11` & `23` | File `C:\Temp\Finance\financial_report.txt` created/deleted |

---

## 🔎 Threat Hunting & KQL Detection Rules

### 1. Brute-Force Correlation Detection Rule
*Fires a High-Severity incident in Sentinel when $\ge 5$ failed logons occur followed by a successful logon from the same IP within 5 minutes.*

```kql
let failedThreshold = 5;
let timeWindow = 5m;
SecurityEvent
| where EventID in (4624, 4625)
| summarize
    FailCount = countif(EventID == 4625),
    SuccessTime = minif(TimeGenerated, EventID == 4624)
  by TargetUserName, IpAddress, bin(TimeGenerated, timeWindow)
| where FailCount >= failedThreshold and isnotempty(SuccessTime)
| project TimeGenerated = SuccessTime, TargetUserName, IpAddress, FailCount
```

### 2. PowerShell Script Block Logging XML Parsing (Event 4104)
*Parses nested XML data to extract execution bypass arguments and malicious command lines.*

```kql
Event
| where TimeGenerated between (datetime(2026-10-07T10:07:00Z) .. datetime(2026-10-07T10:52:00Z))
| where Source == "Microsoft-Windows-PowerShell" and EventID == 4104
| extend x = parse_xml(EventData).DataItem.EventData.Data
| mv-apply d = x on (summarize kv = make_bag(pack(tostring(d["@Name"]), tostring(d["#Text"]))))
| project TimeGenerated, ScriptBlockText = tostring(kv.ScriptBlockText)
| where ScriptBlockText !in ("prompt", "$global:?") and ScriptBlockText !startswith "{"
| order by TimeGenerated asc
```

### 3. Sysmon Outbound C2 Connection Extraction (Event 3)
*Extracts process binary paths, destination IP, and port for network connections.*

```kql
Event
| where TimeGenerated between (datetime(2026-10-07T10:49:00Z) .. datetime(2026-10-07T10:52:00Z))
| where Source == "Microsoft-Windows-Sysmon" and EventID == 3
| extend x = parse_xml(EventData).DataItem.EventData.Data
| mv-apply d = x on (summarize kv = make_bag(pack(tostring(d["@Name"]), tostring(d["#Text"]))))
| project TimeGenerated, User = tostring(kv.User), Image = tostring(kv.Image), DestinationIp = tostring(kv.DestinationIp), DestinationPort = tostring(kv.DestinationPort)
| order by TimeGenerated asc
```

### 4. Scheduled Task & Audit Log Union Query
*Correlates Windows Security Task Creation (4698) with Task Scheduler Operational events (106/140/200/201).*

```kql
union SecurityEvent, Event
| where TimeGenerated between (datetime(2026-10-07T10:00:00Z) .. datetime(2026-10-07T11:00:00Z))
| where EventID == 4698 or (Source == "Microsoft-Windows-TaskScheduler" and EventID in (106, 140, 200, 201))
| project TimeGenerated, EventID, Source, Activity, RenderedDescription
| order by TimeGenerated asc
```

---

## 🔍 Key Analyst Investigative Findings

1. **Process Ancestry vs. Security Log Subject Field**:
   * Security Event `4720` (Account Creation) attributed `labadmin` as the `SubjectUserName`.
   * Tracing Sysmon Event `1` process ancestry revealed the true origin: a `runas.exe` process with `ParentUser: j.carter` and `ParentImage: powershell.exe` spawned the elevated `cmd.exe`. The attacker reused `labadmin` credentials inside the already-compromised `j.carter` RDP session.
2. **Log Source Disagreement on Attribution**:
   * Task Scheduler Operational logs attributed task registration to SID `S-1-5-18` (`NT AUTHORITY\SYSTEM`) due to the task's `/ru SYSTEM` runtime context.
   * Security Event `4698` and Sysmon process lineage correctly attributed creation to the user session (`labadmin`).
3. **Telemetry & Visibility Gap Resolution**:
   * Standard SwiftOnSecurity Sysmon configuration omitted generic file writes outside monitored system paths.
   * The gap was identified mid-investigation when `financial_report.txt` creation went unlogged. Sysmon configuration was tuned with a targeted rule for `C:\Temp\Finance\*`, and telemetry was re-captured successfully.

---

## 🛡️ Containment & Recovery

Containment was executed within 90 seconds from an elevated administrative session and verified against Windows Security events and PowerShell baseline checks:

```powershell
# 1. Disable Backdoor Account
net user lab_attacker /active:no               # Verified via Security Event 4725

# 2. Remove Privileges
net localgroup administrators lab_attacker /delete  # Verified via Security Event 4733

# 3. Remove Persistence Mechanism
schtasks /delete /tn "SystemHealthCheck" /f     # Verified via Security Event 4699

# 4. Purge Account
net user lab_attacker /delete                  # Verified via Security Event 4726
```

**Recovery Verification**:
Executed `Compare-Object` between post-containment system state and pre-incident baselines for Local Users, Administrators Group Members, and Active Scheduled Tasks. Zero residual artifacts or persistence mechanisms remained.

---

## 🗺️ MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Evidence / Artifact |
| :--- | :--- | :--- | :--- |
| **Initial Access** | `T1110.001` | Password Guessing | 8 consecutive 4625 events (~4s apart) |
| **Initial Access** | `T1078` | Valid Accounts | Security 4624 (LogonType 3 & 10) |
| **Initial Access** | `T1021.001` | Remote Desktop Protocol | Interactive session from 10.10.1.20 |
| **Execution** | `T1059.001` | PowerShell | `-ExecutionPolicy Bypass` commands |
| **Discovery** | `T1057` / `T1082` | Process & System Discovery | Executed `whoami`, `hostname`, `ipconfig` |
| **Privilege Escalation** | `T1550` | Credential Reuse / Runas | `powershell.exe` ➔ `runas.exe` ➔ `labadmin` |
| **Persistence** | `T1136.001` | Local Account Creation | Security Event 4720 (`lab_attacker`) |
| **Persistence** | `T1053.005` | Scheduled Task | Created `SystemHealthCheck` running as SYSTEM |
| **Collection** | `T1074.001` | Data Staged | File creation in `C:\Temp\Finance\` |
| **Defense Evasion** | `T1070.004` | File Deletion | Staged file deleted after creation |
| **Command & Control** | `T1071.001` | Application Layer Protocol | Outbound HTTP socket to 10.10.1.20:8080 |

---

## 💡 Production SOC Recommendations

1. **Correlate Credential-Switching**: Deploy analytics rules flagging `runas.exe` or token elevation where parent session user differs from child process context.
2. **Composite Account Escalation Rules**: Correlate account creation (`4720`) immediately followed by group modification (`4732`) within 5 minutes as a High-severity alert.
3. **Audit SYSTEM Scheduled Tasks**: Monitor for non-system processes creating scheduled tasks set to run as `SYSTEM` with `onlogon` triggers.
4. **Custom Sysmon Path Rules**: Extend community baseline configurations to monitor sensitive directories (`Finance`, `HR`, `Executive` folders) for file creation/deletion.
