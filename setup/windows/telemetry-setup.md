# Windows Telemetry Setup

## Host

  Setting    Value
  ---------- ----------------------------------------------
  Hostname   `WKS-FIN-01`
  OS         Windows 11 Pro 25H2
  IP         `10.10.1.10`
  Role       Simulated workstation / investigation target

The workstation was placed in an isolated lab network and configured to
generate the telemetry required for the threat-hunting and
incident-response exercise.

## Telemetry sources

The project collected several Windows telemetry sources:

### Windows Security

Security auditing was used for authentication, account management,
privilege changes, and scheduled-task activity.

Important events observed during the exercise included:

    Event ID Purpose
  ---------- ----------------------------------------------------
        4624 Successful logon
        4625 Failed logon
        4634 Logoff
        4698 Scheduled task created
        4699 Scheduled task deleted
        4720 User account created
        4725 User account disabled
        4726 User account deleted
        4732 Member added to a security-enabled local group
        4733 Member removed from a security-enabled local group

### Sysmon

Sysmon provided process and network telemetry that was important for
attribution and correlation.

The project used:

-   Event ID 1 --- Process Creation
-   Event ID 3 --- Network Connection
-   Event ID 8 --- CreateRemoteThread
-   Event ID 11 --- File Create
-   Event ID 23 --- File Delete

The Sysmon configuration started from the SwiftOnSecurity community
baseline and was extended during the investigation with a targeted rule
for the sensitive file path used in the lab.

### PowerShell

PowerShell Script Block Logging provided Event ID 4104 records for
commands executed during the simulated compromise.

### Task Scheduler

Task Scheduler Operational logging was used to corroborate
scheduled-task creation and execution.

The investigation compared Task Scheduler telemetry with Windows
Security 4698/4699 events because the two sources can describe the
registering/running context differently.

## Baseline collection

Before generating the simulated attack activity, a basic host baseline
was captured.

Examples included:

``` powershell
hostname
whoami
ipconfig
Get-LocalUser
Get-LocalGroupMember Administrators
Get-ScheduledTask
Get-Process
Get-Service
```

The baseline was later used during recovery to verify that
attacker-created accounts, group membership, and scheduled tasks had
been removed.

## Data flow

The telemetry architecture was:

``` text
Windows 11 Workstation
        |
        +-- Windows Security
        +-- PowerShell Operational
        +-- Task Scheduler Operational
        +-- Sysmon
        |
        v
Azure Monitor Agent
        |
        v
Azure Monitor Data Collection Rules
        |
        v
Log Analytics Workspace
        |
        v
Microsoft Sentinel
```

The project deliberately separated Windows Security Events from the
other Windows/Sysmon telemetry collection path.

## Verification principle

A key lesson from the project was that enabling a log source does not
automatically mean the required activity is visible.

Every planned attack step was therefore verified against the telemetry
actually arriving in Sentinel. This exposed a Sysmon visibility gap for
generic file creation/deletion outside monitored paths, which was then
corrected with a targeted configuration rule and the activity
re-performed.
