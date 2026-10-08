# Sentinel Data Collection

## Collection architecture

The Windows endpoint generated several independent telemetry streams:

``` text
WKS-FIN-01
│
├── Windows Security
├── Sysmon
├── PowerShell Operational
├── Task Scheduler Operational
└── Defender Operational
        │
        ▼
Azure Monitor Agent
        │
        ├── DCR: Windows Security Events
        │
        └── DCR: Sysmon / PowerShell /
                 Task Scheduler / Defender
        │
        ▼
Log Analytics
        │
        ▼
Microsoft Sentinel
```

## Windows Security telemetry

Windows Security auditing supplied the authentication and
account-management evidence used throughout the investigation.

The most important records were:

-   4625 --- failed authentication
-   4624 --- successful authentication
-   4634 --- logoff
-   4720 --- local account creation
-   4732 --- administrator group membership change
-   4698 --- scheduled task creation
-   4699 --- scheduled task deletion
-   4725 --- account disabled
-   4726 --- account deleted
-   4733 --- administrator group membership removal

## Sysmon telemetry

Sysmon supplied the process and network context needed to move beyond
single-event analysis.

The investigation used:

-   Event 1 for process creation and command-line/process ancestry
-   Event 3 for outbound network connections
-   Event 8 for a candidate CreateRemoteThread event that was ultimately
    triaged as benign
-   Event 11 for file creation after the configuration gap was corrected
-   Event 23 for file deletion

## PowerShell telemetry

PowerShell Script Block Logging provided visibility into commands
executed during the attack chain.

Event ID 4104 was especially useful because it preserved the PowerShell
content rather than only showing that `powershell.exe` had started.

## Why correlation mattered

No single source told the complete story.

For example:

-   Security events showed `labadmin` as the subject for account
    creation and privilege modification.
-   Sysmon process ancestry showed that the actions originated from a
    compromised `j.carter` session through `runas.exe`.
-   Task Scheduler telemetry provided additional context around the
    persistence mechanism.
-   Sysmon network telemetry connected `powershell.exe` with the Kali
    host on TCP/8080.

This cross-source correlation was central to the investigation.

## Verification before detection

The project followed a simple rule:

> Do not build a detection around telemetry that has not been verified.

Each planned attack step was generated, searched for in Sentinel, and
checked against the expected event source and event ID.

This process identified the file telemetry gap and allowed it to be
corrected before final evidence collection.
