# Data Collection Rule Configuration

The project used **two Azure Monitor Agent Data Collection Rules
(DCRs)** to separate Windows Security Events from the broader
Windows/Sysmon telemetry.

## DCR 1 --- Windows Security Events

### Purpose

This DCR collected Windows Security Events required for authentication,
account management, privilege changes, and scheduled-task investigation.

Important event IDs included:

-   4624 --- successful logon
-   4625 --- failed logon
-   4634 --- logoff
-   4698 --- scheduled task creation
-   4699 --- scheduled task deletion
-   4720 --- account creation
-   4725 --- account disabled
-   4726 --- account deleted
-   4732 --- local group membership addition
-   4733 --- local group membership removal

These records were used in Sentinel through the `SecurityEvent` table.

## DCR 2 --- Sysmon / PowerShell / Task Scheduler / Defender

The second collection path was used for the additional Windows telemetry
required for process and behavior analysis.

Sources included:

-   Sysmon
-   PowerShell Operational
-   Task Scheduler Operational
-   Defender Operational logging where applicable

These records were collected through the general Windows event
collection path and queried from the `Event` table where applicable.

## Why two DCRs?

The separation made the telemetry architecture easier to manage and
reflected the different collection requirements of the project.

It also avoided the common mistake of assuming that every Windows event
source automatically lands in `SecurityEvent`.

## Telemetry verification

After associating the DCRs with the Windows endpoint, the project
generated controlled activity and checked Sentinel for the expected
events.

Examples:

``` kql
SecurityEvent
| where EventID in (4624, 4625, 4720, 4732, 4698)
| sort by TimeGenerated desc
```

``` kql
Event
| where EventID in (1, 3, 8, 11, 23, 4104)
| sort by TimeGenerated desc
```

The exact event availability depends on the configured Windows data
sources and collection rules.

## Important project finding

During verification, the original Sysmon configuration did not capture
generic file creation/deletion for the simulated sensitive file path.

A targeted Sysmon rule was added for:

`C:\Temp\Finance\*`

The file activity was then re-performed, producing the expected Sysmon
file telemetry.

This was treated as a detection-coverage finding rather than hidden or
omitted from the final report.
