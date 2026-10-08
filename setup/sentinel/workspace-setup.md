# Microsoft Sentinel Workspace Setup

## Workspace

The project used the following Azure environment:

  Setting                   Value
  ------------------------- --------------------
  Resource group            `RG-IR-Lab`
  Virtual network           `VNet-IR-Lab`
  Log Analytics workspace   `LAW-ir-lab`
  SIEM                      Microsoft Sentinel

The Windows workstation was connected to the Azure monitoring
environment through the Azure Monitor Agent.

## Purpose

Microsoft Sentinel was used as the investigation and detection layer
rather than simply as a log-storage destination.

The project used Sentinel for:

-   centralized Windows telemetry
-   KQL threat hunting
-   scheduled analytics detection
-   incident generation
-   entity mapping
-   cross-source event correlation
-   investigation timeline reconstruction

## Workspace preparation

The basic workflow was:

1.  Create the Log Analytics workspace.
2.  Enable Microsoft Sentinel on the workspace.
3.  Prepare the Windows endpoint for Azure Monitor Agent collection.
4.  Create and associate the required Data Collection Rules.
5.  Generate controlled Windows activity.
6.  Confirm that the expected records reached the workspace.
7.  Build the detection and hunting queries only after telemetry
    visibility was verified.

## Tables used

The investigation primarily worked with:

-   `SecurityEvent` for Windows Security Events
-   `Event` for Sysmon and other Windows event sources collected through
    the general Windows event collection path

The exact table used depends on the configured data connector/DCR. The
project intentionally did not assume that every Windows event source
would automatically appear in `SecurityEvent`.

## Verification

Example checks used during setup included:

``` kql
SecurityEvent
| summarize Count=count() by EventID
| order by Count desc
```

For the general event table:

``` kql
Event
| summarize Count=count() by EventID
| order by Count desc
```

The first goal was to confirm that useful telemetry existed before
writing detections.

## Project outcome

The completed workspace provided enough visibility to correlate
authentication, PowerShell, process, account, persistence, file, and
network activity into a single incident timeline.
