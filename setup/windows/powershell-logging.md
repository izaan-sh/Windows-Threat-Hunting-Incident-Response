# PowerShell Logging

PowerShell logging was enabled on `WKS-FIN-01` so that PowerShell
activity generated during the simulated compromise could be investigated
in Microsoft Sentinel.

## Logging enabled

The lab enabled:

-   Script Block Logging
-   Module Logging
-   PowerShell operational logging

The investigation primarily relied on **PowerShell Script Block Logging
Event ID 4104**. These records captured the PowerShell commands used for
reconnaissance, account creation, and the `runas` privilege pivot.

## Configuration

On the Windows workstation, the relevant Group Policy path is:

`Computer Configuration → Administrative Templates → Windows Components → Windows PowerShell`

The following settings were enabled:

-   **Turn on PowerShell Script Block Logging**
-   **Turn on Module Logging**

For Script Block Logging, logging was enabled for all PowerShell
scripts.

## Verification

PowerShell operational events can be checked locally with:

``` powershell
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" |
    Select-Object -First 20 TimeCreated, Id, ProviderName, Message
```

For Script Block Logging specifically:

``` powershell
Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-PowerShell/Operational"
    Id      = 4104
} | Select-Object -First 20 TimeCreated, Id, Message
```

## Sentinel visibility

PowerShell events were collected by the Azure Monitor Agent and
forwarded to the Log Analytics workspace used by Microsoft Sentinel.

The investigation correlated PowerShell telemetry with:

-   Windows Security events
-   Sysmon process creation
-   Sysmon network connections
-   Task Scheduler events

This allowed the analyst to determine not only what PowerShell executed,
but also which process/session initiated the activity.

## Project evidence

The main PowerShell evidence used in the investigation included:

-   reconnaissance commands
-   `-ExecutionPolicy Bypass`
-   `net user lab_attacker ... /add`
-   the `runas` pivot
-   subsequent process ancestry visible through Sysmon

All PowerShell activity in this project was generated as part of the
controlled lab exercise.
