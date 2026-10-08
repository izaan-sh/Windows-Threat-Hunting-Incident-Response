# Stage 2 --- PowerShell Reconnaissance

## Objective

After interactive access was established, PowerShell was used to perform
controlled reconnaissance on the Windows workstation.

## Activity

The simulated activity included:

-   host and user discovery
-   process enumeration
-   filesystem inspection
-   PowerShell launched with `-ExecutionPolicy Bypass`

The project captured both process-creation telemetry and PowerShell
Script Block Logging.

## Evidence

Primary telemetry:

-   Sysmon Event ID 1 --- Process Creation
-   PowerShell Event ID 4104 --- Script Block Logging

The investigation used the combination of these sources to determine
both the process that launched PowerShell and the commands executed
inside it.

## Screenshots

Recommended evidence:

-   `01-powershell-process.png`
-   `02-powershell-4104.png`
-   `03-reconnaissance-command.png`

## Why it matters

A process creation event alone shows that PowerShell started. Event 4104
provides additional visibility into the commands that were executed.

This stage therefore demonstrates the value of collecting both process
telemetry and PowerShell content.
