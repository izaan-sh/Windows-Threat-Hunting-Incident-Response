# Attack Simulation

This directory documents the controlled attack sequence used to generate
telemetry for the Windows threat-hunting and incident-response exercise.

The sequence was intentionally performed inside the isolated lab
environment:

``` text
KALI-ATT-01 (10.10.1.20)
        |
        | RDP authentication
        v
WKS-FIN-01 (10.10.1.10)
        |
        +--> PowerShell reconnaissance
        |
        +--> runas privilege pivot
        |
        +--> lab_attacker account creation
        |
        +--> Administrators group modification
        |
        +--> Scheduled Task persistence
        |
        +--> Simulated file staging
        |
        +--> HTTP connection to Kali:8080
```

## Stages

    Stage Activity
  ------- ---------------------------------------
        1 RDP authentication
        2 PowerShell reconnaissance
        3 `runas` privilege pivot
        4 Local account creation
        5 Administrator group modification
        6 Scheduled Task persistence
        7 Simulated file staging
        8 Simulated C2-style HTTP communication

Each stage contains:

-   objective
-   activity performed
-   expected telemetry
-   relevant evidence
-   recommended screenshots
-   investigation significance

## Evidence philosophy

These files document **what was intentionally performed to generate the
security telemetry**.

The `investigation/` and `threat-hunting/` sections of the repository
should instead document **what the analyst found in the resulting
telemetry**.

That distinction keeps the portfolio clear:

> **Attack simulation = activity generated**

> **Detection/investigation = activity observed and interpreted**

All activity was performed by the project author against the isolated
lab environment. No third-party systems were targeted.
