# Stage 8 --- Simulated C2-Style HTTP Communication

## Objective

Generate a controlled outbound HTTP connection from the Windows
workstation to the Kali attacker host.

## Kali listener

Kali hosted a simple Python HTTP server:

``` bash
python3 -m http.server 8080
```

The Windows endpoint then made a request to:

`http://10.10.1.20:8080`

## Windows-side activity

The request was generated using PowerShell:

``` powershell
powershell.exe -NoProfile -Command "Invoke-WebRequest -Uri http://10.10.1.20:8080 -UseBasicParsing"
```

The request returned HTTP 200.

## Evidence

The key Windows telemetry was:

**Sysmon Event ID 3 --- Network Connection**

The investigation correlated:

``` text
powershell.exe
      ↓
10.10.1.20:8080
```

The connection was observed at approximately `10:50:44–10:51:00 UTC`.

Kali's HTTP server also logged the request, providing independent
attacker-side confirmation.

## Screenshots

Recommended evidence:

-   `01-kali-http-server.png`
-   `02-windows-http-request.png`
-   `03-sysmon-event-3.png`
-   `04-kali-access-log.png`

## Interpretation

This was a **simulated C2-style outbound HTTP communication** pattern
used for process-to-network correlation.

It was not a real command-and-control framework and did not constitute
actual data exfiltration.

The activity was generated entirely within the isolated lab network.
