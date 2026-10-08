# Kali Attacker Setup

## Host

  Setting    Value
  ---------- ---------------------------------------
  Hostname   `KALI-ATT-01`
  OS         Kali Linux
  IP         `10.10.1.20`
  Role       Controlled attacker / simulation host

Kali was used only as a controlled attacker host inside the isolated lab
network.

## Network

The lab network was:

`10.10.1.0/24`

Windows target:

`10.10.1.10`

Kali attacker:

`10.10.1.20`

The two systems were intentionally kept within the isolated lab
environment so that the generated activity could be attributed to the
exercise.

## RDP authentication testing

The initial attack stage simulated repeated RDP authentication attempts
against the Windows workstation.

The resulting Windows telemetry was:

-   Event ID 4625 for failed authentication
-   Event ID 4624 for successful authentication

The successful authentication was followed by an interactive RDP
session, represented by a 4624 event with Logon Type 10.

The exact credential values used for the exercise are intentionally not
documented in this repository.

## Interactive access

FreeRDP was used from Kali to establish the controlled RDP session to
the Windows workstation.

Example structure:

``` bash
xfreerdp /v:10.10.1.10 /u:j.carter
```

The password is not included in this repository.

## HTTP listener

Kali also hosted a simple Python HTTP server to provide a controlled
destination for the Windows-side network activity.

Example:

``` bash
python3 -m http.server 8080
```

The Windows endpoint then generated an HTTP request to:

`http://10.10.1.20:8080`

This was used to create a simple process-to-network correlation point
for the investigation.

The activity is described in the report as **simulated C2-style outbound
HTTP communication**. It was not a real command-and-control framework or
a real data-exfiltration operation.

## Evidence generated

The Kali host provided supporting evidence for:

-   RDP authentication activity
-   interactive RDP access
-   the attacker-side HTTP request receipt
-   timestamps used to correlate network activity with Windows Sysmon
    Event ID 3

## Operational note

All attacker-side actions were performed by the project author as part
of the controlled exercise. No third-party systems were targeted.
