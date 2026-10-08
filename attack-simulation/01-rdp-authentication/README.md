# Stage 1 --- RDP Authentication

## Objective

Simulate an initial access attempt against the Windows workstation
through Remote Desktop Protocol (RDP).

The exercise generated repeated failed authentication attempts followed
by a successful authentication from the controlled Kali attacker host.

## Activity

**Target:** `WKS-FIN-01` --- `10.10.1.10`\
**Attacker host:** `KALI-ATT-01` --- `10.10.1.20`\
**Account targeted:** `j.carter`

The authentication sequence produced:

-   8 failed logon attempts
-   a successful protocol-level authentication
-   a later interactive RDP session

## Evidence

Expected Windows Security evidence:

    Event Meaning
  ------- ------------------
     4625 Failed logon
     4624 Successful logon
     4634 Logoff

The failed attempts occurred approximately between `09:18:49` and
`09:19:17` UTC.

The successful protocol-level authentication occurred at approximately
`09:19:21` UTC.

The later interactive session generated a 4624 with Logon Type 10 at
approximately `10:07:34` UTC.

## Screenshots

Recommended evidence:

-   `01-failed-rdp-logons.png` --- multiple 4625 events
-   `02-successful-rdp-logon.png` --- successful 4624
-   `03-kali-rdp-session.png` --- Windows desktop accessed through Kali

## Why it matters

This stage establishes the initial authentication activity that
triggered the investigation. The important correlation is not simply
that a login succeeded, but that it followed a burst of failed
authentication attempts from the same attacker host.

All authentication activity was generated inside the isolated lab.
