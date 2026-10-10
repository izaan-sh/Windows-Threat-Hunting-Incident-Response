# Containment

Containment was performed from a legitimate administrator session (`labadmin`), reversing every persistence and privilege change made during the simulated intrusion, in order. Each action was verified two ways: against the corresponding Windows Security Event in Microsoft Sentinel, and with a direct command-line check immediately after running it.

`lab_attacker` was disabled first rather than deleted immediately, to preserve its forensic value (SID, logon history, group membership) in case deeper investigation was needed before final cleanup.

## Actions taken

| # | Action | Command | Time (UTC) | Verified by |
|---|---|---|---|---|
| 1 | Disabled `lab_attacker` | `net user lab_attacker /active:no` | 20:30:03 | Security Event 4725; `Get-LocalUser` confirmed `Enabled: False` |
| 2 | Removed from Administrators | `net localgroup administrators lab_attacker /delete` | 20:30:15 | Security Event 4733; `Get-LocalGroupMember Administrators` showed only `labadmin` |
| 3 | Removed persistence (scheduled task) | `schtasks /delete /tn "SystemHealthCheck" /f` | 20:30:26 | Security Event 4699; `schtasks /query` returned "file not found" |
| 4 | Deleted `lab_attacker` | `net user lab_attacker /delete` | 20:31:30 | Security Event 4726; `Get-LocalUser` confirmed the account no longer existed |

Total time from first containment action to full account removal: **~90 seconds**.

## Verification query

```kql
SecurityEvent
| where TimeGenerated > ago(30m)
| where EventID in (4725, 4733, 4699, 4726)
| project TimeGenerated, EventID, TargetUserName, SubjectUserName, Activity
| order by TimeGenerated asc
```

Result: all four events present, correctly attributed to `labadmin`, each within seconds of the one before it.

| Time (UTC) | EventID | TargetUserName | SubjectUserName | Activity |
|---|---|---|---|---|
| 20:30:03 | 4725 | lab_attacker | labadmin | A user account was disabled |
| 20:30:15 | 4733 | Administrators | labadmin | A member was removed from a security-enabled local group |
| 20:30:26 | 4699 | — | — | A scheduled task was deleted |
| 20:31:30 | 4733 | Users | labadmin | A member was removed from a security-enabled local group (automatic, on account deletion) |
| 20:31:30 | 4726 | lab_attacker | labadmin | A user account was deleted |

Screenshot: `screenshots/06-containment-recovery/`

## Baseline comparison

A direct comparison of the Administrators group against the pre-incident baseline (captured before the attack began) returned no differences, confirming the privilege escalation was fully reversed, not merely claimed.

```powershell
Compare-Object (Get-Content C:\Baseline\baseline_admins.txt) (Get-Content C:\Baseline\post_incident_admins.txt)
```

Output: empty. The Administrators group matched the original baseline exactly (`labadmin` only).

## What a production SOC would additionally do here

This lab intentionally scoped containment to the host-local changes made during the exercise. A real incident of this shape would also require:

- Resetting `j.carter`'s password (the initially compromised account) and forcing re-authentication.
- Rotating `labadmin`'s credentials too, since they were used in the `runas` pivot and should be treated as potentially exposed.
- Checking for additional persistence mechanisms not explicitly tested here, such as registry Run keys, WMI event subscriptions, other scheduled tasks, or startup folder items.
- Isolating the host from the network entirely (NSG deny-all) while the above checks are in progress, rather than leaving it live.
- A memory or disk forensic capture before remediation, if the case warranted deeper investigation or legal/HR involvement.

See [`recovery.md`](recovery.md) for the post-containment verification pass.
