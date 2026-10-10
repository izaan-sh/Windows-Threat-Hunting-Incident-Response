# Recovery

Following containment (see [`containment.md`](containment.md)), the host was checked against the pre-incident baseline captured before the attack simulation began, and any leftover artifacts were cleaned up.

## Baseline captured before the attack

Before Stage 1 (brute force) was run, the following state was recorded for later comparison:

```powershell
Get-LocalUser | Out-File C:\Baseline\baseline_users.txt
Get-LocalGroupMember Administrators | Out-File C:\Baseline\baseline_admins.txt
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | Out-File C:\Baseline\baseline_tasks.txt
Get-NetTCPConnection -State Established | Out-File C:\Baseline\baseline_netconn.txt
```

## Post-containment state

The same commands were re-run after containment:

```powershell
Get-LocalUser | Out-File C:\Baseline\recovery_users.txt
Get-LocalGroupMember Administrators | Out-File C:\Baseline\recovery_admins.txt
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | Out-File C:\Baseline\recovery_tasks.txt
Get-Process | Out-File C:\Baseline\recovery_processes.txt
Get-NetTCPConnection -State Established | Out-File C:\Baseline\recovery_netconn.txt
```

## Comparison results

```powershell
Compare-Object (Get-Content C:\Baseline\baseline_admins.txt) (Get-Content C:\Baseline\recovery_admins.txt)
Compare-Object (Get-Content C:\Baseline\baseline_tasks.txt) (Get-Content C:\Baseline\recovery_tasks.txt)
```

| Check | Result |
|---|---|
| Local users | `lab_attacker` no longer present; only the original pre-incident accounts remained |
| Administrators group | No differences from baseline |
| Scheduled tasks | No trace of `SystemHealthCheck`; only unrelated, benign Windows/OneDrive housekeeping tasks that registered naturally over the operational period |
| Network connections | No persistent connection to `10.10.1.20` remained (the C2-style connection in Stage 8 was a single request, not a maintained channel) |
| Leftover files | `C:\Temp\scheduled_task_test.txt` removed |

The scheduled-task diff did surface a small number of new entries (`OneDrive Reporting Task`, `OneDrive Standalone Update Task`, `SoftLandingCreativeManagementTask`) and two state-only differences (`PrintJobCleanupTask`, `ResolutionHost` showing `Running` vs `Ready`). These are benign Windows/Microsoft Store background tasks that registered or changed state naturally over the lab's operational period, not artifacts of the simulated intrusion. Triaging and correctly dismissing this kind of baseline drift is itself a normal part of closing out a recovery pass.

## Verdict

The host was confirmed restored to its pre-incident state. The only residual differences were unrelated, benign application activity, not attacker artifacts.

## What a production SOC would additionally do here

- Monitor the host for a defined period post-recovery for any recurrence of the brute-force source IP or similar authentication patterns.
- Re-image the host from a known-good template rather than relying solely on manual reversal, if the environment's risk tolerance required it.
- Confirm EDR/antivirus signatures and detection content are current before returning the host to production use.
- Document the incident in a ticketing/case-management system and formally close it with sign-off, rather than considering recovery complete once the technical state matches baseline.

See the full write-up in [`report/Windows-Threat-Hunting-IR-Report.pdf`](../report/) for the complete Containment and Recovery sections alongside the rest of the investigation.
