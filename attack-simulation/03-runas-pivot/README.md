# Stage 3 --- Privilege Pivot with `runas`

## Objective

Simulate a credential pivot from the compromised `j.carter` session into
the `labadmin` account.

## Activity

The attacker used `runas.exe` from the existing PowerShell session to
launch an elevated command shell under the second account.

The relevant process ancestry was:

``` text
j.carter session
    └── powershell.exe
          └── runas.exe
                └── cmd.exe
```

The later account-management actions were therefore performed under the
`labadmin` security context.

## Evidence

The key evidence was Sysmon process creation telemetry showing:

-   `powershell.exe`
-   `runas.exe`
-   the resulting elevated `cmd.exe`
-   parent/child process relationships

Windows Security events subsequently identified `labadmin` as the
subject of the account-management operations.

## Screenshots

Recommended evidence:

-   `01-runas-command.png`
-   `02-runas-process-tree.png`
-   `03-elevated-shell.png`

## Investigation significance

This stage produced one of the strongest findings in the project.

The Security log's `SubjectUserName` for later account-management events
was `labadmin`. Viewed alone, this could appear to be routine
administrator activity.

Process ancestry provided additional context and showed that the
activity originated from the already-compromised `j.carter` session
through `runas.exe`.

This is why attribution in the investigation was based on cross-source
correlation rather than a single Security event.
