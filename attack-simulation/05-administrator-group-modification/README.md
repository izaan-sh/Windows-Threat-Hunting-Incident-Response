# Stage 5 --- Administrator Group Modification

## Objective

Simulate privilege escalation by adding the newly created `lab_attacker`
account to the local Administrators group.

## Activity

`lab_attacker` was added to the local `Administrators` group.

## Evidence

Windows Security Event ID **4732** recorded the group membership change.

The event occurred at approximately:

`10:22:14 UTC`

## Screenshots

Recommended evidence:

-   `01-add-to-administrators-command.png`
-   `02-event-4732.png`
-   `03-administrators-membership.png`

## Investigation significance

The sequence:

``` text
4720 — account created
        ↓
4732 — account added to Administrators
```

provided a stronger signal than either event viewed independently.

The investigation also correlated these Security events with the earlier
`runas` process ancestry to understand how the administrative context
was obtained.
