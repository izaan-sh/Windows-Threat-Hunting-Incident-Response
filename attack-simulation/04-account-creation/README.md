# Stage 4 --- Local Account Creation

## Objective

Create a new local account to simulate attacker persistence.

## Activity

The account:

`lab_attacker`

was created during the simulated compromise.

The account was created while operating under the `labadmin` context
established during the previous privilege pivot.

## Evidence

Windows Security Event ID **4720** recorded the account creation.

The report timeline places the event at approximately:

`10:21:52 UTC`

## Screenshots

Recommended evidence:

-   `01-account-creation-command.png`
-   `02-event-4720.png`
-   `03-local-users-verification.png`

## Investigation significance

The new account was treated as a high-value persistence indicator
because it was created during the incident window and was not part of
the original host baseline.

The investigation subsequently checked whether the account received
additional privileges.
