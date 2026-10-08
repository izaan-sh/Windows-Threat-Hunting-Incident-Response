# Stage 6 --- Scheduled Task Persistence

## Objective

Simulate persistence using a Windows Scheduled Task.

## Activity

A task named:

`SystemHealthCheck`

was created and executed during the incident window.

The task was configured to run under the SYSTEM context.

## Evidence

Relevant telemetry included:

-   Windows Security Event ID 4698 --- scheduled task created
-   Windows Security Event ID 4699 --- scheduled task deleted during
    cleanup
-   Task Scheduler Operational events 106/140 --- task
    registration/activity
-   Task Scheduler Operational events 200/201 --- task
    execution/completion
-   Sysmon process creation --- supporting process context

Creation occurred at approximately:

`10:34:19 UTC`

Execution occurred approximately:

`10:34:45 UTC`

## Screenshots

Recommended evidence:

-   `01-scheduled-task-created.png`
-   `02-task-scheduler-entry.png`
-   `03-task-execution.png`

## Investigation significance

The project deliberately compared Security and Task Scheduler telemetry.

A notable attribution discrepancy was observed: the Task Scheduler
Operational log reflected the SYSTEM run-as context, while the Security
4698 event and Sysmon process chain provided better evidence of who
initiated the task creation.

This demonstrated why persistence investigations should correlate
multiple telemetry sources.
