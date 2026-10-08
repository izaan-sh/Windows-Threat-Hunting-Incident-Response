# Stage 7 --- Simulated File Staging

## Objective

Create, modify, and delete a fake sensitive file to simulate data
staging and subsequent cleanup behavior.

## Activity

The file used in the exercise was:

`C:\Temp\Finance\financial_report.txt`

The activity included:

1.  file creation
2.  modification/access
3.  deletion

## Telemetry gap

The initial run did not generate the expected Sysmon Event ID 11/23
records.

Investigation of the Sysmon configuration showed that generic file
activity in this location was not covered by the active configuration.

A targeted rule for:

`C:\Temp\Finance\*`

was then added.

The activity was re-performed and captured successfully.

## Evidence

Primary telemetry:

-   Sysmon Event ID 11 --- File Create
-   Sysmon Event ID 23 --- File Delete

The final evidence was re-captured at approximately `12:05:38 UTC`.

The original activity occurred approximately `10:41–10:44 UTC`.

## Screenshots

Recommended evidence:

-   `01-file-created.png`
-   `02-sysmon-event-11.png`
-   `03-sysmon-event-23.png`
-   `04-sysmon-config-gap-fix.png`

## Investigation significance

This became an explicit detection-coverage finding.

The project did not assume that a configured telemetry source guaranteed
visibility. The missing events were identified through deliberate
verification, the Sysmon configuration was adjusted, and the activity
was repeated to obtain the required evidence.
