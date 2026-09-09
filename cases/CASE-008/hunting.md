# CASE-008 — Threat Hunting

## Hunting Objective

Determine whether the suspicious execution observed on `lab-ws-02` has related activity elsewhere in the available laboratory telemetry.

The primary hunting pivot is the executable:

`/tmp/invoice_viewer.exe`

## Primary Hunting Pivots

### File Path

Search available endpoint telemetry for:

`/tmp/invoice_viewer.exe`

This can identify repeated execution or related activity.

### Process Name

Search for:

`invoice_viewer.exe`

This can identify executions of the same process across laboratory hosts.

### User

Search for:

`analyst`

Review whether the same user account is associated with additional suspicious execution events.

### Host

Search for:

`lab-ws-02`

Review endpoint events around the detection timestamp for related process, authentication, file, and network activity.

### Execution Time

Focus on activity around:

`2026-09-09T12:00:00Z`

Temporal correlation can identify events immediately before or after the suspicious execution.

## Current Hunting Result

The CASE-008 dataset contains two process execution events:

- `EVT-008001` — suspicious execution of `invoice_viewer.exe`
- `EVT-008002` — benign execution of `backup_agent.exe`

No additional related telemetry is present in the supplied CASE-008 dataset.

Therefore, no lateral execution, persistence, network activity, or additional host compromise is asserted.

## Recommended Extended Hunt

If additional laboratory telemetry becomes available, search for:

1. SHA-256 hash of the executable
2. Process name across all endpoints
3. File path across all endpoints
4. Command-line fragments
5. Parent and child processes
6. Network destinations
7. DNS queries
8. Persistence mechanisms
9. Authentication events
10. Related file creation or modification events

## Hunting Limitation

Absence of related events in this small laboratory dataset does not prove that no related activity exists.

The hunting result is limited to the telemetry available to this case.
