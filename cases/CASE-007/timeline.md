# CASE-007 — Timeline

## Timeline Overview

**Case ID:** CASE-007

**Scenario:** File Integrity Violation

**Host:** `lab-host-01`

**Detection:** `DET-HOST-001` — File Integrity Violation Detection

**Detection Window:** Five minutes

**Alert ID:** `ALERT-CASE-007-DET-HOST-001`

**Environment:** Controlled cybersecurity laboratory using synthetic telemetry

## Chronological Timeline

| Time (UTC) | Event ID | Event Type | User | File | Change | Authorization |
|---|---|---|---|---|---|---|
| 2026-09-08 12:00:00 | `EVT-007001` | file_integrity | `root` | `/etc/ssh/sshd_config` | modified | No |
| 2026-09-08 12:02:00 | `EVT-007002` | file_integrity | `root` | `/etc/passwd` | modified | No |
| 2026-09-08 12:20:00 | `EVT-007003` | file_integrity | `root` | `/opt/application/config.yml` | modified | Yes |

## 1. Detection Window

The first qualifying event occurred at:

`2026-09-08T12:00:00Z`

The second qualifying event occurred at:

`2026-09-08T12:02:00Z`

The elapsed time between the two events was **2 minutes**.

Because both events occurred within the configured five-minute window, `DET-HOST-001` generated an alert.

## 2. Event — EVT-007001

**Timestamp:** `2026-09-08T12:00:00Z`

**Host:** `lab-host-01`

**User:** `root`

**File:** `/etc/ssh/sshd_config`

**Change Type:** `modified`

**Status:** `changed`

**Authorization:** `authorized_change=false`

### Interpretation

The monitored SSH server configuration changed.

The telemetry records the change as unauthorized within the laboratory scenario.

This event alone does not establish malicious activity.

## 3. Event — EVT-007002

**Timestamp:** `2026-09-08T12:02:00Z`

**Host:** `lab-host-01`

**User:** `root`

**File:** `/etc/passwd`

**Change Type:** `modified`

**Status:** `changed`

**Authorization:** `authorized_change=false`

### Interpretation

The local account database was modified two minutes after the SSH configuration change.

The proximity of the two security-sensitive file modifications is the primary correlation that caused the detection to trigger.

This event alone does not establish account compromise or malicious activity.

## 4. Event — EVT-007003

**Timestamp:** `2026-09-08T12:20:00Z`

**Host:** `lab-host-01`

**User:** `root`

**File:** `/opt/application/config.yml`

**Change Type:** `modified`

**Status:** `changed`

**Authorization:** `authorized_change=true`

### Interpretation

This change occurred 18 minutes after the first event and outside the five-minute detection window.

The telemetry identifies the change as authorized laboratory activity.

It is therefore contextual evidence rather than supporting evidence for the generated alert.

## 5. Correlation Analysis

The detection-relevant sequence is:

```text
12:00:00Z
/etc/ssh/sshd_config modified
        ↓
12:02:00Z
/etc/passwd modified
        ↓
2-minute interval
        ↓
2 qualifying violations
        ↓
DET-HOST-001 triggered

The correlation is based on:

Same host
Same event type
Same changed status
Qualifying change types
Two events within five minutes
6. Alert Boundaries

The alert contains:

EVT-007001
EVT-007002

The alert does not contain:

EVT-007003

The third event is excluded because it occurs outside the five-minute detection window.

7. Temporal Assessment

The observed sequence demonstrates clustered file modifications on a single host.

The first two events are temporally correlated strongly enough to satisfy the detection rule.

The available telemetry does not establish what process performed the modifications or why they occurred.

Further investigation is required to determine whether the activity was administrative, software-driven, misconfigured, or malicious.

8. Evidence Integrity

The timeline is derived from the synthetic telemetry stored at:

telemetry/host/CASE-007.jsonl

The generated detection evidence is stored at:

alerts/CASE-007-DET-HOST-001.json

The event IDs provide the linkage between raw telemetry and the generated alert.

No event timestamps have been altered for this case.

9. Investigation-Relevant Questions

The timeline raises the following questions for further investigation:

What process modified /etc/ssh/sshd_config?
What process modified /etc/passwd?
Was the root activity associated with an authorized administrative session?
Did package management or configuration management modify either file?
Were there authentication events immediately before the changes?
Were privilege escalation events observed?
Were additional files modified around the same time?
Did the host establish unusual network connections?
Were new accounts, SSH keys, or authentication settings introduced?
Is there evidence connecting the two modifications to the same activity?
10. Timeline Conclusion

The timeline confirms two qualifying file integrity violations within a two-minute interval on lab-host-01.

This temporal clustering triggered DET-HOST-001.

The later authorized configuration change is outside the alert window and does not contribute to the detection.

The timeline supports continued investigation but does not independently prove compromise or malicious intent.

Laboratory Limitations

This timeline uses synthetic laboratory telemetry.

It represents a controlled SOC investigation scenario and does not describe a real production security incident.
