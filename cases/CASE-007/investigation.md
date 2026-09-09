# CASE-007 — Investigation

## Investigation Summary

**Case ID:** CASE-007

**Scenario:** File Integrity Violation

**Detection:** DET-HOST-001 — File Integrity Violation Detection

**Alert ID:** ALERT-CASE-007-DET-HOST-001

**Severity:** High

**Confidence:** High

**Environment:** Controlled cybersecurity laboratory using synthetic telemetry

**Investigation Status:** Open — investigation workflow in progress

## 1. Investigation Objective

Determine whether the clustered file integrity violations observed on `lab-host-01` are consistent with authorized administrative activity, suspicious system modification, or potentially malicious file manipulation.

The investigation must distinguish observed telemetry from analyst interpretation. File changes alone do not establish compromise or malicious intent.

## 2. Alert Trigger

`DET-HOST-001` evaluates file integrity events grouped by host.

The configured detection conditions are:

- `event_type` must be `file_integrity`
- `status` must be `changed`
- `change_type` must be `modified`, `created`, or `deleted`
- Events are grouped by host
- At least two qualifying violations must occur within five minutes

The alert was generated because two qualifying changes occurred on `lab-host-01` between `12:00:00Z` and `12:02:00Z`.

## 3. Observed Telemetry

The case telemetry contains three file integrity events.

| Event ID | Timestamp | Host | File | Change | Authorized |
|---|---|---|---|---|---|
| `EVT-007001` | `2026-09-08T12:00:00Z` | `lab-host-01` | `/etc/ssh/sshd_config` | modified | No |
| `EVT-007002` | `2026-09-08T12:02:00Z` | `lab-host-01` | `/etc/passwd` | modified | No |
| `EVT-007003` | `2026-09-08T12:20:00Z` | `lab-host-01` | `/opt/application/config.yml` | modified | Yes |

The first two events satisfy the detection threshold.

The third event occurs outside the five-minute detection window and is explicitly marked as an authorized laboratory change.

## 4. Initial Triage

The two correlated changes affect security-sensitive system files:

- `/etc/ssh/sshd_config`
- `/etc/passwd`

These paths warrant elevated investigation priority because changes to SSH configuration or local account information can materially affect host security.

However, the telemetry does not establish:

- who authorized the changes;
- which process performed the changes;
- whether the files were modified through an administrative workflow;
- whether package management caused the changes;
- whether an attacker performed the changes;
- whether persistence was established;
- whether the host was compromised.

Therefore, the current assessment remains an investigation hypothesis rather than a confirmed security incident.

## 5. Evidence Validation

The alert references:

- `EVT-007001`
- `EVT-007002`

Both supporting events occur within the configured five-minute detection window.

The alert reports:

- **Violation count:** 2
- **Affected files:** `/etc/passwd`, `/etc/ssh/sshd_config`
- **Change type:** `modified`
- **First observed:** `2026-09-08T12:00:00Z`
- **Last observed:** `2026-09-08T12:02:00Z`

The third telemetry event is not part of the alert because it occurs at `12:20:00Z`.

## 6. Hash Evidence

The telemetry records both previous and new file hashes for each observed change.

For `EVT-007001`:

- File: `/etc/ssh/sshd_config`
- Previous hash: recorded in telemetry
- New hash: recorded in telemetry

For `EVT-007002`:

- File: `/etc/passwd`
- Previous hash: recorded in telemetry
- New hash: recorded in telemetry

The hash values demonstrate that the recorded file state changed.

They do not independently establish whether the resulting file contents are malicious.

## 7. Authorization Assessment

The first two events contain:

```text
authorized_change: false

This increases investigative priority because the laboratory telemetry does not identify the changes as approved administrative activity.

This field should nevertheless be treated as telemetry supplied by the laboratory scenario rather than independent proof of unauthorized access.

The third event contains:

authorized_change: true

and occurs outside the detection window.

8. Investigation Hypotheses
Hypothesis A — Authorized Administrative Change

An administrator or approved maintenance process modified the files.

Evidence required:

change-management record;
administrator activity;
package-management logs;
configuration-management records;
scheduled maintenance information.
Hypothesis B — Suspicious Local Modification

An unauthorized process or user modified security-sensitive files.

Evidence required:

process execution telemetry;
shell history where available;
authentication events;
privilege escalation events;
parent/child process relationships;
file access telemetry.
Hypothesis C — Malicious Modification

An attacker with local privileges modified host configuration or account information as part of a broader compromise.

Evidence required:

suspicious authentication;
privilege escalation;
persistence indicators;
malicious process execution;
unexpected account changes;
network connections;
additional file modifications.

The current telemetry alone cannot select among these hypotheses conclusively.

9. Recommended Evidence Preservation

Preserve the following before making remediation changes:

Original CASE-007 telemetry.
Generated alert JSON.
Original and new file hashes.
Relevant authentication events.
Relevant process execution events.
Privilege escalation records.
Package-management logs.
Configuration-management records.
Administrative change records.
Relevant network telemetry.

Evidence should remain unchanged so that later investigation and timeline reconstruction can be reproduced.

10. Investigation Scope

The immediate investigation scope is:

Host: lab-host-01

Primary files:

/etc/ssh/sshd_config
/etc/passwd

Detection window:

2026-09-08T12:00:00Z through 2026-09-08T12:05:00Z

Supporting events:

EVT-007001
EVT-007002

The authorized /opt/application/config.yml change at 12:20:00Z is retained as contextual telemetry but is outside the alert window.

11. Current Assessment

Assessment: Suspicious file-state modification requiring further investigation.

The evidence demonstrates two clustered modifications to security-sensitive files on the same monitored host.

The evidence does not independently demonstrate compromise, persistence, malicious execution, or unauthorized access.

The investigation should therefore continue with timeline reconstruction, indicator analysis, threat-intelligence context, and host-level hunting.

12. Next Investigation Actions

The next investigation steps are:

Reconstruct the event timeline.
Identify file and host indicators.
Review related authentication activity.
Review process and privilege activity.
Determine whether package or configuration management explains the changes.
Evaluate relevant threat-intelligence context.
Hunt for additional related file modifications.
Determine whether containment is warranted.
Produce the final case assessment.
Feed confirmed detection weaknesses back into detection engineering.
13. Laboratory Limitations

This investigation uses synthetic laboratory telemetry.

No production host, real user account, real credential, or real security incident is being claimed.

The case demonstrates a defensive SOC investigation workflow and should not be interpreted as evidence of an actual compromise.
