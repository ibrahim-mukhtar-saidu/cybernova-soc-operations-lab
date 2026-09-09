# CASE-007 — File Integrity Violation

## Case Overview

**Scenario:** Clustered file integrity violations on a monitored Linux host.

**Detection:** `DET-HOST-001` — File Integrity Violation Detection

**Alert:** `ALERT-CASE-007-DET-HOST-001`

**Severity:** High

**Confidence:** High

**Environment:** Controlled cybersecurity laboratory using synthetic telemetry.

## Objective

Investigate clustered file integrity events affecting a monitored host and determine whether the observed changes are consistent with authorized activity, suspicious activity, or a potentially malicious modification.

The detection identifies file-state changes but does not independently establish malicious intent.

## Observed Evidence

The telemetry contains three file integrity events for `lab-host-01`.

Two changes occurred within the configured five-minute detection window:

- `/etc/ssh/sshd_config`
- `/etc/passwd`

A third change to `/opt/application/config.yml` occurred outside the detection window and is marked as an authorized laboratory change.

The detection engine generated one alert because two qualifying violations occurred within five minutes.

## Detection Logic

`DET-HOST-001` groups qualifying file integrity events by host and evaluates them within a five-minute window.

A detection is generated when at least two qualifying violations are observed.

Qualifying changes are:

- `modified`
- `created`
- `deleted`

Only events with `event_type=file_integrity` and `status=changed` are evaluated.

## Evidence Chain

```text
File integrity telemetry
        ↓
DET-HOST-001
        ↓
ALERT-CASE-007-DET-HOST-001
        ↓
Triage
        ↓
Evidence preservation
        ↓
Timeline reconstruction
        ↓
Indicator analysis
        ↓
Threat-intelligence context
        ↓
Hunting
        ↓
ATT&CK mapping
        ↓
Response decision
        ↓
Final assessment
        ↓
Detection improvement
        ↓
Test
        ↓
Security validation
        ↓
Document
        ↓
GitHub evidence
        ↓
Recruiter review
        ↓
Interview evidence
Case Artifacts
README.md — Case overview and investigation scope
alert.json — Detection output and supporting event references
investigation.md — Investigation and triage record
timeline.md — Chronological reconstruction
indicators.md — File and event indicators
threat-intelligence.md — Intelligence context and limitations
hunting.md — Follow-up hunting hypotheses and queries
response.md — Containment, eradication, recovery, and escalation considerations
final-report.md — Final case assessment
lessons-learned.md — Detection and process improvements
Evidence Sources
Primary Evidence
telemetry/host/CASE-007.jsonl
alerts/CASE-007-DET-HOST-001.json
Detection Implementation
src/detection_engine.py
detections/host/DET-HOST-001-file-integrity.yml
Laboratory Limitations

This case uses synthetic laboratory telemetry.

The observed file changes do not prove compromise, persistence, unauthorized access, or malicious intent.

Any production investigation would require corroborating endpoint, authentication, process, package-management, configuration-management, and administrative-change evidence.

No production incident is being claimed.

Case Status

Status: Investigation workflow in progress

The detection and initial alert evidence are implemented. The remaining case artifacts document the investigation, evidence analysis, response considerations, final assessment, and detection-improvement feedback loop.
