# CASE-010 — Lessons Learned and Detection Improvement

## 1. Purpose

This document records lessons learned from the CASE-010 multi-stage attack investigation.

The objective is to convert investigation findings into concrete improvements for detection engineering, correlation logic, testing, investigation procedures, and SOC operations.

CASE-010 is a synthetic laboratory exercise.

The lessons below are therefore engineering and investigation lessons rather than findings from a real production incident.

## 2. Case Summary

CASE-010 demonstrated a three-stage correlated sequence:

```text
Authentication attack
        ↓
Successful authentication
        ↓
Post-authentication activity
        ↓
Linux persistence
```

The individual detections were:

```text
DET-AUTH-001
DET-AUTH-003
DET-LINUX-001
```

The correlation layer generated:

```text
DET-CORR-001
```

The final correlated alert contained:

```text
3 stages
3 supporting alerts
13 supporting events
```

within a configured 30-minute correlation window.

## 3. Lesson — Individual Alerts Need Context

A single alert often provides only part of an investigation.

In CASE-010:

```text
DET-AUTH-001
```

identified repeated authentication failures.

By itself, this did not establish compromise.

The later detections added additional context:

```text
DET-AUTH-003
```

provided post-authentication activity.

```text
DET-LINUX-001
```

provided suspicious persistence activity.

The correlation layer connected these observations into a stronger investigation candidate.

### Improvement

SOC detection systems should preserve individual alerts while providing mechanisms to correlate related alerts using reliable investigation pivots.

## 4. Lesson — Correlation Should Not Replace Evidence

Correlation improves investigative confidence but does not convert inference into fact.

CASE-010 deliberately separates:

```text
Observed telemetry
        ↓
Detection
        ↓
Correlation
        ↓
Analyst interpretation
        ↓
Unproven claims
```

The correlated alert is therefore an investigation-prioritization mechanism rather than automatic proof of compromise.

### Improvement

Correlation outputs should explicitly preserve:

* supporting alert IDs;
* supporting event IDs;
* stage timestamps;
* correlation pivots;
* severity;
* confidence;
* detection versions; and
* analyst interpretation.

## 5. Lesson — Timestamp Schemas Must Be Consistent

During CASE-010 integration, the existing detection outputs did not expose an identical timestamp field structure.

`DET-AUTH-001` provided a direct `timestamp`.

`DET-AUTH-003` provided meaningful temporal information through fields including:

```text
first_seen
last_seen
```

The correlation layer initially expected only `timestamp`.

This created a real integration failure when an existing valid detection output was supplied to the new correlation component.

### Improvement

The correlation layer was adapted to use a deterministic timestamp selection strategy:

```text
timestamp
    ↓
last_seen
    ↓
first_seen
```

This allows correlation to work with the existing normalized detection outputs without fabricating timestamps.

### Engineering Lesson

Cross-component contracts should define temporal semantics explicitly.

Future detection schemas should preferably standardize:

* event timestamp;
* first seen;
* last seen;
* timezone requirements; and
* timestamp precedence.

## 6. Lesson — Correlation Requires Chronological Validation

The correlation logic does not merely require three alerts to exist.

The stages must occur in the expected order:

```text
DET-AUTH-001
        ↓
DET-AUTH-003
        ↓
DET-LINUX-001
```

The correlation layer rejects sequences that:

* occur out of order;
* exceed the configured correlation window; or
* contain conflicting source-IP information.

### Improvement

Correlation rules should validate both:

* stage presence; and
* stage chronology.

This reduces false correlations between unrelated alerts.

## 7. Lesson — Shared Pivots Need Careful Interpretation

CASE-010 uses:

```text
host
user
source_ip
```

as investigation pivots.

Shared values increase correlation confidence.

However, shared pivots are not proof of malicious activity.

For example, legitimate administrators may:

* authenticate from the same workstation;
* use privileged accounts;
* inspect system information; and
* modify scheduled tasks.

### Improvement

Correlation logic should combine multiple independent signals rather than relying on a single shared field.

## 8. Lesson — Benign Controls Are Essential

CASE-010 includes:

```text
EVT-010014
```

representing:

```text
crontab -e
```

This event was intentionally retained as a benign comparison point.

It demonstrates that cron activity alone should not automatically produce a multi-stage attack conclusion.

### Improvement

Detection tests and investigation datasets should include legitimate administrative behavior.

This helps evaluate:

* false positives;
* context requirements;
* threshold quality; and
* analyst decision-making.

## 9. Lesson — Persistence Indicators Should Be Combined

The Linux persistence detection requires multiple indicators.

CASE-010 produced:

```text
cron_persistence_path
shell_download_execution
hidden_or_tmp_payload
```

The combination is more meaningful than any single indicator.

For example:

```text
/etc/cron.d/
```

alone can represent legitimate administration.

Similarly:

```text
curl
```

alone is not necessarily malicious.

### Improvement

Host persistence detections should use multiple contextual indicators where appropriate and document known legitimate behavior.

## 10. Lesson — Detection Output Must Preserve Traceability

The investigation depends on a clear chain:

```text
Event
 ↓
Detection
 ↓
Alert
 ↓
Correlation
 ↓
Investigation
```

CASE-010 preserves this relationship through:

* supporting event IDs;
* supporting alert IDs;
* detection IDs;
* timestamps;
* host;
* user;
* source IP; and
* investigation documents.

### Improvement

Every mature detection should provide enough evidence references for an analyst to move from an alert back to the underlying telemetry.

## 11. Lesson — Alert IDs Need Cross-Case Semantics

The CASE-010 integration exposed an existing engineering issue in the Linux persistence detector.

The generated alert was:

```text
ALERT-CASE-009-DET-LINUX-001-EVT-010013
```

even though the detector was executed against CASE-010 telemetry.

The identifier therefore retains the namespace associated with the original CASE-009 implementation.

### Assessment

This does not prevent the correlation workflow from functioning.

The correlation layer correctly uses the actual supporting alert ID.

However, the identifier is semantically awkward when a reusable detector is applied to another case.

### Improvement

Future detector refactoring should separate:

```text
detection identity
```

from:

```text
case identity
```

and generate alert identifiers that remain unique without hardcoding a specific flagship case.

This should be implemented deliberately with regression tests rather than silently changing existing evidence.

## 12. Lesson — Detection Contracts Must Match Implementations

CASE-010 reinforces the importance of maintaining alignment between:

* YAML detection contracts;
* implementation logic;
* tests;
* alert schemas; and
* investigation documentation.

The correlation contract defines required stages and pivots.

The implementation must enforce those expectations consistently.

### Improvement

Every new detection or correlation capability should be validated against its contract before being treated as complete.

## 13. Lesson — Evidence Classification Prevents Overclaiming

The investigation separates evidence into:

### Observed Evidence

Examples:

* authentication failures;
* successful authentication;
* session activity;
* commands;
* persistence command;
* detection alerts.

### Analyst Interpretation

Examples:

* sequence is consistent with a multi-stage attack;
* persistence activity warrants investigation;
* correlation increases investigative priority.

### Unproven Claims

Examples:

* attacker identity;
* unauthorized access;
* malicious payload contents;
* successful persistence execution;
* confirmed compromise.

### Improvement

SOC reports should explicitly identify which statements are directly observed and which are analytical conclusions.

## 14. Lesson — Threat Intelligence Must Respect Laboratory Boundaries

The CASE-010 network indicators are synthetic.

The investigation therefore does not claim:

* real IP reputation;
* infrastructure ownership;
* geographic attribution;
* threat-actor attribution; or
* malware-family association.

### Improvement

Laboratory repositories should clearly distinguish:

```text
Synthetic indicator
```

from:

```text
Production threat intelligence
```

This prevents portfolio projects from accidentally making unsupported real-world claims.

## 15. Lesson — Hunting Should Expand Beyond the Alert

The investigation defined hunts for:

* source IP;
* host;
* user;
* session;
* authentication;
* persistence;
* command lines;
* timeline expansion; and
* benign administrative activity.

This demonstrates that alert handling should not stop at the initial detection.

### Improvement

SOC analysts should use alerts as starting points for broader investigation rather than treating alert generation as the end of the workflow.

## 16. Lesson — Response Should Preserve Evidence Before Remediation

CASE-010 response planning places evidence preservation before containment and eradication.

This is especially important when persistence or potential compromise is suspected.

### Improvement

Incident-response playbooks should explicitly define:

1. evidence preservation;
2. scope validation;
3. containment;
4. investigation;
5. eradication;
6. recovery;
7. validation; and
8. closure.

## 17. Lesson — Correlation Windows Need Validation

The correlation window is:

```text
30 minutes
```

The observed sequence fits within approximately ten minutes.

However, a correlation window is a detection-engineering parameter rather than a universal truth.

A window that is too short can miss related stages.

A window that is too long can increase false correlations.

### Improvement

Future validation should test:

* sequences below the window;
* sequences exactly at the boundary;
* sequences beyond the window;
* delayed persistence;
* missing stages; and
* unrelated activity sharing the same pivots.

## 18. Lesson — Missing Telemetry Is an Investigation Limitation

The case does not contain:

* actual payload contents;
* payload hash;
* complete network telemetry;
* DNS telemetry;
* process ancestry;
* complete enterprise authentication data; or
* external threat-intelligence enrichment.

Therefore, some conclusions remain undetermined.

### Improvement

Production SOC workflows should define minimum evidence requirements for high-confidence incident conclusions.

## 19. Detection Feedback Loop

CASE-010 demonstrates the intended detection-engineering feedback loop:

```text
Investigation
     ↓
Detection weakness
     ↓
Engineering improvement
     ↓
Regression test
     ↓
Validation
     ↓
Updated detection capability
```

The timestamp-schema integration issue is a concrete example of this process.

The correlation layer initially expected a timestamp field that was not uniformly present.

The implementation was then adapted to handle the existing normalized alert structures deterministically.

## 20. Recommended Regression Tests

Future CASE-010 validation should include:

### Positive Correlation

```text
AUTH-001
+
AUTH-003
+
LINUX-001
=
CORR-001
```

Expected:

```text
one correlated alert
```

### Missing Stage

```text
AUTH-001
+
AUTH-003
```

Expected:

```text
no correlation
```

### Out-of-Order Stages

Expected:

```text
no correlation
```

### Correlation Window Exceeded

Expected:

```text
no correlation
```

### Conflicting Source IPs

Expected:

```text
no correlation
```

### Different Host

Expected:

```text
no correlation
```

### Different User

Expected:

```text
no correlation
```

### Benign Cron Activity

Expected:

```text
no DET-LINUX-001 alert
```

### Timestamp Fallback

Expected:

```text
timestamp available
→ use timestamp

timestamp absent, last_seen available
→ use last_seen

timestamp and last_seen absent, first_seen available
→ use first_seen
```

## 21. Engineering Priorities

The lessons from CASE-010 produce the following priorities:

### Priority 1 — Standardize Alert Schemas

Ensure detection outputs expose consistent temporal and evidence fields.

### Priority 2 — Improve Alert Identifier Semantics

Separate reusable detection identity from case-specific identifiers.

### Priority 3 — Expand Correlation Testing

Add boundary, missing-stage, conflicting-pivot, and malformed-alert tests.

### Priority 4 — Continue False-Positive Validation

Maintain benign administrative controls in detection datasets.

### Priority 5 — Integrate Existing Security Projects

Where appropriate, connect:

* malware analysis;
* threat hunting;
* endpoint monitoring;
* Linux security monitoring; and
* other CYBERNOVA detection capabilities

through evidence-preserving investigation workflows.

## 22. Portfolio Evidence Value

CASE-010 provides evidence of practical capability in:

* multi-stage detection correlation;
* SOC alert operations;
* investigation pivots;
* timeline reconstruction;
* threat hunting;
* threat-intelligence assessment;
* ATT&CK mapping;
* incident-response planning;
* evidence classification;
* detection engineering;
* regression testing; and
* security-focused engineering.

These capabilities should be presented as **hands-on SOC laboratory experience**, not as professional production SOC employment.

## 23. Laboratory Limitations

All lessons are derived from a controlled synthetic environment.

The case does not establish:

* production SOC performance;
* real customer incidents;
* real attacker attribution;
* real-world threat intelligence;
* enterprise-scale detection coverage; or
* professional employment experience.

The portfolio should communicate the laboratory nature of the evidence clearly.

## 24. Final Lesson

The central lesson from CASE-010 is:

```text
Strong SOC work is not simply detecting suspicious events.

It is connecting evidence,
testing assumptions,
preserving traceability,
challenging false positives,
correlating related activity,
documenting uncertainty,
and feeding investigation results
back into detection engineering.
```

CASE-010 therefore serves as the capstone demonstration of the SOC laboratory's progression from individual detection rules toward an evidence-driven multi-stage investigation workflow.
