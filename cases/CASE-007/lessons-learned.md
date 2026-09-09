# CASE-007 — Lessons Learned

## Lessons Learned Summary

**Case ID:** CASE-007

**Scenario:** File Integrity Violation

**Detection:** `DET-HOST-001` — File Integrity Violation Detection

**Alert ID:** `ALERT-CASE-007-DET-HOST-001`

**Environment:** Controlled cybersecurity laboratory using synthetic telemetry

**Case Disposition:** Suspicious activity — unresolved

## 1. Purpose

This document records the technical, detection-engineering, investigation, and SOC-operation lessons identified during CASE-007.

The purpose is to convert investigation findings into measurable improvements to detection coverage, telemetry quality, analyst workflow, and future test cases.

## 2. Primary Lesson

A file-integrity alert identifies a change in file state.

It does not, by itself, establish malicious intent.

The investigation therefore demonstrated the importance of correlating file-integrity telemetry with additional security signals before declaring compromise.

The central lesson is:

> A suspicious file modification should trigger disciplined investigation and evidence correlation, not an unsupported compromise conclusion.

## 3. Detection Engineering Lessons

### Lesson 1 — Correlation Reduces Isolated-Event Noise

A single file modification may be legitimate.

Requiring multiple qualifying changes on the same host within a defined time window provides stronger investigative context.

`DET-HOST-001` currently requires:

```text
minimum violations: 2
window: 5 minutes
grouping: host

This is appropriate for the synthetic scenario but should not be treated as a universal production threshold.

Lesson 2 — Sensitive Paths Require Context

Changes to:

/etc/passwd
/etc/ssh/sshd_config

deserve elevated investigation priority.

However, path sensitivity alone does not prove malicious activity.

Future detection improvements should combine path sensitivity with:

process context;
authentication context;
privilege context;
authorization context;
network context.
Lesson 3 — Authorization Context Is Valuable

The synthetic telemetry contains:

authorized_change=false

for the two triggering events.

This provides useful laboratory context.

In a production environment, authorization should preferably be correlated with trusted change-management or configuration-management records rather than relying solely on an event field.

4. Telemetry Lessons
Lesson 4 — File Events Need Rich Context

The current telemetry records:

event ID;
timestamp;
host;
user;
file path;
change type;
old hash;
new hash;
metadata.

Future telemetry should also capture, where available:

process name;
process ID;
parent process;
command line;
executable hash;
process integrity level;
authentication session;
privilege transition;
source IP;
change-management identifier.

This would significantly improve investigation capability.

Lesson 5 — Hashes Show State Change, Not Intent

The old and new hash values demonstrate that file state changed.

A hash alone cannot explain:

who initiated the change;
why the change occurred;
whether the resulting file is malicious;
whether the resulting configuration is insecure.

Hash evidence therefore requires contextual interpretation.

5. Investigation Lessons
Lesson 6 — Start With Evidence Preservation

Evidence should be preserved before remediation changes the environment.

Important evidence includes:

FIM telemetry;
alert output;
file hashes;
file metadata;
authentication records;
process records;
privilege events;
account changes;
package-management records;
configuration-management records.

This preserves the ability to reconstruct the event accurately.

Lesson 7 — Security-Sensitive Files Require Broader Investigation

The modification of /etc/passwd should lead investigators toward account-related questions.

The modification of /etc/ssh/sshd_config should lead investigators toward remote-access questions.

Neither conclusion should be assumed from the file path alone.

Lesson 8 — Investigation Must Test Competing Hypotheses

The investigation considered several possible explanations:

Authorized administration.
Package or configuration management.
Unexpected local activity.
Unauthorized modification.
Malicious activity.

Testing multiple hypotheses reduces confirmation bias.

6. Threat Intelligence Lessons
Lesson 9 — Do Not Manufacture Attribution

No threat actor, malware family, campaign, or infrastructure was established.

The correct intelligence conclusion is therefore:

No attribution established.

Threat intelligence should support evidence-based investigation rather than force an attribution where none exists.

Lesson 10 — ATT&CK Mapping Requires Evidence

The current detection contract contains contextual mapping to:

T1070 — Indicator Removal

The investigation demonstrates why ATT&CK mappings should be reviewed against the actual behavior being observed.

A generic file modification should not automatically be interpreted as indicator removal.

Future quality validation should determine whether this mapping should be retained, refined, or removed based on stronger behavioral evidence.

7. Response Lessons
Lesson 11 — Containment Must Be Proportional

The alert severity is high, but severity does not automatically require destructive containment.

The available evidence does not establish active compromise.

Therefore, the response plan correctly prioritizes:

preserve
    ↓
validate
    ↓
correlate
    ↓
assess
    ↓
contain if justified
Lesson 12 — Avoid Premature Remediation

Immediately restoring files or isolating a host can destroy useful evidence.

Response actions should consider:

current threat activity;
evidence preservation;
business or laboratory impact;
confidence;
authorization;
corroborating telemetry.
8. Detection Feedback Loop

CASE-007 produced several concrete detection-improvement opportunities.

Current Detection
file integrity event
        ↓
same host
        ↓
2+ violations
        ↓
5-minute window
        ↓
alert
Future Correlation
file integrity
        +
authentication
        +
process execution
        +
privilege activity
        +
network activity
        +
authorization context
        ↓
higher-confidence investigation

These improvements should be implemented incrementally.

Each implementation should include:

positive test;
negative test;
malformed-input test where relevant;
regression validation;
security validation;
documentation update.
9. False-Positive Considerations

Potential legitimate causes of file changes include:

system administration;
package installation;
package upgrades;
configuration-management systems;
automated maintenance;
security tooling;
scheduled jobs.

Therefore, future versions of the detection should improve authorized-change discrimination.

Possible approaches include:

maintenance windows;
trusted automation identities;
package-management correlation;
configuration-management correlation;
approved change identifiers.

These mechanisms should be implemented only when reliable telemetry is available.

10. False-Negative Considerations

The current detection may miss activity when:

only one sensitive file is modified;
changes occur outside the five-minute window;
an attacker distributes changes over time;
different hosts are involved;
file monitoring is incomplete;
telemetry is missing;
events are not classified as file_integrity;
an attacker modifies files without producing expected FIM telemetry.

These limitations should guide future adversarial testing.

11. Adversarial Testing Opportunities

Future tests should evaluate whether the detection can be bypassed through:

Slow Modification

Spread changes beyond five minutes.

Distributed Modification

Modify one sensitive file on multiple hosts.

Single-File Modification

Change only one sensitive file.

Event Manipulation

Submit malformed or incomplete file-integrity events.

Timestamp Manipulation

Use invalid or inconsistent timestamps.

Duplicate Events

Replay identical event IDs.

Authorization Manipulation

Mark unauthorized activity as authorized.

Telemetry Gaps

Remove expected process or authentication context.

The goal is to understand detection limitations, not to simulate attacks against production systems.

12. Engineering Lessons
Lesson 13 — Validation Must Be Explicit

File-integrity events require schema validation before detection logic consumes them.

Required fields should remain explicit and deterministic.

Lesson 14 — Detection Logic Should Be Testable

The implementation now has focused tests for:

qualifying file modifications;
insufficient violations.

This creates a baseline for future changes.

Lesson 15 — Detection Contracts Should Match Implementation

The YAML detection contract documents:

data source;
qualifying events;
grouping;
time window;
threshold;
alert fields;
limitations.

Future changes to the implementation should update the detection contract and tests together.

13. Testing Lessons

The CASE-007 implementation introduced focused regression coverage.

The full test suite currently validates the repository's existing detection behavior alongside the new host-integrity detection.

The positive and negative CASE-007 tests demonstrate:

2 qualifying violations
        ↓
alert

1 qualifying violation
        ↓
no alert

Future testing should expand coverage for:

multiple hosts;
mixed change types;
created files;
deleted files;
events outside the detection window;
malformed telemetry;
duplicate event IDs;
invalid timestamps;
missing fields;
authorization context;
detection boundary conditions.
14. SOC Workflow Lessons

CASE-007 reinforces the complete SOC evidence chain:

telemetry
    ↓
detection
    ↓
alert
    ↓
triage
    ↓
evidence preservation
    ↓
timeline
    ↓
indicators
    ↓
threat intelligence
    ↓
hunting
    ↓
ATT&CK context
    ↓
response
    ↓
final assessment
    ↓
detection improvement
    ↓
testing

Each stage should remain traceable to evidence.

15. Portfolio Evidence Lessons

The case demonstrates several capabilities relevant to SOC hiring evidence:

detection engineering;
host monitoring;
alert generation;
evidence preservation;
timeline reconstruction;
indicator analysis;
threat hunting;
threat-intelligence reasoning;
incident-response planning;
ATT&CK analysis;
detection feedback;
regression testing;
laboratory limitations.

These capabilities should be presented as hands-on cybersecurity laboratory experience.

They must not be represented as professional production SOC employment.

16. Documentation Lessons

A strong investigation record should clearly distinguish:

Observed

What the telemetry directly demonstrates.

Inferred

What the evidence reasonably suggests.

Unknown

What cannot currently be established.

Recommended

What should be investigated or performed next.

This separation prevents unsupported conclusions.

17. Process Improvements

Future cases should continue to use:

Standardized case IDs.
Stable alert IDs.
Traceable event IDs.
Structured case artifacts.
Evidence classification.
Explicit limitations.
Detection-to-test feedback.
Reproducible synthetic telemetry.
Clear production disclaimers.
Git-based evidence history.
18. Recommended Detection Improvements

Priority improvements for DET-HOST-001:

Priority 1 — Process Correlation

Identify the process responsible for a file modification.

Priority 2 — Authentication Correlation

Identify recent authentication associated with the modification.

Priority 3 — Privilege Correlation

Identify privilege transitions associated with the change.

Priority 4 — Authorization Correlation

Distinguish approved changes from unexplained changes.

Priority 5 — Path Risk

Apply differentiated risk to security-sensitive files.

Priority 6 — Multi-Signal Correlation

Combine file, process, authentication, privilege, and network signals.

Each improvement should be accompanied by regression tests.

19. Lessons-to-Action Matrix
Lesson	Improvement	Validation
File changes lack context	Add process correlation	Positive/negative tests
Sensitive paths need priority	Add path-risk logic	Path classification tests
Authorization matters	Add trusted change context	Authorized/unauthorized tests
Hashes lack intent	Correlate hashes with content/context	Evidence validation
Single events may be benign	Maintain clustering threshold	Boundary tests
Slow activity may evade detection	Test wider temporal patterns	Adversarial tests
ATT&CK mapping needs evidence	Review technique mapping	ATT&CK quality audit
Response must preserve evidence	Formalize preservation workflow	Case checklist
Attribution requires evidence	Require corroboration	Intelligence review
20. Final Lessons

The most important lessons from CASE-007 are:

File integrity detection is most valuable when combined with contextual telemetry.
Security-sensitive files deserve elevated investigation priority.
A file hash proves state change, not malicious intent.
Authorization context can significantly reduce false positives.
Evidence preservation must precede destructive remediation when practical.
Competing hypotheses reduce investigative bias.
Threat intelligence should not manufacture attribution.
ATT&CK mappings must reflect observed behavior.
Detection thresholds require adversarial validation.
Every detection improvement should produce regression tests.
Laboratory evidence must remain clearly separated from production claims.
The strongest SOC workflow is evidence-driven from telemetry through final assessment.
21. Case Closure Assessment

Case: CASE-007

Detection: DET-HOST-001

Alert: ALERT-CASE-007-DET-HOST-001

Disposition: Suspicious activity — unresolved

Confirmed Compromise: No

Confirmed Malware: No

Threat Actor Attribution: No

Production Incident: No

Detection Improvement Identified: Yes

Further Corroboration Required: Yes

The case demonstrates a complete investigative workflow while maintaining appropriate uncertainty around the underlying cause.

22. Laboratory Limitations

This case uses synthetic laboratory telemetry.

No production host was compromised, isolated, modified, or remediated.

No real credentials, real users, or real organizational systems are represented.

The findings demonstrate defensive SOC investigation methodology and should not be interpreted as evidence of a real-world incident.

Conclusion

CASE-007 demonstrates how a SOC analyst can move from a file-integrity alert to a structured evidence-based investigation.

The detection successfully identified clustered file-state changes.

The investigation then expanded beyond the initial alert into evidence preservation, timeline reconstruction, indicator analysis, threat intelligence, hunting, ATT&CK context, response planning, and detection improvement.

The final lesson is straightforward:

Detection creates the lead. Correlated evidence creates the conclusion.
