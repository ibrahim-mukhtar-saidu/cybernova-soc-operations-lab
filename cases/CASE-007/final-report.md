# CASE-007 — Final Report

## Executive Summary

**Case ID:** CASE-007

**Scenario:** File Integrity Violation

**Detection:** `DET-HOST-001` — File Integrity Violation Detection

**Alert ID:** `ALERT-CASE-007-DET-HOST-001`

**Host:** `lab-host-01`

**Severity:** High

**Confidence:** High

**Environment:** Controlled cybersecurity laboratory using synthetic telemetry

**Case Status:** Investigation complete — unresolved suspicious activity

## 1. Executive Assessment

The CYBERNOVA SOC Detection Engine identified two clustered file integrity violations on `lab-host-01`.

The affected files were:

- `/etc/ssh/sshd_config`
- `/etc/passwd`

The two modifications occurred two minutes apart and satisfied the configured `DET-HOST-001` threshold of at least two qualifying file changes within five minutes.

Both events were marked `authorized_change=false` in the synthetic telemetry.

The available evidence is sufficient to classify the activity as suspicious and requiring investigation.

The evidence is **not sufficient to establish confirmed compromise, malicious execution, persistence, unauthorized access, or threat-actor attribution**.

## 2. Detection Summary

The detection logic evaluates:

- `event_type=file_integrity`;
- `status=changed`;
- change types `modified`, `created`, or `deleted`;
- events grouped by host;
- a five-minute correlation window;
- minimum two qualifying violations.

The alert was generated because two qualifying events occurred on the same host within two minutes.

## 3. Alert Evidence

The generated alert is:

```text
ALERT-CASE-007-DET-HOST-001

Alert characteristics:

Field	Value
Detection	DET-HOST-001
Severity	High
Confidence	High
Host	lab-host-01
Violations	2
First Seen	2026-09-08T12:00:00Z
Last Seen	2026-09-08T12:02:00Z
Change Type	modified

Supporting events:

EVT-007001
EVT-007002
4. Timeline Findings
12:00:00Z

EVT-007001 recorded a modification to:

/etc/ssh/sshd_config

The associated user was:

root

The synthetic authorization field was:

authorized_change=false
12:02:00Z

EVT-007002 recorded a modification to:

/etc/passwd

The associated user was:

root

The synthetic authorization field was:

authorized_change=false
12:20:00Z

EVT-007003 recorded a modification to:

/opt/application/config.yml

This event was marked:

authorized_change=true

It occurred outside the detection window and did not contribute to the alert.

5. Evidence Assessment

The strongest observed evidence is:

Two security-sensitive files were modified.
Both modifications occurred on the same host.
The modifications occurred within two minutes.
Both events are directly referenced by the alert.
Both events are associated with the root user.
Both events are marked unauthorized within the synthetic scenario.
Previous and new file hashes were recorded.

The evidence demonstrates file-state changes.

It does not establish the reason for those changes.

6. File Integrity Findings
SSH Configuration

The modification to:

/etc/ssh/sshd_config

is security-relevant because SSH configuration can affect remote-access behavior.

However, the telemetry does not provide the actual before-and-after file contents.

Therefore, no specific SSH configuration alteration is claimed.

Account Database

The modification to:

/etc/passwd

is security-relevant because the file contains local account information.

However, the telemetry does not provide account-level before-and-after content.

Therefore, no specific account creation, deletion, UID change, GID change, or privilege modification is claimed.

7. Hash Findings

The telemetry records different old and new SHA-256-style values for the two modified files.

This confirms that the recorded file state changed within the synthetic scenario.

The values are laboratory data and are not claimed to represent real production files or malicious hashes.

No external malware hash match was established.

8. Hunting Findings

The investigation identified several important hunting areas:

authentication preceding the modifications;
privilege escalation;
process attribution;
additional file modifications;
account changes;
SSH configuration changes;
persistence;
network activity;
package management;
configuration management.

The current CASE-007 dataset does not contain sufficient telemetry to resolve these questions.

No additional authentication, process, privilege, persistence, network, package-management, or configuration-management evidence is claimed.

9. Threat Intelligence Assessment

No threat actor, malware family, campaign, malicious infrastructure, or external indicator match was established.

The activity is therefore not attributed to a specific adversary.

The current ATT&CK mapping in the detection contract is:

T1070 — Indicator Removal

This should be treated as contextual rather than confirmed adversary behavior because the telemetry demonstrates file modification but does not establish indicator removal.

10. Response Decision

The recommended response is:

Continue controlled investigation and validate authorization before destructive remediation.

Priority actions are:

Preserve the original evidence.
Validate administrative authorization.
Review authentication activity.
Identify the responsible process.
Review privilege activity.
Validate account changes.
Validate SSH configuration changes.
Search for additional file modifications.
Assess network context.
Escalate if corroborating evidence confirms compromise.

No production containment or eradication action is being claimed.

11. Incident Classification
Current Classification

Suspicious activity — unresolved

Rationale

The activity is suspicious because:

security-sensitive files were modified;
the modifications were closely correlated in time;
the laboratory telemetry marks both changes as unauthorized.

The activity remains unresolved because:

process attribution is unavailable;
authentication context is unavailable;
privilege context is unavailable;
file-content differences are unavailable;
account-level changes are unavailable;
network context is unavailable.
12. Impact Assessment
Confirmed Impact

The confirmed impact within the laboratory dataset is:

Two security-sensitive files changed state.

Not Established

The following impacts are not established:

account compromise;
unauthorized remote access;
privilege escalation;
persistence;
data exposure;
data theft;
service disruption;
malware execution;
lateral movement.

These must not be inferred from the current telemetry.

13. Root Cause Assessment

Root cause: Not established.

Potential explanations include:

authorized administration;
package-management activity;
configuration-management activity;
manual modification;
unexpected local activity;
malicious modification.

Additional evidence is required to distinguish these possibilities.

14. Detection Performance

DET-HOST-001 successfully identified the intended synthetic scenario.

Observed behavior:

2 qualifying file changes
        ↓
same host
        ↓
within 5 minutes
        ↓
alert generated

The detection also excluded the third file modification because it occurred outside the configured window.

This demonstrates that the current correlation logic operates as designed for the supplied scenario.

15. Detection Limitations

The current detection does not independently determine:

whether a change is malicious;
which process performed the change;
whether a user was compromised;
whether privilege escalation occurred;
whether the file contents became insecure;
whether the modification was authorized;
whether the change was part of a larger attack.

These limitations should be communicated clearly to analysts and reviewers.

16. Detection Improvement Recommendations

Future detection improvements should consider:

Process Correlation

Associate sensitive file changes with process execution telemetry.

Authentication Correlation

Correlate file modifications with recent authentication events.

Privilege Correlation

Correlate changes with privilege transitions.

Sensitive Path Risk

Apply stronger investigative priority to security-sensitive files.

Authorization Context

Support reliable change-management context.

Multi-Signal Detection

Correlate file, authentication, process, privilege, and network signals.

Every implemented improvement should receive regression tests and security validation.

17. Evidence Chain
Synthetic FIM telemetry
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
Threat-intelligence assessment
        ↓
Threat hunting
        ↓
ATT&CK context
        ↓
Response decision
        ↓
Final assessment
        ↓
Detection improvement
        ↓
Regression testing
        ↓
Security validation
        ↓
Documentation
18. Evidence References
Primary Telemetry
telemetry/host/CASE-007.jsonl
Alert Evidence
alerts/CASE-007-DET-HOST-001.json
Detection Implementation
src/detection_engine.py
Detection Contract
detections/host/DET-HOST-001-file-integrity.yml
Case Artifacts
cases/CASE-007/README.md
cases/CASE-007/investigation.md
cases/CASE-007/timeline.md
cases/CASE-007/indicators.md
cases/CASE-007/threat-intelligence.md
cases/CASE-007/hunting.md
cases/CASE-007/response.md
cases/CASE-007/final-report.md
19. Lessons for SOC Operations

This case demonstrates several operational principles:

File integrity alerts require contextual investigation.
Security-sensitive paths should receive appropriate priority.
Correlation reduces isolated-event noise.
Alert evidence must remain traceable to source telemetry.
Suspicious activity must not automatically be classified as compromise.
Threat intelligence should support investigation rather than manufacture attribution.
Response actions should be proportional to evidence.
Detection improvements should be driven by investigation findings.
Laboratory evidence must remain clearly separated from production claims.
20. Final Analyst Assessment

Final Assessment: Suspicious file integrity activity requiring corroboration.

Two security-sensitive files were modified on lab-host-01 within a two-minute period.

The detection operated according to its configured logic and produced a high-severity, high-confidence alert.

The evidence justifies continued investigation.

However, the available telemetry does not establish malicious intent or compromise.

The appropriate professional conclusion is therefore:

The laboratory telemetry demonstrates clustered file integrity violations affecting security-sensitive Linux files. The activity is suspicious and warrants corroboration through authentication, process, privilege, account, configuration-management, package-management, and network evidence. No confirmed compromise or production incident is established.

21. Case Disposition

Disposition: Suspicious — unresolved

Production Incident: No

Confirmed Compromise: No

Confirmed Malware: No

Threat Actor Attribution: No

Containment Performed: No production action claimed

Eradication Performed: No production action claimed

Recovery Performed: No production action claimed

Detection Improvement Required: Yes

Further Investigation Required: Yes

22. Laboratory Limitations

This report is based on synthetic laboratory telemetry.

No production system, real credential, real user account, or real security incident is represented.

The report demonstrates a defensive SOC investigation workflow and must not be interpreted as evidence of a real-world compromise.

Final Conclusion

CASE-007 demonstrates an end-to-end host file-integrity investigation from telemetry through detection, alert validation, timeline reconstruction, indicator analysis, threat-intelligence review, hunting, response planning, and final assessment.

The evidence supports a disciplined finding of:

Suspicious file integrity activity — unresolved, requiring corroboration.
