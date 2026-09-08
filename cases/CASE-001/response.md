# CASE-001 — Incident Response Record

## 1. Purpose

This document records the incident-response assessment and recommended response actions for CASE-001.

The response plan is based on the observed authentication activity associated with `198.51.100.25`, the `root` account, and successful authentication event `EVT-001012`.

The case exists within an authorized SOC laboratory.

No production response activity is claimed.

Response actions described as recommendations are not represented as actions that were actually executed unless explicitly documented as performed.

---

## 2. Response Overview

**Case ID:** CASE-001

**Alert ID:** `ALERT-CASE-001-DET-AUTH-001`

**Detection:** `DET-AUTH-001`

**Incident Type:** Authentication Attack

**Attack Category:** SSH Brute Force / Password Guessing

**Primary Host:** `lab-auth-01`

**Target Account:** `root`

**Source IP:** `198.51.100.25`

**Protocol:** SSH

**Observed Failed Attempts:** 8

**Successful Authentication Observed:** Yes

**Successful Authentication Event:** `EVT-001012`

**Current Severity:** High

**Current Case Status:** Open

**Compromise Status:** Not confirmed

**Environment:** Authorized SOC Laboratory

---

## 3. Response Objectives

The response process has the following objectives:

1. Preserve relevant evidence.
2. Validate the suspicious authentication sequence.
3. Prevent additional unauthorized access if compromise is confirmed.
4. Protect the affected account and host.
5. Determine whether post-authentication activity occurred.
6. Identify potential persistence or lateral movement.
7. Remove confirmed malicious changes.
8. Restore the affected system to a trusted state.
9. Validate recovery.
10. Document all actions and findings.
11. Improve detection coverage based on lessons learned.

---

## 4. Response Classification

The current response classification is:

**Suspicious authentication activity requiring investigation and controlled containment planning.**

The observed successful authentication does not independently establish account compromise.

The response therefore follows an evidence-driven approach.

Containment actions should be authorized according to the laboratory rules before execution.

---

## 5. Evidence Preservation

Before making changes to the affected environment, preserve relevant evidence.

### Required Evidence

Preserve:

* Original authentication telemetry.
* Detection configuration.
* Generated alert.
* Case alert copy.
* Relevant event IDs.
* Authentication timestamps.
* Source IP information.
* Username information.
* Host information.
* Endpoint telemetry if available.
* Network telemetry if available.
* Relevant system logs.
* File-integrity information if available.
* Account and privilege information.
* Analyst notes.

### Primary Evidence

The primary evidence currently available is:

`telemetry/authentication/CASE-001-authentication-events.jsonl`

### Primary Event Sequence

`EVT-001004` through `EVT-001011` represent the repeated failed authentication sequence.

`EVT-001012` represents the subsequent successful authentication.

Evidence should be preserved before destructive response actions whenever practical.

---

## 6. Evidence Integrity Requirements

Response activities must maintain evidence integrity.

Analysts should:

* Preserve original telemetry.
* Avoid modifying original evidence files.
* Work from copies when analysis requires transformation.
* Record timestamps for response actions.
* Record commands or tools used during investigation.
* Record analyst decisions.
* Record evidence sources.
* Distinguish observed evidence from analyst interpretation.
* Document missing evidence.
* Record any evidence collection failures.

No evidence should be altered to support a predetermined conclusion.

---

## 7. Initial Containment Assessment

### Containment Trigger

Containment should be considered because:

* Eight failed SSH authentication attempts were observed.
* The configured detection threshold was exceeded.
* The activity targeted the privileged `root` account.
* Successful authentication subsequently occurred.
* The successful authentication originated from the same source IP.

### Current Decision

**Containment recommended pending authorized validation of the laboratory scenario.**

The available evidence is sufficient to justify elevated investigation priority.

The evidence is not sufficient to claim confirmed compromise.

---

## 8. Recommended Immediate Containment

If this were an authorized live response environment, recommended containment actions would include:

1. Restrict or block the suspicious source IP where operationally appropriate.
2. Review active sessions associated with the affected account.
3. Temporarily restrict the affected privileged account if compromise is suspected.
4. Preserve relevant authentication and endpoint evidence.
5. Review SSH configuration and authentication controls.
6. Determine whether additional hosts received connections from the same source.
7. Monitor for repeated authentication attempts.
8. Escalate the case if compromise indicators are identified.

### Laboratory Boundary

These actions are recommendations only.

No real-world blocking, account disablement, host isolation, or credential reset is claimed to have been performed.

---

## 9. Account Protection

The `root` account requires elevated attention because it is a privileged account.

If compromise is confirmed, recommended actions include:

* Disable or restrict the affected account where operationally safe.
* Rotate credentials.
* Review authorized SSH keys.
* Review privilege assignments.
* Review recent authentication history.
* Review account modifications.
* Identify unauthorized account changes.
* Require stronger authentication controls.
* Prefer controlled administrative accounts over direct root SSH access.

### Current Status

No account compromise has been confirmed from the available evidence.

Therefore, credential rotation is recorded as a recommended containment action rather than a completed action.

---

## 10. SSH Security Review

The affected host should be reviewed for:

* Direct root SSH access.
* Password authentication.
* Public-key authentication.
* Failed authentication thresholds.
* SSH configuration changes.
* Unauthorized authorized-key entries.
* Unexpected SSH services.
* Unusual listening ports.
* Authentication-related configuration changes.
* Account lockout controls.

Where operationally appropriate, direct root SSH access should be restricted and administrative access should use controlled privileged accounts.

---

## 11. Endpoint Investigation Before Eradication

Before removing potentially malicious artifacts, investigators should collect endpoint evidence.

Recommended evidence includes:

* Process listings.
* Active network connections.
* Running services.
* Scheduled tasks or jobs.
* Recent file modifications.
* Shell history where appropriate.
* SSH configuration.
* Authorized SSH keys.
* Account information.
* Privilege configuration.
* Persistence mechanisms.
* Security logs.
* System logs.

### Required Correlation

Endpoint activity should be correlated against the timestamp of:

`EVT-001012`

This is the primary post-authentication pivot.

---

## 12. Network Investigation

If network telemetry is available, investigate:

* Connections from `lab-auth-01` after `EVT-001012`.
* Connections to other internal systems.
* Outbound connections.
* DNS requests.
* Unusual destination ports.
* Repeated connections.
* Authentication attempts against other systems.
* Evidence of lateral movement.

The source IP `198.51.100.25` should also be searched across available network telemetry.

### Current Limitation

No network telemetry is currently available in the CASE-001 dataset.

Therefore, network-based post-authentication activity remains undetermined.

---

## 13. Lateral Movement Assessment

The successful SSH authentication creates a requirement to assess possible lateral movement.

Recommended investigation:

1. Identify systems accessible from `lab-auth-01`.
2. Search authentication logs for subsequent outbound authentication.
3. Search for the same account being used elsewhere.
4. Search for new SSH sessions.
5. Review network connections after `EVT-001012`.
6. Correlate endpoint and authentication events across hosts.

### Current Finding

No lateral movement has been confirmed.

The available telemetry is insufficient to perform a complete lateral-movement assessment.

---

## 14. Persistence Assessment

If successful access is determined to be unauthorized, investigate potential persistence mechanisms.

Review:

* SSH authorized keys.
* Cron jobs.
* Systemd services.
* Startup scripts.
* Shell initialization files.
* New user accounts.
* Privilege escalation configuration.
* Scheduled tasks.
* Unexpected binaries or scripts.

### Current Finding

No persistence mechanism has been observed in the available CASE-001 evidence.

This is not equivalent to proving that persistence is absent.

---

## 15. Eradication Plan

Eradication should occur only after evidence collection and confirmation of malicious changes.

Potential eradication actions include:

* Remove unauthorized SSH keys.
* Remove unauthorized accounts.
* Remove malicious processes.
* Remove malicious persistence.
* Remove unauthorized scripts or binaries.
* Revert unauthorized configuration changes.
* Rotate compromised credentials.
* Correct insecure SSH configuration.
* Patch identified vulnerabilities.

### Current Status

No malicious artifact has been confirmed.

Therefore, no eradication action is recorded as completed.

---

## 16. Recovery Plan

If compromise is confirmed, recovery should include:

1. Restore the host to a trusted state.
2. Apply required security updates.
3. Restore known-good configuration.
4. Reset affected credentials.
5. Re-enable required services.
6. Validate authentication controls.
7. Monitor the host for recurring suspicious activity.
8. Verify that unauthorized persistence is absent.
9. Confirm normal system operation.

Recovery should be validated before returning the system to normal operational status.

---

## 17. Recovery Validation

Recovery validation should include:

* Authentication testing.
* Privilege validation.
* SSH configuration validation.
* Service validation.
* Process validation.
* Network connection review.
* File-integrity verification.
* Log monitoring.
* Detection-rule testing.
* Repeat attack simulation using authorized laboratory telemetry.

### Expected Outcome

The host should demonstrate:

* No unauthorized accounts.
* No unauthorized SSH keys.
* No unexpected persistence.
* No suspicious active sessions.
* Correct SSH security controls.
* Expected system functionality.
* Continued detection of repeated authentication attacks.

---

## 18. Monitoring After Recovery

Post-recovery monitoring should focus on:

* Repeated authentication failures.
* Successful authentication after failures.
* Privileged-account authentication.
* New SSH keys.
* New accounts.
* Unexpected processes.
* Unexpected network connections.
* Lateral authentication.
* Persistence indicators.

The detection `DET-AUTH-001` should remain active and should be validated after any detection or configuration changes.

---

## 19. Escalation Criteria

Escalate CASE-001 if any of the following are identified:

* Confirmed unauthorized successful authentication.
* Evidence of credential compromise.
* Suspicious commands executed after `EVT-001012`.
* Unauthorized account modification.
* Unauthorized SSH keys.
* Suspicious persistence.
* Malware execution.
* Privilege escalation.
* Lateral movement.
* Data access or exfiltration indicators.
* Repeated activity from the same source against multiple hosts.
* Evidence that additional systems are affected.

---

## 20. Severity Reassessment

### Current Severity

**High**

### Reason

The detection identified repeated authentication failures against a privileged account followed by successful authentication from the same source.

### Conditions for Critical Escalation

Severity may be increased to critical if evidence establishes:

* Confirmed privileged-account compromise.
* Active attacker control.
* Lateral movement.
* Malware deployment.
* Significant persistence.
* Data exfiltration.
* Multiple compromised systems.

### Conditions for Severity Reduction

Severity may be reduced if investigation establishes that:

* The authentication was authorized.
* The source was an approved administrative system.
* The repeated failures were caused by a known configuration problem.
* No unauthorized activity occurred.
* Supporting evidence confirms a benign explanation.

---

## 21. False-Positive Response

Potential benign explanations should be evaluated before destructive containment.

Possible causes include:

* Authorized penetration testing.
* Security validation activity.
* Misconfigured automation.
* Administrative credential errors.
* Scheduled jobs using outdated credentials.
* Internal security testing.
* Approved laboratory simulation.

The source IP `198.51.100.25` is within a documentation/test address range used for this laboratory scenario.

This characteristic prevents the address from being treated as real-world malicious infrastructure.

The behavior itself remains useful for detection and response training.

---

## 22. Analyst Response Actions

### Actions Completed

The following analytical response actions have been completed:

* Detection validated.
* Alert generated.
* Alert preserved in the case workspace.
* Authentication sequence reviewed.
* Timeline established.
* Indicators documented.
* Threat-intelligence assessment completed.
* Threat-hunting assessment completed.

### Actions Not Performed

The following actions have not been represented as executed:

* Real network blocking.
* Account disablement.
* Credential rotation.
* Host isolation.
* Malware removal.
* System rebuild.
* Production remediation.

These distinctions maintain evidence integrity and prevent the laboratory exercise from being misrepresented as production incident response.

---

## 23. Recommended Response Workflow

The recommended response sequence is:

**Detect**

→ Validate alert

→ Preserve evidence

→ Triage affected account and host

→ Investigate successful authentication

→ Correlate endpoint and network telemetry

→ Determine whether compromise occurred

→ Contain if justified

→ Eradicate confirmed malicious artifacts

→ Recover trusted state

→ Validate recovery

→ Monitor

→ Close or escalate

→ Improve detection

---

## 24. Response Decision Matrix

| Condition                                     | Recommended Response                         |
| --------------------------------------------- | -------------------------------------------- |
| Repeated failures only                        | Monitor and investigate                      |
| Repeated failures + successful authentication | Escalate investigation                       |
| Confirmed unauthorized access                 | Contain account/source                       |
| Confirmed credential compromise               | Rotate credentials                           |
| Malicious process confirmed                   | Isolate and eradicate                        |
| Persistence confirmed                         | Preserve evidence and eradicate              |
| Lateral movement confirmed                    | Expand incident scope                        |
| No malicious activity confirmed               | Document and close with evidence             |
| Evidence insufficient                         | Maintain investigation and collect telemetry |

---

## 25. Evidence and Action Separation

The following distinction applies throughout the response:

### Observed Evidence

Eight failed SSH authentication attempts from `198.51.100.25` against `root`, followed by successful authentication event `EVT-001012`.

### Analyst Interpretation

The sequence is suspicious and warrants investigation.

### Hypothesis

The successful authentication may represent unauthorized access.

### Confirmed Finding

Repeated authentication activity and successful authentication are confirmed in the telemetry.

### Not Confirmed

Account compromise, malicious execution, persistence, lateral movement, and data impact are not confirmed.

### Recommended Actions

Containment, account protection, endpoint investigation, network investigation, eradication, and recovery are recommended based on future evidence.

---

## 26. Response Limitations

The response assessment is limited by:

* Authentication-only telemetry.
* Absence of endpoint telemetry.
* Absence of network telemetry.
* Absence of process execution records.
* Absence of command history evidence.
* Absence of file-integrity telemetry.
* Absence of identity-management telemetry.
* Absence of production environment context.

These limitations prevent a complete compromise determination.

---

## 27. MITRE ATT&CK Response Context

The primary observed behavior maps to:

**T1110 — Brute Force**

**T1110.001 — Password Guessing**

Additional techniques should only be assigned when supporting evidence exists.

Potential future investigative areas include:

* Valid Accounts
* Remote Services
* Command and Scripting Interpreter
* Persistence techniques
* Lateral Movement

These are investigative possibilities and are not confirmed CASE-001 findings.

---

## 28. Detection Improvement After Response

Response findings should feed back into detection engineering.

Recommended improvements include:

1. Maintain detection for repeated SSH failures.
2. Increase priority when successful authentication follows the threshold.
3. Detect privileged-account targeting.
4. Correlate authentication with endpoint telemetry.
5. Correlate authentication with network telemetry.
6. Detect source IP targeting multiple accounts.
7. Detect source IP targeting multiple hosts.
8. Add regression tests for successful-after-failure scenarios.
9. Measure detection false positives.
10. Document tuning decisions.

---

## 29. Response Validation Requirements

Before closing the response process, verify:

* Evidence is preserved.
* Detection output is reproducible.
* Case artifacts are internally consistent.
* Indicators match the source telemetry.
* Timeline matches event timestamps.
* Response actions are accurately classified.
* No unsupported compromise claim exists.
* Limitations are documented.
* Detection improvements are recorded.
* Required follow-up investigations are assigned.

---

## 30. Case Closure Criteria

CASE-001 should not be closed as a confirmed compromise without additional evidence.

The case may be closed as suspicious activity if investigation establishes a documented benign explanation.

The case should remain open or be escalated if:

* Unauthorized access remains plausible.
* Additional evidence is pending.
* Endpoint/network correlation is unavailable.
* New indicators are discovered.
* Additional hosts become involved.

---

## 31. Current Response Determination

### Determination

**Suspicious authentication activity requiring continued investigation and controlled response planning.**

The available evidence confirms:

* Repeated SSH authentication failures.
* Eight failed attempts from `198.51.100.25`.
* Targeting of the privileged `root` account.
* Successful authentication represented by `EVT-001012`.

The available evidence does not confirm:

* Account compromise.
* Malicious command execution.
* Malware execution.
* Persistence.
* Lateral movement.
* Data exfiltration.
* Attacker attribution.

---

## 32. Analyst Handoff

The next analyst should begin with:

**Primary pivot:**

`198.51.100.25 → root → EVT-001012`

### Priority Tasks

1. Obtain endpoint telemetry for `lab-auth-01`.
2. Search for process activity after `EVT-001012`.
3. Search for network activity after `EVT-001012`.
4. Review SSH configuration and authorized keys.
5. Review account and privilege changes.
6. Search for lateral authentication.
7. Determine whether the successful authentication was authorized.
8. Update the case determination based on new evidence.

---

## 33. Response Evidence References

### Telemetry

`telemetry/authentication/CASE-001-authentication-events.jsonl`

### Detection

`detections/authentication/DET-AUTH-001-ssh-brute-force.yml`

### Alert

`alerts/CASE-001-DET-AUTH-001.json`

`cases/CASE-001/alert.json`

### Case Records

`cases/CASE-001/README.md`

`cases/CASE-001/timeline.md`

`cases/CASE-001/indicators.md`

`cases/CASE-001/investigation.md`

`cases/CASE-001/threat-intelligence.md`

`cases/CASE-001/hunting.md`

### Governance

`docs/evidence-integrity.md`

`docs/limitations.md`

`docs/threat-model.md`

---

## 34. Final Response Statement

CASE-001 generated a high-priority authentication investigation because eight failed SSH authentication attempts against the privileged `root` account were followed by successful authentication from the same source IP.

The evidence supports containment planning and expanded investigation.

However, no production response action is claimed, and account compromise is not confirmed from the available authentication telemetry.

The next response priority is to correlate `EVT-001012` with endpoint, identity, and network telemetry.

**Final response status: Investigation active — containment planning recommended — compromise not confirmed.**
