# CASE-001 — Lessons Learned

## 1. Purpose

This document records the lessons learned from the complete CASE-001 detection, investigation, threat-hunting, and response workflow.

The objective is to identify what worked well, what evidence gaps remained, what detection and investigation capabilities should be improved, and how the exercise can strengthen future SOC operations.

This document is based on an authorized SOC laboratory scenario using synthetic/test telemetry.

---

## 2. Case Overview

**Case ID:** CASE-001

**Detection:** `DET-AUTH-001`

**Alert:** `ALERT-CASE-001-DET-AUTH-001`

**Primary Source IP:** `198.51.100.25`

**Target Account:** `root`

**Primary Host:** `lab-auth-01`

**Primary Pivot:** `EVT-001012`

**Protocol:** SSH

**Observed Failed Attempts:** 8

**Successful Authentication:** Yes

**Current Severity:** High

**Final Determination:** Suspicious authentication activity confirmed; compromise not confirmed.

---

## 3. Executive Lessons Learned

CASE-001 demonstrated that a useful SOC workflow requires more than detecting a threshold violation.

The investigation successfully progressed through:

**Detection → Alert Validation → Triage → Evidence Preservation → Timeline Analysis → Indicator Analysis → Threat Intelligence → Threat Hunting → Response Planning → Final Reporting → Detection Improvement**

The strongest lesson is that authentication telemetry can identify suspicious access patterns, but authentication evidence alone is insufficient to determine post-authentication impact.

The successful authentication event `EVT-001012` therefore became the critical pivot for additional endpoint, identity, and network investigation.

---

## 4. What Worked Well

### 4.1 Detection Logic

`DET-AUTH-001` successfully detected the primary authentication pattern.

The five-failure threshold within five minutes was exceeded by eight observed failures.

### 4.2 Successful Authentication Correlation

The detection escalated the situation when successful authentication followed repeated failures.

This significantly improved the investigation priority compared with a detection that only counted failures.

### 4.3 Evidence Preservation

The generated alert was preserved in the case workspace.

The original alert and case copy were validated as equivalent.

### 4.4 Timeline Construction

The event sequence was reconstructed using event IDs and timestamps.

This established the relationship between repeated failures and the subsequent successful authentication.

### 4.5 Indicator Documentation

The investigation documented the primary:

* Source IP.
* Account.
* Host.
* Protocol.
* Event IDs.
* Detection ID.
* Alert ID.

### 4.6 Threat Hunting

Threat hunting used the primary source IP, account, and successful authentication event as pivots.

This confirmed the primary sequence and identified evidence gaps.

### 4.7 Evidence Integrity

The investigation consistently separated:

* Observed evidence.
* Analyst interpretation.
* Hypotheses.
* Confirmed findings.
* Recommended actions.
* Limitations.

This prevented unsupported claims of compromise or attribution.

---

## 5. Detection Lessons

### Lesson D-001 — Thresholds Need Context

A threshold-based detection is useful for identifying suspicious activity, but thresholds alone do not establish malicious intent.

A legitimate administrator can generate repeated failures.

Therefore, threshold detections should be combined with contextual signals.

### Lesson D-002 — Successful Authentication Changes Priority

A successful authentication following repeated failures is more significant than repeated failures alone.

Future detections should explicitly correlate:

**failed authentication → threshold exceeded → successful authentication**

### Lesson D-003 — Privileged Accounts Require Higher Risk Weighting

Authentication attacks against privileged accounts should receive increased investigation priority.

The `root` account represents a high-impact target because successful access could provide extensive system privileges.

### Lesson D-004 — Multi-Dimensional Correlation Improves Detection

Authentication detection should eventually correlate:

* Identity.
* Endpoint.
* Network.
* Process.
* File integrity.
* Account changes.

This provides greater investigative context.

---

## 6. Telemetry Lessons

The largest limitation identified during CASE-001 was the absence of endpoint and network telemetry.

Authentication logs established that successful authentication occurred.

They did not establish what happened afterward.

### Required Additional Telemetry

Future versions of the laboratory should include:

* Process creation.
* Command execution.
* Shell activity.
* Network connections.
* DNS activity.
* File modifications.
* Privilege changes.
* Account changes.
* SSH key changes.
* Persistence mechanisms.

This would allow the investigation to continue beyond the authentication boundary.

---

## 7. Investigation Lessons

### Lesson I-001 — Start With a Strong Pivot

The most valuable pivot was:

`198.51.100.25 → root → EVT-001012`

This pivot connects:

* Source.
* Account.
* Authentication sequence.
* Successful access.

### Lesson I-002 — Preserve the Original Alert

The original detection output should be preserved before investigation changes or transformations occur.

This supports reproducibility and auditability.

### Lesson I-003 — Negative Evidence Must Be Qualified

A lack of endpoint telemetry does not prove that no endpoint activity occurred.

It means the activity cannot be determined from the available evidence.

### Lesson I-004 — Evidence Gaps Should Become Investigation Tasks

Missing telemetry should not simply be listed as a limitation.

It should generate concrete follow-up tasks.

For CASE-001, the primary follow-up is to obtain endpoint and network telemetry around `EVT-001012`.

---

## 8. Threat Hunting Lessons

Threat hunting added value beyond the original alert.

The hunt confirmed:

* The primary source IP activity.
* The targeted privileged account.
* The repeated failure sequence.
* The successful authentication.
* The absence of additional correlated account targeting in the available dataset.

The hunt also identified the inability to perform post-authentication hunting because endpoint and network telemetry were unavailable.

### Key Lesson

A detection should produce useful hunting pivots rather than ending the investigation.

---

## 9. Threat Intelligence Lessons

The source address `198.51.100.25` is a documentation/test address used for the laboratory scenario.

Therefore, external attribution was intentionally avoided.

### Key Lesson

Threat intelligence should provide context without forcing an attribution conclusion.

Behavioral evidence is more important than assigning an actor when the available evidence does not support attribution.

---

## 10. Response Lessons

The case demonstrated the importance of distinguishing between:

**Recommended response**

and

**Response actually performed**

Recommended containment included source restriction, account protection, evidence preservation, and expanded investigation.

No production containment, credential rotation, host isolation, eradication, or recovery was claimed.

### Key Lesson

A professional SOC record must accurately represent what analysts actually did.

A laboratory exercise should never be presented as production incident response.

---

## 11. False-Positive Lessons

Potential benign explanations include:

* Authorized security testing.
* Administrative mistakes.
* Misconfigured automation.
* Outdated credentials.
* Approved laboratory activity.

The detection therefore requires analyst validation rather than automatic assumption of compromise.

### Improvement

Future detection versions should incorporate additional contextual signals such as:

* Account privilege.
* Source reputation where applicable.
* Known administrative systems.
* Authentication method.
* Host criticality.
* Time-of-day patterns.
* Historical behavior.

---

## 12. Detection Engineering Improvements

The following improvements are recommended.

### Improvement DE-001

Add explicit correlation for successful authentication following repeated failures.

### Improvement DE-002

Increase severity when the targeted account is privileged.

### Improvement DE-003

Detect a single source targeting multiple usernames.

### Improvement DE-004

Detect a single source targeting multiple hosts.

### Improvement DE-005

Correlate authentication events with endpoint process activity.

### Improvement DE-006

Correlate authentication events with network connections.

### Improvement DE-007

Add regression tests for:

* Threshold reached.
* Threshold not reached.
* Successful authentication after failures.
* Successful authentication without preceding failures.
* Multiple accounts.
* Multiple source IPs.
* Duplicate events.
* Invalid telemetry.

---

## 13. Testing Lessons

CASE-001 demonstrated the importance of validating both positive and negative detection scenarios.

### Positive Test

Expected:

Eight failures from the same source/account should trigger the detection.

Observed:

Detection triggered successfully.

### Negative Test

Expected:

A source/account combination with fewer than five failures within five minutes should not trigger the threshold.

### Future Tests

Additional tests should verify:

* Boundary conditions.
* Exactly five failures.
* Four failures.
* Failures outside the time window.
* Multiple accounts.
* Multiple hosts.
* Successful authentication after threshold.
* Duplicate events.
* Malformed telemetry.

---

## 14. Automation Lessons

The detection engine successfully transformed raw authentication telemetry into a structured alert.

This demonstrates the value of automation for:

* Event validation.
* Threshold evaluation.
* Correlation.
* Alert generation.
* Evidence preservation.
* Repeatable analysis.

### Improvement

Future automation should also support:

* Case creation.
* Timeline generation.
* Indicator extraction.
* Detection regression testing.
* Metrics collection.
* Report generation.

Automation should support analyst decision-making rather than replace evidence-based judgment.

---

## 15. Documentation Lessons

CASE-001 demonstrated the value of separating investigation functions into dedicated records.

The case contains separate artifacts for:

* Case overview.
* Alert preservation.
* Timeline.
* Indicators.
* Investigation.
* Threat intelligence.
* Threat hunting.
* Response.
* Final reporting.
* Lessons learned.

This structure makes the investigation easier to audit, review, reproduce, and explain during technical interviews.

---

## 16. Evidence Integrity Lessons

The investigation maintained a clear evidence model.

### Observed Evidence

Eight failed SSH authentication attempts followed by successful authentication.

### Interpretation

The sequence is suspicious.

### Hypothesis

The successful authentication may represent unauthorized access.

### Confirmed Findings

The authentication events occurred in the supplied telemetry.

### Unconfirmed Findings

Compromise, malware execution, persistence, lateral movement, and data exfiltration remain unconfirmed.

### Key Lesson

Analysts should never upgrade a hypothesis into a confirmed finding without supporting evidence.

---

## 17. SOC Process Improvements

Future cases should improve the workflow in the following areas:

1. Standardize alert intake.
2. Automate evidence validation.
3. Generate timelines automatically where possible.
4. Expand telemetry coverage.
5. Standardize hunt hypotheses.
6. Track response actions separately from recommendations.
7. Measure detection performance.
8. Add repeatable regression tests.
9. Track case closure reasons.
10. Record detection improvement actions.

---

## 18. Metrics Opportunities

CASE-001 also identifies useful SOC metrics that can be measured in future cases.

Potential metrics include:

* Mean Time to Detect.
* Mean Time to Triage.
* Mean Time to Investigate.
* Mean Time to Contain.
* Detection precision.
* False-positive rate.
* Alert volume.
* Escalation rate.
* Detection coverage.
* Investigation completion rate.
* Evidence completeness.
* Case closure time.

These metrics should be implemented consistently across future cases.

---

## 19. Portfolio Evidence Lessons

CASE-001 provides strong evidence of practical SOC workflow capability.

The case demonstrates experience with:

* Detection engineering.
* Authentication telemetry.
* Alert validation.
* Security triage.
* Timeline analysis.
* IOC documentation.
* Threat intelligence assessment.
* Threat hunting.
* MITRE ATT&CK mapping.
* Response planning.
* Evidence integrity.
* Detection improvement.
* Automated validation.
* Git-based case management.

The appropriate professional positioning is:

**Hands-on SOC Laboratory Experience**

and

**Detection Engineering and Security Investigation Projects**

The exercise should not be described as production SOC employment.

---

## 20. Interview Lessons

CASE-001 can support technical interview discussions around:

### Detection

How was repeated SSH brute-force activity detected?

### Triage

Why was the alert escalated to high severity?

### Investigation

Why was `EVT-001012` the most important pivot?

### Threat Hunting

How did the investigation determine whether the source targeted other accounts?

### Evidence

Why was account compromise not confirmed?

### Response

What containment actions would be appropriate if unauthorized access were confirmed?

### Detection Engineering

How would the detection be improved?

### Limitations

What additional telemetry would be required?

A strong interview answer should consistently distinguish observed evidence from assumptions.

---

## 21. What Should Be Improved in the Next Case

The next investigation should improve upon CASE-001 by introducing additional telemetry.

Priority improvements:

1. Add endpoint telemetry.
2. Add process execution events.
3. Add network connection events.
4. Add DNS telemetry.
5. Add file-integrity events.
6. Add account-management events.
7. Add persistence-related telemetry.
8. Correlate multiple telemetry sources.
9. Build cross-host investigation capability.
10. Measure detection performance.

This will enable investigations to progress from authentication detection toward complete attack-chain analysis.

---

## 22. Lessons Applied to Future Cases

The following standards should become reusable across the SOC laboratory:

### Standard S-001

Every alert should have a preserved copy.

### Standard S-002

Every case should have a timeline.

### Standard S-003

Every investigation should distinguish evidence from interpretation.

### Standard S-004

Every hunt should begin with documented hypotheses.

### Standard S-005

Every response action should identify whether it was performed or recommended.

### Standard S-006

Every case should document limitations.

### Standard S-007

Every confirmed finding should reference supporting evidence.

### Standard S-008

Every detection should have positive and negative tests.

### Standard S-009

Every completed case should produce detection-improvement recommendations.

### Standard S-010

Every case should be reproducible from its documented evidence sources.

---

## 23. Final Lessons Learned

CASE-001 successfully demonstrated an end-to-end SOC investigation process.

The most important lessons are:

1. Detection is only the beginning of the investigation.
2. Successful authentication after repeated failures significantly increases investigation priority.
3. Privileged-account targeting requires additional scrutiny.
4. Strong investigation pivots connect source, account, host, and event.
5. Threat hunting should extend beyond the original alert.
6. Missing telemetry must be treated as an evidence gap.
7. Response recommendations must be separated from actions actually performed.
8. Threat intelligence should not exceed the available evidence.
9. Detection rules require positive and negative validation.
10. Every investigation should produce actionable detection improvements.

---

## 24. Final Improvement Priorities

| Priority | Improvement                                        | Reason                                             |
| -------- | -------------------------------------------------- | -------------------------------------------------- |
| P1       | Add endpoint telemetry                             | Investigate post-authentication activity           |
| P1       | Add network telemetry                              | Investigate lateral movement and outbound activity |
| P1       | Correlate successful authentication after failures | Improve alert fidelity                             |
| P2       | Add privileged-account risk weighting              | Prioritize high-impact accounts                    |
| P2       | Add cross-host hunting                             | Identify broader attack scope                      |
| P2       | Expand regression tests                            | Improve detection reliability                      |
| P3       | Add SOC metrics                                    | Measure operational performance                    |
| P3       | Automate case generation                           | Reduce repetitive analyst work                     |
| P3       | Add additional telemetry categories                | Expand attack-chain visibility                     |

---

## 25. Final Case Lesson

The central lesson from CASE-001 is:

**A detection can identify suspicious behavior, but only evidence-driven investigation can determine its significance.**

The eight failed SSH authentication attempts and subsequent successful authentication established a strong reason to investigate.

They did not, by themselves, establish compromise.

The investigation therefore remained evidence-driven, documented its limitations, avoided unsupported attribution, and identified the exact telemetry required for the next investigative stage.

**Final lesson: Detect broadly, investigate systematically, preserve evidence, state uncertainty honestly, and continuously improve detection coverage.**
