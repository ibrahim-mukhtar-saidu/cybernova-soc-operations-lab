# PB-010 — Multi-Stage Attack

## 1. Purpose

PB-010 defines the analyst workflow for investigating a multi-stage attack sequence identified through correlation of multiple high-confidence SOC detections.

The playbook is designed around `DET-CORR-001 — Multi-Stage Attack Correlation` and the CYBERNOVA SOC laboratory CASE-010 investigation.

The objective is to determine whether independently detected activities form a coherent chronological attack sequence, preserve the supporting evidence, assess confidence and severity, identify investigative gaps, and provide a defensible response path.

The correlation result is an investigation-prioritization mechanism. It does not independently establish malicious intent, successful compromise, attacker attribution, or production impact.

---

## 2. Scope

This playbook covers:

* multi-stage detection correlation;
* credential attack correlation;
* post-authentication activity correlation;
* persistence correlation;
* temporal analysis;
* host and user attribution;
* source-IP consistency;
* supporting alert preservation;
* supporting event preservation;
* ATT&CK mapping;
* evidence classification;
* threat-intelligence boundaries;
* false-positive analysis;
* false-negative analysis;
* adversarial evasion;
* containment;
* eradication;
* recovery;
* detection feedback;
* cross-project investigation;
* escalation;
* closure;
* laboratory evidence packaging.

This playbook applies to authorized defensive investigations only.

---

## 3. Laboratory Boundary

CYBERNOVA SOC Operations Lab is a controlled defensive laboratory.

Telemetry, hosts, users, IP addresses, hashes, alerts, and investigation outcomes described in this playbook are laboratory evidence unless explicitly identified otherwise.

No section of this playbook should be interpreted as evidence of a real-world production compromise.

No real credentials, private information, unauthorized systems, or uncontrolled infrastructure should be used to reproduce these scenarios.

---

## 4. Primary Correlation

Primary correlation:

`DET-CORR-001`

Name:

`Multi-Stage Attack Correlation`

Version:

`1.0`

Implementation:

`src/case_correlation.py`

Primary laboratory case:

`CASE-010`

Primary output:

`ALERT-CASE-010-DET-CORR-001`

---

## 5. Correlation Objective

The correlation layer combines three existing detection stages:

1. credential-access activity;
2. post-authentication privileged activity;
3. Linux persistence activity.

The purpose is to determine whether the stages occur:

* on the same host;
* for the same user;
* in chronological order;
* within the configured correlation window;
* without conflicting source-IP evidence.

The correlation layer therefore operates above individual telemetry detectors.

It does not replace the underlying detections.

---

## 6. Required Detection Stages

The current implementation requires all three detection IDs:

| Detection       | Stage                          | Role                                               |
| --------------- | ------------------------------ | -------------------------------------------------- |
| `DET-AUTH-001`  | `credential_access`            | Credential attack                                  |
| `DET-AUTH-003`  | `post_authentication_activity` | Suspicious post-authentication privileged activity |
| `DET-LINUX-001` | `persistence`                  | Suspicious Linux cron persistence                  |

A correlation is not generated unless all required stages are represented.

---

## 7. Stage One — Credential Access

`DET-AUTH-001` represents the credential-access stage.

The current laboratory scenario uses SSH brute-force authentication activity followed by successful authentication.

The analyst should validate:

* failed authentication sequence;
* successful authentication;
* source IP;
* target host;
* target user;
* timestamps;
* supporting event IDs;
* alert identity;
* confidence;
* status.

The underlying authentication detection remains the authoritative source for the credential-access finding.

---

## 8. Stage Two — Post-Authentication Activity

`DET-AUTH-003` represents suspicious activity after authentication.

The analyst should validate:

* successful authentication;
* session creation;
* user identity;
* host identity;
* privileged activity;
* enumeration commands;
* privilege-related commands;
* command timestamps;
* source IP when available;
* supporting events.

The presence of this stage does not independently prove that the authenticated user was compromised.

---

## 9. Stage Three — Persistence

`DET-LINUX-001` represents suspicious Linux persistence.

The current detector focuses on suspicious cron persistence indicators, including download-and-execute behavior.

The analyst should validate:

* cron path;
* cron command;
* persistence mechanism;
* process context;
* user;
* host;
* timestamps;
* supporting events;
* source IP when available;
* file evidence;
* command-line evidence.

The persistence alert itself does not independently prove that persistence was successfully established or maliciously controlled.

---

## 10. Correlation Window

The configured correlation window is:

**30 minutes**

The earliest selected stage and latest selected stage must occur within 30 minutes.

If:

`latest_timestamp - earliest_timestamp > 30 minutes`

the candidate correlation is rejected.

The window is measured using timezone-aware timestamps.

---

## 11. Host Correlation

All required stages must belong to the same host.

The current implementation groups candidate alerts by:

`host + user`

If the host differs between required stages, the stages cannot form the same correlation.

Host attribution should therefore be validated before accepting the correlated sequence.

---

## 12. User Correlation

All required stages must belong to the same user.

The current implementation requires a non-empty user field.

A multi-stage sequence involving different users is not automatically treated as one correlation.

Analysts may investigate cross-user relationships separately when authorized evidence supports such investigation.

---

## 13. Alert Status Requirement

Each candidate stage must have:

`status = open`

Closed or otherwise non-open alerts are excluded from correlation.

This prevents historical or already-resolved alerts from automatically participating in the active correlation workflow.

---

## 14. Confidence Requirement

Each candidate stage must have:

`confidence = high`

Lower-confidence alerts are excluded by the current implementation.

This is an engineering control designed to reduce weak signals producing high-level multi-stage correlations.

It does not mean that a high-confidence correlation proves compromise.

---

## 15. Timestamp Selection

The correlation implementation uses deterministic timestamp selection:

1. `timestamp`
2. `last_seen`
3. `first_seen`

If none of these fields contains a valid non-empty string, correlation fails with a validation error.

Analysts should preserve the original alert timestamps and should not silently substitute undocumented times.

---

## 16. Timestamp Validation

Timestamps must contain timezone information.

Timezone-naive timestamps are rejected.

ISO-8601 timestamps should be preserved in the evidence package.

Examples include:

`2026-09-09T10:02:03Z`

and:

`2026-09-09T10:03:21+00:00`

Timestamp normalization must not alter the underlying observed evidence.

---

## 17. Chronological Ordering

The selected stages must occur in the expected order:

`DET-AUTH-001`

then:

`DET-AUTH-003`

then:

`DET-LINUX-001`

If the timestamps are not chronologically ordered, the candidate sequence is rejected.

This prevents a persistence alert occurring before the credential-access stage from being incorrectly interpreted as the same ordered attack chain.

---

## 18. Source-IP Consistency

The correlation engine collects available source IP values from the selected alerts.

If more than one distinct source IP is present, the candidate sequence is rejected.

A missing source IP does not automatically reject the correlation.

This is important because not every detection currently exposes source-IP telemetry.

Source-IP consistency is therefore a supporting correlation control rather than universal proof of attacker identity.

---

## 19. Supporting Alerts

Every correlated stage must retain its original alert ID.

The correlation output preserves:

* supporting alert IDs;
* detection IDs;
* stage names;
* stage timestamps.

Analysts must not replace the original alerts with the correlation alert.

The correlation alert is an additional analytical layer.

---

## 20. Supporting Events

Supporting event IDs from all three stage alerts are combined into a deterministic sorted set.

These IDs form the evidence trail connecting the correlation back to the underlying telemetry.

Every investigation should preserve the original event records where available.

---

## 21. Correlation Output

The current implementation generates:

`ALERT-CASE-010-DET-CORR-001`

with:

* detection ID: `DET-CORR-001`;
* detection name: `Multi-Stage Attack Correlation`;
* version: `1.0`;
* status: `open`;
* severity: `critical`;
* confidence: `high`;
* host;
* user;
* source IP when available;
* stage count;
* stages;
* supporting alert IDs;
* supporting event IDs;
* ATT&CK mapping;
* analyst interpretation.

---

## 22. Severity

The current correlation output assigns:

**Critical**

This severity reflects the combination of credential-access activity, post-authentication privileged activity, and persistence indicators.

It should not be interpreted as proof that the system was compromised.

Severity should be reconsidered if the underlying evidence is invalidated during investigation.

---

## 23. Confidence

The current correlation output assigns:

**High**

This reflects successful technical correlation of the required high-confidence stages.

It does not mean:

* compromise is confirmed;
* malware is confirmed;
* persistence success is confirmed;
* attacker attribution is confirmed;
* production impact is confirmed.

---

## 24. Evidence Classification

Analysts should separate:

### Observed evidence

Directly represented by telemetry or generated alerts.

Examples:

* three required detection stages;
* same host;
* same user;
* chronological timestamps;
* supporting alert IDs;
* supporting event IDs;
* source-IP consistency where available.

### Analyst interpretation

Reasoned conclusions derived from observed evidence.

Examples:

* the sequence is consistent with a multi-stage attack pattern;
* the credential-access stage precedes post-authentication activity;
* persistence activity follows the earlier stages.

### Unconfirmed claims

Do not automatically claim:

* successful compromise;
* malicious intent;
* attacker identity;
* persistence success;
* data theft;
* malware execution;
* production impact.

---

## 25. CASE-010 Laboratory Evidence

CASE-010 is the flagship laboratory implementation of PB-010.

The observed sequence was:

1. `DET-AUTH-001`
2. `DET-AUTH-003`
3. `DET-LINUX-001`

The sequence occurred on:

`lab-linux-10`

for:

`root`

with available source-IP evidence:

`198.51.100.90`

The three stages were correlated successfully.

---

## 26. CASE-010 Stage One

Detection:

`DET-AUTH-001`

Stage:

`credential_access`

Timestamp:

`2026-09-09T10:02:03Z`

This stage represents the authentication attack portion of the sequence.

---

## 27. CASE-010 Stage Two

Detection:

`DET-AUTH-003`

Stage:

`post_authentication_activity`

Timestamp:

`2026-09-09T10:03:21+00:00`

This stage represents suspicious post-authentication privileged activity.

The alert did not originally provide a `timestamp` field, so the correlation implementation uses its available deterministic time field according to the timestamp-selection rules.

---

## 28. CASE-010 Stage Three

Detection:

`DET-LINUX-001`

Stage:

`persistence`

Timestamp:

`2026-09-09T10:12:00Z`

This stage represents suspicious Linux cron persistence activity.

---

## 29. CASE-010 Correlation Result

The laboratory correlation produced:

`ALERT-CASE-010-DET-CORR-001`

Detection:

`DET-CORR-001`

Severity:

`critical`

Confidence:

`high`

Stage count:

`3`

Supporting alerts:

* `ALERT-CASE-001-DET-AUTH-001`
* `ALERT-CASE-004-DET-AUTH-003`
* `ALERT-CASE-009-DET-LINUX-001-EVT-010013`

The correlation contained 13 supporting telemetry events.

---

## 30. CASE-010 Analyst Interpretation

The observed evidence supports investigation of a multi-stage attack sequence because credential-access activity, post-authentication privileged activity, and Linux persistence activity were correlated on the same laboratory host and user within the configured correlation window.

The sequence does not independently prove compromise.

Any compromise determination requires additional corroborating evidence.

---

## 31. ATT&CK Context

The current correlation maps to:

### Credential Access

`T1110` — Brute Force

### Credential / Account Context

`T1078` — Valid Accounts

### Discovery

`T1087` — Account Discovery

`T1069.001` — Permission Groups Discovery: Local Groups

### Persistence

`T1053.003` — Scheduled Task/Job: Cron

ATT&CK mappings are contextual representations of the observed detection stages.

They should not be treated as proof that every technique was successfully executed by a malicious actor.

---

## 32. Alert Validation

Before investigation begins, verify:

* alert ID exists;
* detection ID is correct;
* detection version is present;
* status is open;
* confidence is high;
* severity is present;
* host is non-empty;
* user is non-empty;
* timestamp is valid;
* supporting alerts exist;
* supporting events can be resolved.

Any failed validation should be documented.

---

## 33. Evidence Preservation

Preserve:

* correlation alert;
* original stage alerts;
* original telemetry events;
* timestamps;
* source IPs;
* host information;
* user information;
* process information;
* command lines;
* file evidence;
* persistence evidence;
* authentication evidence;
* investigation notes.

Do not modify original telemetry to make the correlation appear stronger.

---

## 34. Timeline Reconstruction

Construct a single chronological timeline.

At minimum include:

| Time             | Detection     | Stage               | Evidence                    |
| ---------------- | ------------- | ------------------- | --------------------------- |
| `10:02:03Z`      | DET-AUTH-001  | Credential access   | Authentication activity     |
| `10:03:21+00:00` | DET-AUTH-003  | Post-authentication | Privileged session activity |
| `10:12:00Z`      | DET-LINUX-001 | Persistence         | Cron persistence activity   |

The final timeline should distinguish direct observations from analyst interpretation.

---

## 35. Authentication Investigation

Review:

* failed authentication events;
* successful authentication;
* account targeted;
* source IP;
* authentication method;
* session creation;
* subsequent privileged activity;
* related authentication alerts.

Determine whether the authentication sequence is supported by independent telemetry.

---

## 36. Post-Authentication Investigation

Review:

* session ID;
* commands;
* privilege changes;
* account enumeration;
* group enumeration;
* sudo activity;
* shell activity;
* process execution;
* files accessed;
* network activity.

Determine whether the activity can be explained by authorized laboratory behavior.

---

## 37. Persistence Investigation

Review:

* cron configuration;
* cron file path;
* cron command;
* process execution;
* downloaded content;
* temporary files;
* hidden files;
* file hashes;
* parent process;
* user context;
* persistence modification time.

Do not assume that suspicious cron configuration automatically proves successful persistence.

---

## 38. Network Correlation

Where available, correlate:

* source IP;
* destination IP;
* destination port;
* DNS;
* connection timestamps;
* process;
* host;
* user.

Investigate source-IP consistency across the correlated stages.

A consistent source IP increases correlation confidence but does not prove attacker identity.

---

## 39. Endpoint Correlation

Where endpoint telemetry is available, investigate:

* process creation;
* parent/child relationships;
* shell execution;
* command lines;
* file creation;
* file modification;
* temporary directories;
* downloaded payloads.

Endpoint evidence can strengthen or weaken the multi-stage hypothesis.

---

## 40. Malware Correlation

Where applicable, investigate:

* suspicious executable files;
* hashes;
* YARA findings;
* sandbox results;
* process behavior;
* persistence artifacts;
* network behavior.

No malware should be claimed unless supporting evidence exists.

---

## 41. File Correlation

Investigate:

* modified configuration files;
* cron files;
* downloaded payloads;
* temporary files;
* hidden files;
* executable permissions;
* hashes;
* file timestamps.

File evidence should be connected to specific events whenever possible.

---

## 42. Threat Intelligence

Threat intelligence should be applied only to observable indicators.

Potential intelligence targets include:

* source IPs;
* destination IPs;
* domains;
* URLs;
* file hashes;
* filenames;
* command-and-control infrastructure.

The CASE-010 laboratory correlation itself is not a threat-intelligence match.

Do not invent actor, campaign, malware-family, or infrastructure attribution.

---

## 43. False Positive Analysis

Potential legitimate explanations include:

* authorized security testing;
* penetration-testing activity;
* administrative troubleshooting;
* vulnerability validation;
* scheduled maintenance;
* configuration-management activity;
* incident-response testing.

Analysts should compare the complete sequence against authorized activity before determining maliciousness.

---

## 44. False Negative Considerations

The correlation can fail to identify multi-stage activity when:

* stages occur outside 30 minutes;
* different users are involved;
* different hosts are involved;
* source IPs rotate;
* a required stage is not detected;
* an input alert is not open;
* an input alert is below high confidence;
* timestamps are missing;
* timestamps are manipulated;
* telemetry is deleted;
* persistence occurs through an unsupported mechanism.

These limitations must be documented rather than hidden.

---

## 45. Adversarial Evasion — Slow Activity

An attacker could distribute stages across more than 30 minutes.

Current behavior:

The sequence is not correlated.

Improvement:

Evaluate configurable correlation windows and complementary longer-term hunting.

---

## 46. Adversarial Evasion — Source-IP Rotation

An attacker could use different source IPs across stages.

Current behavior:

Multiple distinct source IPs cause the candidate correlation to be rejected.

Improvement:

Use additional authorized identity, host, session, or infrastructure correlation rather than relying exclusively on source IP.

---

## 47. Adversarial Evasion — Account Rotation

An attacker could use different accounts across stages.

Current behavior:

The current correlation requires the same user.

Improvement:

Consider controlled identity relationships and session lineage where reliable evidence exists.

---

## 48. Adversarial Evasion — Host Rotation

An attacker could move between hosts.

Current behavior:

The current correlation requires the same host.

Improvement:

Introduce carefully validated cross-host correlation using authentication, session, network, and identity evidence.

---

## 49. Adversarial Evasion — Missing Detection Stage

If one required detection fails to trigger, the correlation does not occur.

Improvement:

Use threat hunting and cross-project telemetry correlation to identify activity that bypassed one detection stage.

---

## 50. Timestamp Manipulation

Timestamp manipulation can disrupt chronological correlation.

Analysts should compare:

* event timestamps;
* ingestion times;
* filesystem timestamps;
* authentication times;
* process times;
* log-source metadata.

Conflicting timestamps should be recorded as evidence-quality limitations.

---

## 51. Duplicate Alerts

Duplicate alerts must not be treated as additional attack stages.

Analysts should preserve original alert IDs and identify duplicates before counting independent evidence.

The current correlation uses selected alerts and supporting event IDs; analysts should validate uniqueness during investigation.

---

## 52. Evidence Deletion

If supporting telemetry is missing, document the missing evidence.

Do not reconstruct deleted evidence as if it were observed.

Use remaining telemetry to establish only what can actually be supported.

---

## 53. Containment Assessment

Containment decisions should be based on the total evidence.

Potential laboratory containment actions include:

* isolate the affected lab host;
* terminate suspicious sessions;
* disable the affected test account;
* block suspicious network communication;
* preserve relevant files;
* stop suspicious persistence mechanisms.

Do not perform containment against systems without explicit authorization.

---

## 54. Account Containment

Where evidence supports account misuse, consider:

* session termination;
* credential rotation;
* account disablement;
* privilege review;
* SSH-key review;
* authentication-policy review.

Do not automatically disable accounts based solely on the correlation alert.

---

## 55. Host Containment

If the investigation establishes sufficiently strong evidence of malicious activity, consider isolating the laboratory host.

Preserve evidence before destructive remediation where practical.

---

## 56. Eradication

Potential eradication activities include:

* remove malicious persistence;
* remove unauthorized files;
* terminate malicious processes;
* rotate credentials;
* remove unauthorized SSH keys;
* correct compromised configuration;
* remove unauthorized scheduled tasks.

Every remediation action should be documented.

---

## 57. Recovery

Recovery should include:

* restore expected configuration;
* verify persistence removal;
* verify authentication controls;
* verify account state;
* verify scheduled tasks;
* verify network behavior;
* run relevant detections again;
* monitor for recurrence.

---

## 58. Post-Recovery Monitoring

Monitor for:

* repeated authentication attacks;
* renewed privileged sessions;
* persistence recreation;
* suspicious process execution;
* network anomalies;
* file modifications;
* account changes.

Detection recurrence should be correlated with the original case.

---

## 59. Detection Feedback Loop

The investigation should produce engineering feedback.

Example:

**Observation**

Three independent detections can form a coherent attack sequence.

**Weakness**

Individual detections provide limited context when viewed independently.

**Improvement**

Correlation layer combines them using host, user, time, and source-IP consistency.

**Validation**

CASE-010 demonstrates successful three-stage correlation.

**Next improvement**

Expand correlation resilience against slow, distributed, and identity-changing activity.

---

## 60. Cross-Project Correlation

PB-010 should connect with:

* `cybernova-siem-detection-lab`;
* `cybernova-threat-hunting-toolkit`;
* `cybernova-malware-analysis-sandbox`;
* `cybernova-windows-security-monitoring-lab`;
* `linux-security-audit-toolkit`;
* other authorized CYBERNOVA security projects where evidence is relevant.

Cross-project evidence must remain traceable to its original source.

---

## 61. Evidence Package

A complete PB-010 investigation package should contain:

* correlation alert;
* supporting alerts;
* supporting telemetry;
* investigation notes;
* timeline;
* indicators;
* threat-intelligence assessment;
* hunting results;
* ATT&CK mapping;
* response actions;
* impact assessment;
* final report;
* lessons learned;
* detection-improvement recommendations.

---

## 62. Escalation Criteria

Escalate when:

* multiple high-confidence detections correlate;
* suspicious privileged activity follows authentication anomalies;
* persistence is identified;
* malware evidence is discovered;
* unauthorized account activity is supported;
* network infrastructure appears suspicious;
* evidence indicates broader host or identity scope;
* containment is required;
* evidence quality prevents reliable determination.

Escalation does not mean compromise is automatically confirmed.

---

## 63. Closure Criteria

A PB-010 investigation may close when:

* all required evidence has been reviewed;
* the correlation has been validated;
* the timeline is complete;
* indicators are documented;
* ATT&CK context is recorded;
* threat-intelligence limitations are documented;
* response actions are recorded;
* false-positive considerations are addressed;
* limitations are documented;
* detection feedback is captured;
* the final analyst conclusion is supported by evidence.

---

## 64. Analyst Decision Matrix

| Finding                               | Recommended Position                   |
| ------------------------------------- | -------------------------------------- |
| Required stages absent                | No multi-stage correlation             |
| Stages present but outside 30 minutes | Correlation not established            |
| Source IPs conflict                   | Correlation rejected                   |
| Same host/user, ordered stages        | Investigate                            |
| Correlation generated                 | High-priority investigation            |
| Malware corroboration                 | Escalate                               |
| Persistence corroboration             | Escalate                               |
| Compromise evidence corroborated      | Confirm according to evidence standard |
| Correlation only                      | Do not claim confirmed compromise      |

---

## 65. CASE-010 Evidence Chain

The CASE-010 evidence chain is:

`authentication attack`

→ `successful authentication`

→ `privileged post-authentication activity`

→ `Linux persistence`

→ `multi-stage correlation`

→ `SOC investigation`

The chain demonstrates how individual detections can become a higher-level investigative finding.

---

## 66. Engineering Limitation — Static Correlation Alert ID

The current implementation generates:

`ALERT-CASE-010-DET-CORR-001`

This identifier is tied to the CASE-010 namespace.

This is documented as an engineering limitation.

A future refactor should provide deterministic case-independent correlation alert IDs while preserving backward compatibility for existing laboratory evidence.

---

## 67. Engineering Limitation — Linux Alert Namespace

The CASE-010 correlation currently consumes a Linux persistence alert whose identifier carries the CASE-009 namespace.

This is preserved as existing laboratory evidence.

It should not be silently rewritten during investigation.

A future detection-engineering refactor can separate detection alert identity from case-specific evidence packaging.

---

## 68. Security Validation

PB-010 should be tested against:

* missing host;
* missing user;
* missing timestamp;
* invalid timestamp;
* timezone-naive timestamp;
* missing supporting events;
* malformed supporting event lists;
* closed alerts;
* low-confidence alerts;
* missing required stage;
* reversed stage order;
* correlation window exceeded;
* conflicting source IPs;
* duplicate alerts;
* multiple candidate alerts;
* empty source IP;
* malformed alert objects.

---

## 69. Regression Validation

The correlation test suite should verify:

* valid three-stage correlation;
* correlation alert identity;
* detection ID;
* stage count;
* stage ordering;
* timestamps;
* host;
* user;
* source IP;
* supporting alert IDs;
* supporting event IDs;
* ATT&CK mapping;
* rejection of invalid sequences.

Existing tests are located in:

`tests/test_case_correlation.py`

---

## 70. Laboratory Validation

The successful CASE-010 laboratory result demonstrates:

* three required stages detected;
* same host;
* same user;
* chronological sequence;
* source-IP consistency where available;
* correlation within the 30-minute window;
* one generated correlation alert;
* supporting evidence preserved.

This is laboratory evidence of technical correlation, not evidence of a production incident.

---

## 71. Recruiter Evidence

PB-010 demonstrates practical SOC capabilities including:

* multi-stage alert correlation;
* detection orchestration;
* temporal analysis;
* evidence preservation;
* alert validation;
* ATT&CK mapping;
* threat-hunting integration;
* adversarial detection analysis;
* incident-response reasoning;
* detection engineering feedback.

The appropriate portfolio claim is:

**Hands-on SOC laboratory experience implementing and investigating multi-stage detection correlation.**

Do not claim professional SOC employment based on this laboratory work.

---

## 72. Interview Evidence

An analyst should be able to explain:

1. Why individual alerts were correlated.
2. Why the host and user were required to match.
3. Why the 30-minute window exists.
4. Why source-IP conflicts reject correlation.
5. Why high-confidence inputs are required.
6. How timestamp fallback works.
7. How supporting evidence is preserved.
8. Why the correlation is critical severity.
9. Why the result does not automatically prove compromise.
10. How an attacker could evade the correlation.
11. How detection engineering could improve it.
12. How CASE-010 validates the implementation.

---

## 73. Operational Checklist

### Correlation

* [ ] DET-AUTH-001 present
* [ ] DET-AUTH-003 present
* [ ] DET-LINUX-001 present
* [ ] All alerts open
* [ ] All alerts high confidence
* [ ] Same host
* [ ] Same user
* [ ] Valid timestamps
* [ ] Chronological order
* [ ] Within 30 minutes
* [ ] Source IPs do not conflict

### Investigation

* [ ] Original alerts preserved
* [ ] Supporting events preserved
* [ ] Timeline created
* [ ] Authentication investigated
* [ ] Privileged activity investigated
* [ ] Persistence investigated
* [ ] Network investigated
* [ ] Endpoint investigated
* [ ] Malware evidence checked
* [ ] Threat intelligence documented
* [ ] ATT&CK documented

### Response

* [ ] Severity assessed
* [ ] Containment assessed
* [ ] Account response assessed
* [ ] Host response assessed
* [ ] Eradication documented
* [ ] Recovery documented
* [ ] Monitoring documented

### Closure

* [ ] Evidence classification complete
* [ ] Limitations documented
* [ ] False positives considered
* [ ] False negatives considered
* [ ] Detection feedback captured
* [ ] Final report complete
* [ ] Lessons learned complete

---

## 74. Completion Standard

PB-010 is complete when an analyst can move from:

**individual detection**

→ **correlation**

→ **timeline**

→ **evidence validation**

→ **threat intelligence**

→ **ATT&CK**

→ **hunting**

→ **response**

→ **impact assessment**

→ **detection improvement**

without losing traceability to the original telemetry.

---

## 75. Final Analyst Statement

The CYBERNOVA `DET-CORR-001` correlation layer demonstrates a controlled method for identifying a multi-stage attack sequence by correlating credential-access, post-authentication activity, and Linux persistence detections on the same laboratory host and user within a defined temporal window.

CASE-010 demonstrates that the correlation can successfully connect three independent detection stages into a single investigative finding.

The result should be treated as a high-priority investigative signal.

It does not independently establish compromise, malicious intent, successful persistence, attacker attribution, or production impact.

All final conclusions must remain proportional to the available evidence.
