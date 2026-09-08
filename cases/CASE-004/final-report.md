# CASE-004 — Final Incident Report

## 1. Document Control

| Field                   | Value                                                       |
| ----------------------- | ----------------------------------------------------------- |
| Case ID                 | CASE-004                                                    |
| Case Type               | Account Compromise / Suspicious Post-Authentication Session |
| Detection ID            | DET-AUTH-003                                                |
| Detection Name          | Suspicious Post-Authentication Privileged Session           |
| Severity                | High                                                        |
| Confidence              | High                                                        |
| Status                  | Investigated — Compromise Not Confirmed                     |
| Environment             | Synthetic / Authorized Security Laboratory                  |
| Primary Host            | `lab-linux-01`                                              |
| Primary User            | `admin`                                                     |
| Primary Source IP       | `198.51.100.60`                                             |
| Session ID              | `SES-004-C`                                                 |
| Evidence Classification | Observed Evidence                                           |
| Report Version          | 1.0                                                         |

---

## 2. Executive Summary

CASE-004 was generated from synthetic Linux SSH authentication and post-authentication session telemetry.

The detection identified a sequence involving:

1. Four failed password authentication attempts against the `admin` account.
2. A successful password authentication from the same source IP.
3. A correlated privileged session start.
4. Four post-authentication command executions.
5. Privileged activity indicators including `id` and `sudo -l`.

The correlated source was `198.51.100.60`, the affected host was `lab-linux-01`, and the session identifier was `SES-004-C`.

The sequence is suspicious because authentication failures were followed by successful authentication and immediate privileged-session activity. The post-authentication commands also included account and privilege enumeration.

However, the telemetry is synthetic laboratory evidence. The source address is a documentation/test address and does not represent a real-world malicious infrastructure indicator.

**Final determination: suspicious authentication and post-authentication activity was confirmed in the laboratory dataset; account compromise was not confirmed.**

No real-world containment action is warranted from this synthetic case alone.

---

## 3. Detection Summary

### Detection

**DET-AUTH-003 — Suspicious Post-Authentication Privileged Session**

The detection correlates authentication and session telemetry rather than treating an isolated failed login as sufficient evidence of compromise.

The detection requires:

* At least four failed password authentication attempts.
* The failures to target the same user and originate from the same source.
* A subsequent successful password authentication.
* A correlated session start.
* At least two post-authentication command executions.
* At least one privileged activity indicator.

The detection escalates the resulting alert to high severity and high confidence when the complete sequence is observed.

---

## 4. Alert Summary

The detection engine generated one alert:

| Field                     | Observed Value                |
| ------------------------- | ----------------------------- |
| Alert ID                  | `ALERT-CASE-004-DET-AUTH-003` |
| Detection                 | `DET-AUTH-003`                |
| Severity                  | High                          |
| Confidence                | High                          |
| Source IP                 | `198.51.100.60`               |
| Host                      | `lab-linux-01`                |
| User                      | `admin`                       |
| Failed Authentications    | 4                             |
| Successful Authentication | `EVT-004007`                  |
| Session Start             | `EVT-004008`                  |
| Post-Auth Commands        | 4                             |
| Session                   | `SES-004-C`                   |
| Privileged Indicators     | `id`, `sudo -l`               |
| Supporting Events         | 10                            |

---

## 5. Evidence Summary

### Observed Evidence

The telemetry directly demonstrates:

* Four failed password authentication events from `198.51.100.60`.
* A successful password authentication from the same source and account.
* Session `SES-004-C` beginning after successful authentication.
* Four command execution events associated with that session.
* `id` and `sudo -l` appearing in the post-authentication activity.
* Correlation of the activity to `lab-linux-01` and account `admin`.

Supporting events:

```text
EVT-004003
EVT-004004
EVT-004005
EVT-004006
EVT-004007
EVT-004008
EVT-004009
EVT-004010
EVT-004011
EVT-004012
```

### Analyst Interpretation

The observed sequence is consistent with suspicious authentication followed by privileged-session discovery activity.

The sequence could represent:

* legitimate administrative activity following authentication failures;
* an authorized account-management or troubleshooting action;
* attempted credential compromise;
* successful unauthorized access;
* or another benign or malicious workflow not represented completely in the available telemetry.

The evidence therefore supports escalation and investigation but does not independently establish malicious intent.

---

## 6. Authentication Analysis

The primary authentication sequence involved four failed password authentication attempts against the `admin` account.

These failures were followed by successful authentication:

* Source: `198.51.100.60`
* User: `admin`
* Authentication method: password
* Successful event: `EVT-004007`

The successful authentication contained metadata indicating that it was preceded by four failures.

This satisfies the authentication portion of DET-AUTH-003.

The sequence is suspicious because repeated failures followed by success can indicate password guessing, credential reuse, or legitimate user error. Additional session evidence is therefore required before determining whether compromise occurred.

---

## 7. Post-Authentication Analysis

Following successful authentication, session `SES-004-C` was established.

The session generated four command execution events:

1. `whoami`
2. `id`
3. `sudo -l`
4. `uname -a`

These commands provide information about:

* current identity;
* group and privilege context;
* available sudo permissions;
* operating-system information.

The combination of authentication correlation and subsequent discovery activity increases the significance of the alert compared with an isolated authentication failure.

---

## 8. Privileged Activity Assessment

Two commands were specifically treated as privileged activity indicators:

* `id`
* `sudo -l`

`id` can reveal the effective user and group memberships.

`sudo -l` can reveal commands the authenticated account may execute through sudo.

These commands are not inherently malicious. They can legitimately be executed by administrators during routine troubleshooting or system administration.

Their significance in this case comes from their position immediately after the suspicious authentication sequence.

---

## 9. Threat Intelligence Assessment

The primary source IP is:

`198.51.100.60`

This address belongs to a documentation/test address range used for synthetic security scenarios.

Therefore:

* no real-world malicious reputation is assigned;
* no real-world threat actor attribution is made;
* no malware infrastructure association is established;
* no campaign attribution is established.

Threat intelligence is used only as contextual information for this laboratory exercise.

The observed behavior should not be interpreted as evidence that `198.51.100.60` is a real malicious host.

---

## 10. MITRE ATT&CK Mapping

The observed activity was mapped to the following techniques:

| Technique | Name                               | Relevance                                            |
| --------- | ---------------------------------- | ---------------------------------------------------- |
| T1110     | Brute Force                        | Repeated failed authentication attempts              |
| T1078     | Valid Accounts                     | Successful authentication using an account           |
| T1087     | Account Discovery                  | `id` used to inspect account context                 |
| T1069.001 | Permission Groups Discovery: Local | `id` and `sudo -l` used to inspect privilege context |
| T1059.004 | Unix Shell                         | Shell-based command execution                        |

These mappings describe behavior represented in the synthetic telemetry. They do not establish that an adversary actually performed the activity.

---

## 11. Investigation Findings

### Finding 1 — Suspicious Authentication Sequence

**Determination:** Confirmed in observed telemetry.

Four failed password authentication attempts were followed by a successful authentication for the same account and source.

### Finding 2 — Privileged Session Correlation

**Determination:** Confirmed in observed telemetry.

A session start followed the successful authentication and was correlated to session `SES-004-C`.

### Finding 3 — Post-Authentication Enumeration

**Determination:** Confirmed in observed telemetry.

Four command executions occurred after authentication, including identity, privilege, and operating-system enumeration.

### Finding 4 — Account Compromise

**Determination:** Not confirmed.

The available synthetic telemetry does not establish unauthorized access, credential theft, persistence, lateral movement, or malicious intent.

### Finding 5 — Persistence

**Determination:** Not established.

No persistence mechanism was represented in the available evidence.

### Finding 6 — Lateral Movement

**Determination:** Not established.

No lateral movement telemetry was included in this case.

### Finding 7 — Malware Execution

**Determination:** Not established.

No malware execution evidence was present in the available dataset.

---

## 12. Investigation Gaps

The following information would be required for a stronger real-world determination:

* authoritative identity-provider or SSH authentication records;
* account ownership and authorization status;
* source-system ownership;
* complete shell history;
* process execution telemetry;
* endpoint detection telemetry;
* privilege escalation events;
* sudo execution logs;
* persistence locations;
* network connection telemetry;
* DNS activity;
* file modification telemetry;
* additional authentication history;
* session termination records;
* known administrative change records.

Because these datasets are not represented in the current synthetic case, the investigation cannot independently confirm compromise.

---

## 13. Response Assessment

The appropriate response to this laboratory alert is investigative rather than destructive.

Recommended analyst workflow:

1. Validate the alert.
2. Verify whether the authentication was authorized.
3. Confirm account ownership.
4. Validate source-system ownership.
5. Review the complete session.
6. Examine privilege-related activity.
7. Check for persistence.
8. Correlate endpoint and network telemetry.
9. Preserve relevant evidence.
10. Escalate to containment only if unauthorized activity is confirmed.

No real-world blocking, account disabling, host isolation, or destructive remediation should be performed against the synthetic infrastructure represented in this case.

---

## 14. Evidence Preservation

The following evidence should be preserved for reproducibility:

* original CASE-004 telemetry;
* generated alert;
* detection specification;
* investigation timeline;
* indicators;
* threat-intelligence assessment;
* hunting hypotheses and results;
* response workflow;
* analyst conclusions;
* validation output where retained.

Evidence should remain unchanged after collection. Derived analysis should be clearly separated from original observations.

---

## 15. Recovery Considerations

If this were a real confirmed compromise, recovery would depend on the verified root cause and scope.

Potential actions could include:

* credential reset;
* session revocation;
* SSH key review;
* account access review;
* removal of confirmed persistence;
* endpoint remediation;
* network containment;
* restoration from known-good state;
* increased monitoring;
* post-remediation validation.

These actions are recommendations for a hypothetical real-world incident and were not performed against this synthetic laboratory case.

---

## 16. Lessons for Detection Engineering

CASE-004 demonstrates why authentication detections should not rely exclusively on failure counts.

An isolated sequence of failed logins can have many benign explanations.

The detection becomes more useful when authentication telemetry is correlated with:

* successful authentication;
* account identity;
* session creation;
* process or command execution;
* privilege enumeration;
* endpoint activity;
* network activity.

This improves triage quality and helps analysts distinguish isolated authentication noise from a potentially meaningful authentication-to-session sequence.

---

## 17. Detection Limitations

DET-AUTH-003 may generate false positives when:

* administrators mistype passwords;
* legitimate users retry authentication;
* shared administrative accounts are used;
* automated systems authenticate after retries;
* authorized administrators perform discovery commands immediately after login.

The detection may generate false negatives when:

* fewer than four failures occur;
* authentication telemetry is incomplete;
* session identifiers are unavailable;
* command execution telemetry is missing;
* an attacker uses another authentication mechanism;
* the attacker does not execute the monitored commands;
* events fall outside the configured correlation window.

The detection should therefore be treated as an investigation trigger rather than an automatic compromise verdict.

---

## 18. Final Determination

### Current Status

**Suspicious activity confirmed.**

### Account Compromise

**Not confirmed.**

### Malicious Intent

**Not confirmed.**

### Persistence

**Not established.**

### Lateral Movement

**Not established.**

### Malware Activity

**Not established.**

### Threat Actor Attribution

**Not established.**

### Recommended Disposition

**Escalate for authorization and identity verification if this were real telemetry; retain the case as a high-confidence suspicious authentication sequence in the laboratory environment.**

---

## 19. Portfolio Evidence

CASE-004 demonstrates the following SOC capabilities:

* authentication detection engineering;
* multi-event correlation;
* session-aware investigation;
* privileged activity analysis;
* alert triage;
* evidence classification;
* MITRE ATT&CK mapping;
* threat-intelligence assessment;
* threat hunting;
* response planning;
* containment decision-making;
* evidence preservation;
* investigation-gap identification;
* analyst determination without overstating evidence.

The case demonstrates a complete analytical transition from:

**authentication alert → session correlation → command analysis → privilege review → threat assessment → response decision → final determination.**

---

## 20. Evidence Integrity Note

This report is based on synthetic, authorized laboratory telemetry created for cybersecurity detection and incident-response training.

All observations should be interpreted within the scope of the available dataset.

The report deliberately distinguishes:

* observed evidence;
* analyst interpretation;
* investigative hypotheses;
* confirmed findings;
* limitations;
* recommended actions.

The presence of suspicious behavior in this laboratory case does not establish that a real account, host, source IP, threat actor, malware family, or external infrastructure was compromised or malicious.

---

## 21. Case Closure Statement

CASE-004 successfully demonstrated the DET-AUTH-003 suspicious post-authentication privileged-session workflow.

The detection generated one high-severity, high-confidence alert from the CASE-004 dataset and correlated authentication, session, and command-execution telemetry into a single investigation unit.

The final case determination is:

> **Suspicious authentication and post-authentication privileged activity observed and confirmed in synthetic telemetry. Account compromise is not confirmed.**

The case may be closed as an investigated laboratory detection scenario while preserving the documented limitations and recommended real-world investigative workflow.
