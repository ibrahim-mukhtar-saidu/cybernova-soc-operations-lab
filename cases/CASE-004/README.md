# CASE-004 — Suspicious Post-Authentication Privileged Session

## Case Overview

| Field          | Value                                                                 |
| -------------- | --------------------------------------------------------------------- |
| Case ID        | CASE-004                                                              |
| Scenario       | Account Compromise / Suspicious Authentication After Successful Login |
| Detection      | `DET-AUTH-003`                                                        |
| Detection Name | Suspicious Post-Authentication Privileged Session                     |
| Severity       | High                                                                  |
| Confidence     | High                                                                  |
| Status         | Investigated — Compromise Not Confirmed                               |
| Environment    | Synthetic / Authorized Security Laboratory                            |
| Primary Host   | `lab-linux-01`                                                        |
| Primary User   | `admin`                                                               |
| Primary Source | `198.51.100.60`                                                       |
| Session        | `SES-004-C`                                                           |

---

## 1. Scenario

CASE-004 demonstrates a multi-stage authentication and post-authentication investigation.

The scenario contains:

1. Four failed password authentication attempts.
2. A successful authentication against the same account.
3. A correlated privileged session.
4. Four post-authentication command executions.
5. Identity and privilege enumeration.
6. Benign authentication noise.
7. Correlation of authentication, session, and command activity.

The purpose is to demonstrate how a SOC analyst can progress from an authentication alert into a broader investigation instead of treating the initial authentication failures as an isolated event.

---

## 2. Detection

### DET-AUTH-003

**Suspicious Post-Authentication Privileged Session**

The detection identifies a sequence containing:

* repeated failed authentication;
* successful authentication from the same source;
* session creation;
* post-authentication command execution;
* privileged activity indicators.

The detection uses a five-minute correlation window and requires:

* at least four failed password authentication attempts;
* successful authentication;
* correlated session start;
* at least two post-authentication commands;
* at least one privileged activity indicator.

---

## 3. Alert Result

The detection engine generated exactly one alert from the CASE-004 telemetry.

| Field                     | Result                        |
| ------------------------- | ----------------------------- |
| Alert ID                  | `ALERT-CASE-004-DET-AUTH-003` |
| Severity                  | High                          |
| Confidence                | High                          |
| Source IP                 | `198.51.100.60`               |
| Host                      | `lab-linux-01`                |
| User                      | `admin`                       |
| Failed Authentications    | 4                             |
| Successful Authentication | `EVT-004007`                  |
| Session Start             | `EVT-004008`                  |
| Post-Auth Commands        | 4                             |
| Session ID                | `SES-004-C`                   |
| Privileged Indicators     | `id`, `sudo -l`               |
| Supporting Events         | 10                            |

---

## 4. Investigation Path

The investigation followed this sequence:

```text
Authentication failures
        ↓
Successful authentication
        ↓
Session correlation
        ↓
Post-authentication commands
        ↓
Privilege analysis
        ↓
Threat-intelligence assessment
        ↓
Threat hunting
        ↓
Response assessment
        ↓
Final determination
```

This workflow demonstrates the transition from automated detection to analyst-driven investigation.

---

## 5. Key Evidence

The primary supporting events are:

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

The post-authentication commands were:

```text
whoami
id
sudo -l
uname -a
```

The privileged activity indicators were:

```text
id
sudo -l
```

---

## 6. Findings

### Confirmed Observations

The synthetic telemetry confirms:

* four failed password authentication attempts;
* successful authentication from the same source and account;
* session `SES-004-C`;
* four correlated post-authentication commands;
* identity and privilege enumeration.

### Analyst Determination

The sequence is suspicious and warrants investigation.

However:

**Account compromise is not confirmed.**

The available telemetry does not independently establish:

* credential theft;
* unauthorized access;
* malicious intent;
* persistence;
* lateral movement;
* malware execution;
* threat actor attribution.

---

## 7. Threat Intelligence

The source address `198.51.100.60` is a documentation/test address.

It is therefore not treated as a real malicious IOC.

This case does not establish:

* malicious reputation;
* threat actor attribution;
* malware infrastructure;
* campaign infrastructure.

Threat intelligence is used only for contextual analysis within the laboratory scenario.

---

## 8. MITRE ATT&CK Mapping

| Technique | Name                               | Observed Context               |
| --------- | ---------------------------------- | ------------------------------ |
| T1110     | Brute Force                        | Failed authentication sequence |
| T1078     | Valid Accounts                     | Successful authentication      |
| T1087     | Account Discovery                  | `id`                           |
| T1069.001 | Permission Groups Discovery: Local | `id`, `sudo -l`                |
| T1059.004 | Unix Shell                         | Command execution              |

These mappings describe observed behavior in the synthetic dataset and do not establish adversary activity.

---

## 9. Response Determination

The appropriate response for the laboratory case is investigative.

A real-world SOC analyst should verify:

* authentication authorization;
* account ownership;
* source-system ownership;
* session legitimacy;
* privilege usage;
* endpoint activity;
* persistence;
* lateral movement;
* network activity.

Containment should only be considered when unauthorized activity is confirmed and the scope is understood.

No real-world containment action should be performed against the synthetic source `198.51.100.60`.

---

## 10. Investigation Limitations

The dataset does not include complete:

* identity-provider telemetry;
* endpoint telemetry;
* shell history;
* sudo execution records;
* persistence telemetry;
* network telemetry;
* DNS telemetry;
* file modification telemetry;
* session termination data.

Therefore, absence of these events must not be interpreted as proof that the corresponding behaviors did not occur.

The final determination is limited to the evidence represented in the laboratory dataset.

---

## 11. Case Determination

### Status

**Investigated — Compromise Not Confirmed**

### Suspicious Activity

**Confirmed in synthetic telemetry.**

### Account Compromise

**Not confirmed.**

### Persistence

**Not established.**

### Lateral Movement

**Not established.**

### Malware Activity

**Not established.**

### Threat Actor Attribution

**Not established.**

---

## 12. Case Artifacts

| Artifact                 | Purpose                               |
| ------------------------ | ------------------------------------- |
| `alert.json`             | Generated detection-engine alert      |
| `investigation.md`       | Detailed analyst investigation        |
| `timeline.md`            | Chronological event analysis          |
| `indicators.md`          | Case indicators and observables       |
| `threat-intelligence.md` | Threat-intelligence assessment        |
| `hunting.md`             | Threat-hunting hypotheses and results |
| `response.md`            | Response and containment workflow     |
| `final-report.md`        | Executive-level final report          |
| `lessons-learned.md`     | Detection and SOC workflow lessons    |

---

## 13. Evidence Integrity

This case uses synthetic, authorized laboratory telemetry.

The source IP `198.51.100.60` is a documentation/test address and must not be treated as a real malicious infrastructure indicator.

The case documentation deliberately separates:

* observed evidence;
* analyst interpretation;
* hypotheses;
* confirmed findings;
* recommended actions;
* investigation gaps;
* limitations.

No real-world account, host, source IP, threat actor, malware family, or external infrastructure is claimed to be compromised or malicious based on this case.

---

## 14. Portfolio Relevance

CASE-004 demonstrates practical SOC capabilities including:

* authentication detection;
* multi-event correlation;
* session-aware analysis;
* privileged activity investigation;
* evidence classification;
* threat hunting;
* threat-intelligence assessment;
* response planning;
* containment decision-making;
* incident reporting;
* detection limitation analysis.

The case demonstrates the SOC workflow:

**Detect → Triage → Investigate → Hunt → Validate → Respond → Document → Improve**

---

## 15. Final Case Statement

> **Suspicious authentication and post-authentication privileged activity was confirmed in synthetic telemetry, but account compromise was not confirmed.**

CASE-004 is therefore retained as an investigated laboratory incident scenario demonstrating a complete authentication-to-post-authentication SOC investigation workflow.
