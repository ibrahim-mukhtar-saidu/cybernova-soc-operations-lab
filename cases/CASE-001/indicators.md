# CASE-001 — Indicators of Interest

## 1. Purpose

This document records indicators associated with CASE-001 that are directly supported by the authorized laboratory telemetry.

Indicators are classified according to their evidence status.

The presence of an indicator does not automatically establish maliciousness or compromise.

---

## 2. Indicator Summary

| Indicator Type | Indicator | Context | Evidence Status | Confidence |
|---|---|---|---|---|
| IPv4 Address | `198.51.100.25` | Source of repeated SSH authentication failures and subsequent successful root authentication | Observed | High |
| Username | `root` | Target account associated with the primary authentication sequence | Observed | High |
| Protocol | `SSH` | Protocol associated with the detected authentication activity | Observed | High |
| Hostname | `lab-auth-01` | Host associated with the authentication telemetry | Observed | High |
| Event ID | `EVT-001004` | First failed authentication in primary sequence | Observed | High |
| Event ID | `EVT-001005` | Second failed authentication in primary sequence | Observed | High |
| Event ID | `EVT-001006` | Third failed authentication in primary sequence | Observed | High |
| Event ID | `EVT-001007` | Fourth failed authentication in primary sequence | Observed | High |
| Event ID | `EVT-001008` | Fifth failed authentication; detection threshold reached | Observed | High |
| Event ID | `EVT-001009` | Sixth failed authentication | Observed | High |
| Event ID | `EVT-001010` | Seventh failed authentication | Observed | High |
| Event ID | `EVT-001011` | Eighth failed authentication | Observed | High |
| Event ID | `EVT-001012` | Successful root authentication following eight failures | Observed | High |

---

## 3. Primary Network Indicator

### IPv4 Address

**Indicator:** `198.51.100.25`

**Type:** IPv4 address

**Role:** Source IP

**Observed behavior:**

The address generated eight failed SSH authentication attempts against the `root` account and was subsequently associated with a successful SSH authentication.

**Supporting events:**

- `EVT-001004`
- `EVT-001005`
- `EVT-001006`
- `EVT-001007`
- `EVT-001008`
- `EVT-001009`
- `EVT-001010`
- `EVT-001011`
- `EVT-001012`

**Evidence classification:** Observed evidence

**Assessment:** Suspicious in the context of CASE-001.

**Confidence:** High

**Important limitation:**

The telemetry establishes that the address was recorded as the source IP of the authentication events. It does not establish the identity of the person or system controlling that address.

---

## 4. Primary Account Indicator

### Username

**Indicator:** `root`

**Type:** Username / privileged account

**Role:** Target account

**Observed behavior:**

The account received eight failed SSH authentication attempts from `198.51.100.25`, followed by a successful SSH authentication.

**Supporting events:**

- `EVT-001004`
- `EVT-001005`
- `EVT-001006`
- `EVT-001007`
- `EVT-001008`
- `EVT-001009`
- `EVT-001010`
- `EVT-001011`
- `EVT-001012`

**Evidence classification:** Observed evidence

**Assessment:** High-priority account context because `root` represents a privileged account in the laboratory scenario.

**Confidence:** High

**Important limitation:**

The successful authentication does not independently prove that the account was compromised.

---

## 5. Protocol Indicator

### SSH

**Indicator:** `SSH`

**Type:** Network / authentication protocol

**Role:** Protocol associated with the authentication events

**Observed behavior:**

The primary sequence consists of repeated failed SSH authentication attempts followed by successful SSH authentication.

**Evidence classification:** Observed evidence

**Confidence:** High

---

## 6. Host Indicator

### `lab-auth-01`

**Indicator:** `lab-auth-01`

**Type:** Hostname

**Role:** Authentication server / monitored laboratory host

**Observed behavior:**

The primary authentication events are associated with this host.

**Evidence classification:** Observed evidence

**Confidence:** High

---

## 7. Event Indicators

The following event IDs are retained as evidence references rather than standalone malicious indicators.

### Failed Authentication Sequence

- `EVT-001004`
- `EVT-001005`
- `EVT-001006`
- `EVT-001007`
- `EVT-001008`
- `EVT-001009`
- `EVT-001010`
- `EVT-001011`

These events collectively establish the eight-failure authentication sequence.

### Successful Authentication

- `EVT-001012`

This event is particularly important because it records successful authentication for `root` from the same source IP following the repeated failures.

---

## 8. Detection Indicator

### DET-AUTH-001

**Detection ID:** `DET-AUTH-001`

**Name:** SSH Brute-Force Authentication Detection

**Detection condition:**

Five or more failed SSH authentication attempts for the same source IP and user within five minutes.

**Observed case value:**

- Threshold: `5`
- Observed failures: `8`
- Window: `5 minutes`
- Source IP: `198.51.100.25`
- User: `root`

**Evidence classification:** Detection logic / analytical artifact

**Assessment:** Detection condition satisfied.

---

## 9. Alert Indicator

### ALERT-CASE-001-DET-AUTH-001

**Alert ID:** `ALERT-CASE-001-DET-AUTH-001`

**Severity:** High

**Confidence:** High

**Status:** Open

**Evidence classification:** Observed evidence generated by the detection pipeline.

**Reason for alert:**

Eight failed SSH authentication attempts were observed for `root` from `198.51.100.25` within the configured detection window, followed by a successful authentication.

---

## 10. Indicators Not Present

The current CASE-001 telemetry does **not** provide evidence for:

- File hashes
- Malware hashes
- Domain names
- URLs
- File paths
- Process names
- Command lines
- Persistence artifacts
- Registry indicators
- Malware filenames
- User-agent strings
- Email addresses
- Cryptographic certificates

These fields must not be populated without supporting evidence.

---

## 11. Indicator Handling Guidance

### Observed

Directly represented in the laboratory telemetry.

Examples:

- `198.51.100.25`
- `root`
- `lab-auth-01`
- `SSH`
- `EVT-001004` through `EVT-001012`

### Analyst Interpretation

Indicators that become suspicious because of their relationship to other observed evidence.

Example:

> `198.51.100.25` is suspicious in CASE-001 because it generated eight failed SSH authentication attempts against `root` followed by a successful authentication.

### Hypothesis

Potential explanations that require further evidence.

Example:

> The source may represent an unauthorized authentication attempt that resulted in valid credentials being accepted.

This remains a hypothesis until additional evidence confirms authorization status and post-authentication activity.

---

## 12. Recommended Correlation

Future investigation should correlate the primary indicators against available authorized laboratory telemetry.

Priority correlation targets:

1. `198.51.100.25`
2. `root`
3. `lab-auth-01`
4. `EVT-001012`
5. Authentication activity immediately following `EVT-001012`
6. Endpoint process activity after the successful authentication
7. Network activity associated with the authenticated session
8. Account or privilege changes
9. File modifications
10. Persistence-related activity

Correlation results should be documented as new observed evidence rather than retroactively added to this indicator record.

---

## 13. Indicator Assessment

### Primary Indicator

`198.51.100.25` is the primary indicator associated with the detected authentication sequence.

### Primary Target

`root` is the primary account targeted in the observed sequence.

### Key Evidence Event

`EVT-001012` is the highest-priority event for follow-up because it records successful authentication after the repeated failure sequence.

### Current Determination

The indicators support classification of CASE-001 as:

**Suspicious authentication activity requiring further investigation.**

They do not, by themselves, establish confirmed account compromise.

---

## 14. Evidence References

Primary telemetry:

`telemetry/authentication/CASE-001-authentication-events.jsonl`

Detection:

`detections/authentication/DET-AUTH-001-ssh-brute-force.yml`

Generated alert:

`alerts/CASE-001-DET-AUTH-001.json`

Preserved case alert:

`cases/CASE-001/alert.json`

Timeline:

`cases/CASE-001/timeline.md`

Case record:

`cases/CASE-001/README.md`
