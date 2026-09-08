# CASE-001 — Threat Intelligence Assessment

## 1. Purpose

This document records the threat-intelligence assessment for CASE-001.

The objective is to determine what threat-intelligence conclusions can reasonably be drawn from the available indicators and to document the limitations of intelligence enrichment in an authorized laboratory environment.

Threat intelligence is used as contextual evidence and must not be treated as proof of malicious activity without sufficient supporting evidence.

---

## 2. Intelligence Scope

The primary indicators considered for enrichment are:

- IPv4 address: `198.51.100.25`
- Username: `root`
- Hostname: `lab-auth-01`
- Protocol: SSH
- Detection: `DET-AUTH-001`
- Alert: `ALERT-CASE-001-DET-AUTH-001`

The investigation also considers the authentication event sequence:

- `EVT-001004` through `EVT-001011` — failed authentication attempts
- `EVT-001012` — successful authentication

---

## 3. Intelligence Classification

The indicators in this case are primarily **laboratory observables** rather than externally attributable threat indicators.

The source IP `198.51.100.25` is used within the authorized laboratory scenario as a documentation/test address.

Therefore:

- External malicious-IP attribution is not used as evidence.
- Reputation-based conclusions are not used to establish maliciousness.
- The source IP should not be represented as a confirmed real-world malicious infrastructure indicator.
- The authentication behavior itself remains the primary evidence for the case.

---

## 4. Primary Indicator — Source IP

### Indicator

`198.51.100.25`

### Type

IPv4 address

### Role

Source IP associated with the primary authentication sequence.

### Observed Case Activity

The address was associated with:

- Eight failed SSH authentication attempts against `root`.
- A subsequent successful SSH authentication.
- The successful authentication recorded as `EVT-001012`.

### Intelligence Assessment

The address is suspicious **within the context of CASE-001** because of its observed behavior.

The investigation does not classify the address as globally malicious based solely on this laboratory scenario.

### Intelligence Confidence

**High for case correlation**

**Not established for real-world attribution**

---

## 5. Documentation/Test Address Consideration

The address `198.51.100.25` belongs to the IPv4 documentation range reserved for examples and documentation.

Within this laboratory project, it represents simulated source infrastructure.

This distinction is important because a professional analyst must avoid treating synthetic or documentation indicators as live threat infrastructure.

### Analyst Rule

A laboratory indicator may demonstrate:

- detection logic,
- investigation workflow,
- correlation,
- enrichment methodology,
- reporting quality,
- and evidence handling.

It must not be presented as evidence that a real-world threat actor controlled the address.

---

## 6. Account Intelligence

### Indicator

`root`

### Type

Privileged username

### Intelligence Relevance

`root` is a high-value account context because successful unauthorized access to a privileged account can have significant security implications.

However, the username itself is not a threat indicator.

The username becomes significant because of its relationship with the observed authentication sequence.

### Observed Relationship

`198.51.100.25` → repeated SSH failures → `root` → successful authentication

### Assessment

**High investigative relevance**

The account should be prioritized for validation of authorization and subsequent activity.

---

## 7. Host Intelligence

### Indicator

`lab-auth-01`

### Type

Laboratory host

### Role

Authentication target associated with CASE-001.

### Intelligence Relevance

The host provides the environmental context required to correlate authentication activity with additional endpoint and network evidence.

### Assessment

The host should be treated as the primary investigation asset for subsequent correlation.

---

## 8. Protocol Intelligence

### Indicator

SSH

### Type

Remote administration/authentication protocol

### Relevance

SSH is commonly used for legitimate remote administration and can also be targeted by credential attacks.

Therefore, SSH usage alone is not malicious.

The intelligence significance comes from the combination of:

- repeated failures,
- same source,
- same privileged account,
- threshold violation,
- and subsequent successful authentication.

### Assessment

**Suspicious in context; not inherently malicious.**

---

## 9. Event-Level Intelligence

The following events represent the primary intelligence sequence:

### Failed Authentication Sequence

- `EVT-001004`
- `EVT-001005`
- `EVT-001006`
- `EVT-001007`
- `EVT-001008`
- `EVT-001009`
- `EVT-001010`
- `EVT-001011`

These events establish repeated authentication failures.

### Successful Authentication

- `EVT-001012`

This event establishes that successful authentication was observed after the failure sequence.

### Intelligence Significance

The sequence provides behavioral context that is more useful than evaluating any single indicator independently.

---

## 10. Threat Behavior Assessment

The observed behavior is consistent with a possible password-guessing or brute-force pattern.

Relevant characteristics include:

1. Repeated authentication failures.
2. Consistent source IP.
3. Consistent target account.
4. SSH remote-access protocol.
5. Threshold exceeded.
6. Successful authentication following the failures.

This behavior is mapped by the detection to:

**MITRE ATT&CK T1110 — Brute Force**

and:

**T1110.001 — Password Guessing**

The mapping describes the observed behavior pattern and does not independently identify an attacker.

---

## 11. External Intelligence Enrichment

For a production investigation, an analyst could enrich an external IP indicator using authorized threat-intelligence sources.

Potential enrichment categories include:

- IP reputation
- Autonomous System information
- ASN ownership
- Geolocation
- Passive DNS
- Domain relationships
- Historical abuse reports
- Malware infrastructure associations
- Known command-and-control associations
- Threat-actor infrastructure relationships
- Historical sightings

For CASE-001, external enrichment is intentionally not used as evidence because the source address represents laboratory test infrastructure.

---

## 12. Intelligence Requirements for a Real Investigation

If the same behavior occurred in a real environment, the following intelligence questions should be answered:

### IR-001 — Source Ownership

Who owns or operates the source IP?

### IR-002 — Historical Reputation

Has the source IP previously been associated with malicious activity?

### IR-003 — Infrastructure Relationships

Is the source IP associated with domains, certificates, hosts, or other infrastructure?

### IR-004 — Targeting Pattern

Has the source targeted other accounts or systems?

### IR-005 — Temporal Activity

Does the source show activity against the organization before or after the observed authentication event?

### IR-006 — Threat-Actor Association

Is there credible intelligence linking the infrastructure to a known threat actor or campaign?

### IR-007 — Credential Abuse

Is there evidence that the successful authentication involved compromised credentials?

---

## 13. Intelligence Confidence Model

Threat-intelligence confidence for CASE-001 is divided into separate dimensions.

| Assessment | Confidence | Reason |
|---|---|---|
| Source IP observed in authentication telemetry | High | Direct laboratory telemetry |
| Eight failed SSH attempts occurred | High | Direct event evidence |
| Successful authentication occurred | High | Direct event evidence |
| Activity is suspicious in case context | High | Multiple correlated observations |
| Brute-force behavior is plausible | High | Detection threshold and sequence support assessment |
| Source IP is globally malicious | Not established | Laboratory documentation address |
| Account compromise occurred | Not established | No endpoint or identity evidence |
| Threat actor attribution | Not established | No attribution evidence |
| Credential theft occurred | Not established | No credential-access evidence beyond authentication pattern |

---

## 14. Intelligence Gaps

The current case contains several intelligence gaps.

### Gap G-001

No real-world reputation information is applicable to the laboratory source address.

### Gap G-002

No evidence identifies the operator behind the source IP.

### Gap G-003

No evidence establishes how the successful credentials were obtained.

### Gap G-004

No endpoint telemetry is currently available to determine post-authentication activity.

### Gap G-005

No network telemetry is currently available to identify subsequent connections.

### Gap G-006

No identity-management context is available to confirm whether the login was authorized.

### Gap G-007

No threat-actor attribution evidence is available.

These gaps prevent the investigation from progressing from suspicious activity to confirmed compromise or attribution.

---

## 15. Recommended Intelligence Correlation

The following correlation activities are recommended:

1. Search for `198.51.100.25` across all available laboratory telemetry.
2. Search for all activity involving `root`.
3. Search for authentication activity against other hosts from the same source.
4. Search for other source IPs targeting `root`.
5. Correlate `EVT-001012` with endpoint activity.
6. Correlate `EVT-001012` with network activity.
7. Review activity immediately before and after the successful authentication.
8. Compare the activity with known authorized administrative behavior.
9. Record any additional indicators discovered during correlation.
10. Update the case intelligence assessment if new evidence changes confidence.

---

## 16. Intelligence Handling Rules

Indicators discovered during the investigation should be handled according to their evidence status.

### Observed Indicator

Directly present in authorized telemetry.

Example:

`198.51.100.25`

### Enriched Indicator

An observed indicator that has been supplemented with external or internal intelligence.

Example:

An IP address associated with a documented threat campaign in a real investigation.

### Analyst Interpretation

An assessment derived from multiple indicators.

Example:

The authentication sequence is suspicious.

### Hypothesis

A possible explanation that requires additional evidence.

Example:

The successful authentication may represent unauthorized credential use.

### Confirmed Finding

A conclusion directly supported by sufficient evidence.

Example:

Eight failed SSH authentication attempts occurred before `EVT-001012`.

---

## 17. False-Positive Considerations

Threat intelligence should not override environmental context.

Possible benign explanations include:

- Authorized administrator testing.
- Incorrect credentials.
- Misconfigured automation.
- Scheduled tasks using outdated credentials.
- Security testing.
- Maintenance activity.

External reputation, even when available, should be considered alongside organizational context.

A source with a poor reputation does not automatically prove that a particular authentication event was malicious.

Similarly, a source without a negative reputation does not prove that an authentication event was legitimate.

---

## 18. Intelligence-Driven Investigation Priorities

Based on current evidence, investigation priorities are:

### Priority 1 — Successful Authentication

Investigate `EVT-001012` because it represents the transition from repeated failure to successful access.

### Priority 2 — Source Correlation

Search for other activity involving `198.51.100.25`.

### Priority 3 — Privileged Account Review

Determine whether the `root` authentication was expected and authorized.

### Priority 4 — Post-Authentication Activity

Identify any process, command, file, or network activity following the successful login.

### Priority 5 — Detection Improvement

Determine whether additional telemetry could improve confidence and reduce investigation time.

---

## 19. Intelligence Assessment

The available intelligence supports the following conclusion:

`198.51.100.25` is a high-confidence case indicator because it is directly associated with the observed authentication sequence.

The observed behavior is suspicious and consistent with a possible brute-force authentication attempt followed by successful credential use.

However, the source IP is a laboratory documentation/test address and should not be presented as real-world malicious infrastructure.

No threat-actor attribution is established.

No credential theft is established.

No account compromise is confirmed.

---

## 20. Intelligence-Driven Determination

### Current Determination

**Suspicious authentication behavior requiring continued investigation.**

### Threat Intelligence Status

**Contextual intelligence available; real-world attribution not established.**

### Source Reputation Status

**Not applicable as proof of maliciousness in this laboratory scenario.**

### Account Compromise Status

**Not confirmed.**

### Threat Actor Attribution

**Not established.**

### Confidence

**High confidence in the observed authentication behavior.**

**Low/undetermined confidence regarding malicious attribution or compromise.**

---

## 21. Intelligence Update Conditions

This document should be updated if new evidence provides:

- endpoint telemetry,
- network telemetry,
- identity-management records,
- additional authentication events,
- additional source indicators,
- confirmed authorization context,
- or credible external intelligence applicable to a real-world indicator.

Any update should preserve the distinction between original observations and newly obtained intelligence.

---

## 22. Evidence References

### Primary Telemetry

- `telemetry/authentication/CASE-001-authentication-events.jsonl`

### Detection

- `detections/authentication/DET-AUTH-001-ssh-brute-force.yml`

### Alert

- `alerts/CASE-001-DET-AUTH-001.json`
- `cases/CASE-001/alert.json`

### Case Investigation

- `cases/CASE-001/README.md`
- `cases/CASE-001/timeline.md`
- `cases/CASE-001/indicators.md`
- `cases/CASE-001/investigation.md`

### Governance

- `docs/evidence-integrity.md`
- `docs/limitations.md`
- `docs/threat-model.md`

---

## 23. Final Threat Intelligence Statement

CASE-001 demonstrates how threat intelligence should be applied to a controlled SOC investigation without overstating the available evidence.

The primary source IP, `198.51.100.25`, is a laboratory indicator associated with repeated SSH authentication failures and a subsequent successful authentication against `root`.

The behavioral pattern is suspicious and appropriately mapped to brute-force activity.

The laboratory source address must not be represented as confirmed malicious infrastructure, and no threat actor or compromise should be inferred without additional evidence.

The most valuable next intelligence step is correlation of the successful authentication event `EVT-001012` with endpoint, identity, and network telemetry.

**Threat intelligence determination: Behavioral indicators support continued investigation; malicious attribution and compromise remain unconfirmed.**
