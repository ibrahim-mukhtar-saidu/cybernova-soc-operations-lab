# CASE-004 — Indicators and Evidence

## 1. Document Control

| Field | Value |
|---|---|
| Case ID | CASE-004 |
| Alert ID | ALERT-CASE-004-DET-AUTH-003 |
| Detection | DET-AUTH-003 |
| Detection Name | Suspicious Post-Authentication Privileged Session |
| Severity | High |
| Confidence | High |
| Host | lab-linux-01 |
| User | admin |
| Session | SES-004-C |
| Evidence Classification | Observed Evidence |
| Environment | Synthetic authorized SOC laboratory |

---

## 2. Purpose

This document records the indicators, identifiers, observable artifacts, and supporting evidence associated with CASE-004.

The purpose is to provide a structured evidence reference for investigation, threat hunting, correlation, response planning, and final reporting.

Indicators in this document are not automatically classified as malicious. Each item is accompanied by an evidence classification and analyst context where appropriate.

---

## 3. Evidence Classification

### Observed Evidence

Observed evidence consists of values directly represented in the synthetic CASE-004 telemetry or generated detection alert.

Examples include:

- source IP address
- host
- username
- session identifier
- authentication event identifiers
- command execution event identifiers
- executed commands
- alert identifier
- detection identifier

### Analyst Interpretation

Analyst interpretation explains what the observed evidence may indicate.

Interpretation does not convert an observable value into a confirmed malicious indicator.

### Hypothesis

A hypothesis is a possible explanation that requires additional validation.

### Confirmed Finding

A confirmed finding requires sufficient evidence to support the conclusion.

For CASE-004, suspicious activity is confirmed as observed telemetry behavior, but account compromise or malicious intent is not independently confirmed.

---

## 4. Primary Network Indicator

### Source IP

**Indicator:** `198.51.100.60`

| Attribute | Value |
|---|---|
| Indicator type | IPv4 source address |
| Source | Authentication telemetry |
| Associated host | lab-linux-01 |
| Associated user | admin |
| Protocol | SSH |
| Port | 22 |
| Authentication method | Password |
| Classification | Documentation/test range |
| Evidence status | Observed evidence |

### Interpretation

The source address `198.51.100.60` is the source associated with the suspicious authentication sequence.

It must not be treated as a real-world malicious IP address. The address belongs to a documentation/test range and is used to represent an external test source inside the authorized laboratory.

The security significance comes from the observed authentication sequence rather than from the reputation of the IP address.

---

## 5. Host Indicator

**Host:** `lab-linux-01`

| Attribute | Value |
|---|---|
| Indicator type | Host identifier |
| Hostname | lab-linux-01 |
| Operating system context | Linux |
| User involved | admin |
| Session | SES-004-C |
| Classification | Lab asset |
| Evidence status | Observed evidence |

### Interpretation

The host is the Linux laboratory endpoint on which the suspicious authentication and subsequent session activity were observed.

The hostname identifies the affected laboratory asset but does not independently establish compromise.

---

## 6. Account Indicator

**Username:** `admin`

| Attribute | Value |
|---|---|
| Indicator type | User/account identifier |
| Username | admin |
| Host | lab-linux-01 |
| Authentication protocol | SSH |
| Authentication method | Password |
| Privileged context | Yes |
| Session | SES-004-C |
| Evidence status | Observed evidence |

### Interpretation

The `admin` account is significant because the observed session involved privileged activity.

The account name alone does not establish unauthorized access. Authorization and ownership must be verified against the expected laboratory activity.

---

## 7. Session Indicator

**Session ID:** `SES-004-C`

| Attribute | Value |
|---|---|
| Indicator type | Session identifier |
| Host | lab-linux-01 |
| User | admin |
| Source IP | 198.51.100.60 |
| Authentication event | EVT-004007 |
| Session start | EVT-004008 |
| Post-authentication commands | EVT-004009 through EVT-004012 |
| Evidence status | Observed evidence |

### Interpretation

`SES-004-C` provides the primary correlation key connecting the successful authentication to the subsequent session and command execution activity.

This correlation is important because the detection is based on behavior occurring after authentication rather than on authentication failures alone.

---

## 8. Authentication Event Indicators

The suspicious authentication sequence contains four failed authentication events followed by a successful authentication.

### Failed Authentication Events

| Event ID | Role | Source IP | User | Action | Status |
|---|---|---|---|---|---|
| EVT-004003 | Failed authentication | 198.51.100.60 | admin | login_failure | failure |
| EVT-004004 | Failed authentication | 198.51.100.60 | admin | login_failure | failure |
| EVT-004005 | Failed authentication | 198.51.100.60 | admin | login_failure | failure |
| EVT-004006 | Failed authentication | 198.51.100.60 | admin | login_failure | failure |

### Successful Authentication

| Event ID | Role | Source IP | User | Action | Status | Session |
|---|---|---|---|---|---|---|
| EVT-004007 | Successful authentication | 198.51.100.60 | admin | login_success | success | SES-004-C |

### Interpretation

The sequence of four failed password authentication attempts followed by a successful authentication is the authentication component of the DET-AUTH-003 correlation.

This pattern is suspicious but does not independently prove credential compromise.

---

## 9. Session Establishment Indicator

**Event:** `EVT-004008`

| Attribute | Value |
|---|---|
| Event type | session_start |
| User | admin |
| Host | lab-linux-01 |
| Source IP | 198.51.100.60 |
| Session ID | SES-004-C |
| Privilege context | admin |
| Evidence status | Observed evidence |

### Interpretation

The session-start event establishes continuity between the successful authentication and the subsequent command execution events.

---

## 10. Post-Authentication Command Indicators

Four command execution events were correlated with session `SES-004-C`.

### EVT-004009

**Command:** `whoami`

Purpose represented by telemetry:

- identity verification
- account context discovery

Classification:

- Observed evidence

MITRE context:

- T1033 — System Owner/User Discovery

### EVT-004010

**Command:** `id`

Purpose represented by telemetry:

- user identity and group information
- privilege/group enumeration

Classification:

- Observed evidence

MITRE context:

- T1087 — Account Discovery
- T1069.001 — Permission Groups Discovery: Local

### EVT-004011

**Command:** `sudo -l`

Purpose represented by telemetry:

- privilege capability enumeration
- checking available sudo permissions

Classification:

- Observed evidence

MITRE context:

- T1069.001 — Permission Groups Discovery: Local

### EVT-004012

**Command:** `uname -a`

Purpose represented by telemetry:

- system information discovery

Classification:

- Observed evidence

MITRE context:

- T1082 — System Information Discovery

---

## 11. Privileged Activity Indicators

The detection identified the following privileged activity indicators:

- `id`
- `sudo -l`

These commands are not inherently malicious.

They are significant in CASE-004 because they occurred during the correlated privileged session following the suspicious authentication sequence.

### Analyst Interpretation

The commands are consistent with account and privilege enumeration.

An analyst should determine whether this behavior was expected for the `admin` account and whether it matches the authorized laboratory scenario.

---

## 12. Supporting Event Set

The complete supporting evidence set for the generated alert is:

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

Total supporting events:

10

These events represent:

four failed authentication attempts
one successful authentication
one correlated session start
four post-authentication command executions
13. Alert Indicator

Alert ID: ALERT-CASE-004-DET-AUTH-003

Attribute	Value
Detection	DET-AUTH-003
Severity	High
Confidence	High
Status	Open
Host	lab-linux-01
User	admin
Source IP	198.51.100.60
Session	SES-004-C
Failed authentications	4
Post-auth commands	4
Privileged indicators	id, sudo -l
14. Detection Correlation

DET-AUTH-003 correlated the following behavioral sequence:

4 failed password authentications
            |
            v
successful password authentication
            |
            v
session start
            |
            v
post-authentication commands
            |
            +---- whoami
            |
            +---- id
            |
            +---- sudo -l
            |
            +---- uname -a

The sequence was associated with:

Source IP: 198.51.100.60
User:      admin
Host:      lab-linux-01
Session:   SES-004-C
15. MITRE ATT&CK Context

The detection specification maps the observed behavior to the following techniques:

Technique	Name	Relevance
T1110	Brute Force	Four failed authentication attempts preceded successful authentication
T1078	Valid Accounts	Successful authentication using the admin account
T1087	Account Discovery	id command provides account/group context
T1069.001	Permission Groups Discovery: Local	id and sudo -l provide privilege/group information
T1059.004	Unix Shell	Post-authentication shell command execution

These mappings describe behavioral relationships and should not be interpreted as proof that a specific adversary technique was used.

16. Indicators That Are Not Malicious by Themselves

The following values should not be automatically classified as malicious:

198.51.100.60
lab-linux-01
admin
SES-004-C
whoami
id
sudo -l
uname -a

Their significance comes from their relationship within the observed event sequence.

This distinction prevents the case from incorrectly treating normal administrative artifacts as standalone indicators of compromise.

17. False Positive Considerations

Potential legitimate explanations include:

authorized administrator troubleshooting
password entry mistakes
administrative account verification
routine privilege enumeration
approved security testing
authorized laboratory exercises

The investigation should therefore verify:

whether the authentication was expected
whether the source IP belongs to an authorized test actor
whether the admin account was expected to authenticate at the observed time
whether the commands were part of an approved activity
whether additional telemetry supports or contradicts the suspicious interpretation
18. Investigation Gaps

The current evidence does not establish:

whether the credentials were compromised
who controlled the source system
whether the successful authentication was authorized
whether any credentials were exposed or reused
whether additional commands occurred outside the supplied telemetry
whether persistence was established
whether files were modified
whether network connections occurred after authentication
whether the session continued beyond the supplied observation window

These gaps should remain explicit in the case record.

19. IOC Handling Guidance

Because the network addresses in this case are documentation/test ranges, they should be handled as laboratory indicators, not submitted to external reputation systems as suspected real-world malicious infrastructure.

If this workflow were adapted to real authorized telemetry, the analyst could enrich indicators using approved threat-intelligence sources.

For this laboratory case, enrichment should remain clearly separated from observed evidence.

20. Current Indicator Assessment
Observed Evidence

The case contains:

source IP 198.51.100.60
host lab-linux-01
user admin
session SES-004-C
four failed authentication events
one successful authentication event
one correlated session-start event
four post-authentication command events
privileged activity indicators id and sudo -l
Analyst Interpretation

The evidence represents a suspicious authentication-to-session sequence involving a privileged account and subsequent enumeration activity.

Hypothesis

The activity could represent unauthorized credential use followed by account and privilege discovery.

Alternative explanations include authorized administration or security testing.

Confirmed Finding

Suspicious activity observed.

Compromise status: Not confirmed.

The evidence is sufficient to support escalation for additional investigation, but not sufficient to establish malicious intent or confirmed account compromise.

21. Evidence Integrity Note

All indicators and event identifiers in this document originate from the synthetic CASE-004 dataset and generated detection artifacts in the authorized CYBERNOVA SOC laboratory.

The IP address 198.51.100.60 is a documentation/test address.

No indicator in this document should be interpreted as a claim that the associated address, hostname, account, or command represents real-world malicious infrastructure or activity.

All analyst interpretations are explicitly separated from observed evidence.
