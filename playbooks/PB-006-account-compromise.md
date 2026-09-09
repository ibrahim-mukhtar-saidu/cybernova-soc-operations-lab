# PB-006 — Account Compromise Response Playbook

**Playbook ID:** PB-006
**Playbook Name:** Account Compromise
**Status:** Implemented
**Primary Detection:** DET-AUTH-003
**Related Flagship Case:** CASE-004
**Severity:** High
**Environment:** CYBERNOVA SOC Operations Laboratory
**Purpose:** Defensive SOC investigation and response workflow for suspicious authentication-to-session activity involving potentially compromised accounts.

---

## 1. Purpose

This playbook defines the investigation and response workflow for suspected account compromise.

It is designed for situations where authentication telemetry indicates a suspicious sequence such as:

1. Multiple failed authentication attempts.
2. Successful authentication.
3. Correlated session establishment.
4. Post-authentication activity.
5. Privileged or administrative activity.

The playbook provides a repeatable workflow for:

* alert validation;
* authentication analysis;
* account validation;
* source-IP analysis;
* session investigation;
* privileged-activity analysis;
* evidence preservation;
* timeline reconstruction;
* indicator extraction;
* threat-intelligence enrichment;
* MITRE ATT&CK mapping;
* containment;
* eradication;
* recovery;
* detection validation;
* threat hunting;
* escalation;
* closure;
* lessons learned;
* detection-engineering feedback.

This playbook is intentionally laboratory-focused.

It does not claim that the detection proves an account was compromised.

---

## 2. Scope

This playbook applies to suspicious account activity observed through authentication and session telemetry.

Primary detection:

`DET-AUTH-003`

Detection name:

`Suspicious Post-Authentication Privileged Session`

Related case:

`CASE-004`

The workflow covers:

* authentication failures;
* successful authentication;
* source IP;
* target account;
* host;
* session ID;
* session start;
* command execution;
* privileged indicators;
* account discovery;
* permission discovery;
* Unix shell activity;
* related authentication detections;
* endpoint telemetry;
* network telemetry;
* persistence telemetry;
* identity validation.

---

## 3. Laboratory Boundary

All examples and procedures in this playbook are intended for authorized defensive laboratory environments.

The laboratory must use:

* synthetic telemetry;
* test accounts;
* controlled hosts;
* non-production IP addresses;
* synthetic indicators;
* authorized security-testing activity.

Do not use this playbook to access accounts, hosts, credentials, or systems without authorization.

No real passwords, API keys, authentication tokens, personal information, or production credentials should be placed in the repository.

---

## 4. Detection Trigger

PB-006 is triggered when `DET-AUTH-003` identifies a suspicious post-authentication sequence.

The current detector requires:

* a successful authentication;
* at least four failed authentication attempts;
* matching source IP;
* matching user;
* a correlated session start;
* at least two command executions;
* at least one privileged-activity indicator;
* correlation within the configured five-minute window.

Current detection constants:

```text
DETECTION_AUTH_003 = DET-AUTH-003
DETECTION_AUTH_003_VERSION = 1.0
AUTH_003_MIN_FAILURES = 4
AUTH_003_MIN_COMMANDS = 2
AUTH_003_WINDOW_MINUTES = 5
```

---

## 5. Detection Logic Summary

The detection evaluates successful authentication events.

For each successful authentication, the engine searches backward for failed authentication events matching:

* source IP;
* user;
* detection time window.

The engine then searches forward for:

* a matching session-start event;
* matching source IP;
* matching user;
* matching session ID;
* command-execution events;
* privileged activity indicators.

An alert is produced only when the required correlation conditions are satisfied.

---

## 6. Alert Validation

Before beginning investigation, validate the alert itself.

Confirm:

* alert ID exists;
* detection ID is `DET-AUTH-003`;
* detection name is correct;
* detection version is present;
* status is present;
* severity is present;
* confidence is present;
* host is present;
* user is present;
* source IP is present;
* session ID is present;
* authentication counts are present;
* supporting event IDs are present;
* first-seen timestamp is present;
* last-seen timestamp is present;
* MITRE ATT&CK metadata is present.

Do not begin containment solely because an alert exists.

First determine whether the telemetry is internally consistent.

---

## 7. Expected CASE-004 Alert

CASE-004 contains:

```text
alert_id:
ALERT-CASE-004-DET-AUTH-003

detection_id:
DET-AUTH-003

detection_name:
Suspicious Post-Authentication Privileged Session

severity:
high

confidence:
high

source_ip:
198.51.100.60

host:
lab-linux-01

user:
admin

failed_authentication_count:
4

successful_authentication_event_id:
EVT-004007

session_start_event_id:
EVT-004008

post_authentication_command_count:
4

privileged_activity_indicators:
id
sudo -l

session_id:
SES-004-C

correlation_window_minutes:
5
```

These values describe the laboratory case and must not be represented as production activity.

---

## 8. Evidence Classification

Separate observed evidence from analyst interpretation.

### Observed evidence

Examples from CASE-004 include:

* four failed authentication attempts;
* successful authentication;
* session establishment;
* four post-authentication command events;
* command `id`;
* command `sudo -l`;
* source IP `198.51.100.60`;
* host `lab-linux-01`;
* user `admin`;
* session `SES-004-C`.

### Analyst interpretation

The sequence is suspicious because repeated authentication failures were followed by successful authentication and privileged-account activity.

This sequence is consistent with possible unauthorized account access.

It does not independently prove:

* credential theft;
* successful compromise;
* malicious intent;
* persistence;
* lateral movement;
* data theft;
* malware execution.

Those conclusions require additional evidence.

---

## 9. Severity Assessment

Default severity for this playbook is **High** when the alert contains:

* authentication anomalies;
* successful authentication;
* privileged account activity;
* correlated session activity.

Escalate toward critical handling when additional evidence establishes or strongly supports:

* confirmed unauthorized access;
* active attacker control;
* persistence;
* lateral movement;
* destructive activity;
* sensitive-data access;
* multiple compromised accounts;
* multiple affected hosts.

Do not automatically label every suspicious authentication sequence as a confirmed compromise.

---

## 10. Confidence Assessment

High detector confidence means the telemetry satisfied the detector's correlation requirements.

It does not mean:

> "The account is definitely compromised."

Confidence in the detection and confidence in the incident conclusion are separate concepts.

Record both appropriately.

---

## 11. Data Quality Validation

Check:

* timestamp validity;
* event ordering;
* source-IP consistency;
* user consistency;
* host consistency;
* session-ID consistency;
* event IDs;
* event types;
* command fields;
* missing fields;
* duplicate events.

If timestamps conflict, preserve the original values and document the discrepancy.

Do not silently rewrite evidence.

---

## 12. Source IP Validation

Investigate:

`198.51.100.60`

Determine:

* whether the address belongs to the expected laboratory source;
* whether it is associated with the account;
* whether it appears elsewhere in the case;
* whether other accounts use it;
* whether other hosts receive authentication from it;
* whether activity occurs outside the expected window.

In the laboratory, documentation may use reserved documentation addresses.

Do not represent these addresses as real-world malicious infrastructure.

---

## 13. Account Validation

Investigate the affected account.

Record:

* username;
* account type;
* privilege level;
* expected owner;
* expected use;
* expected source locations;
* normal login times;
* normal authentication methods;
* recent account changes;
* password changes;
* group membership;
* administrative privileges.

For CASE-004:

```text
user = admin
host = lab-linux-01
```

The account's authorization must be verified before declaring the activity malicious.

---

## 14. Authentication Investigation

Review all authentication events surrounding the alert.

Search backward for:

* failed logins;
* repeated failures;
* source-IP changes;
* username changes;
* authentication-method changes;
* unusual timing.

Search forward for:

* successful authentication;
* additional authentication;
* session establishment;
* privilege changes;
* commands.

---

## 15. Authentication Sequence

Construct the sequence:

```text
Failed authentication
        |
        v
Failed authentication
        |
        v
Failed authentication
        |
        v
Failed authentication
        |
        v
Successful authentication
        |
        v
Session established
        |
        v
Post-authentication commands
        |
        v
Privileged activity
```

The sequence is an investigation signal.

It is not by itself proof of compromise.

---

## 16. Successful Authentication Validation

Validate the successful authentication event:

`EVT-004007`

Check:

* timestamp;
* source IP;
* user;
* host;
* authentication method;
* event ID;
* relationship to failed events.

Confirm that the event belongs to the same authentication sequence.

---

## 17. Session Validation

Validate:

`EVT-004008`

Session:

`SES-004-C`

Confirm:

* session ID;
* user;
* source IP;
* host;
* timestamp;
* relationship to successful authentication.

A session ID mismatch should be treated as a correlation problem requiring investigation.

---

## 18. Command Investigation

CASE-004 contains four post-authentication command events.

The commands include privileged indicators:

```text
id
sudo -l
```

Investigate:

* complete command lines;
* timestamps;
* order;
* process information;
* parent process;
* terminal/session information;
* execution user;
* execution host;
* subsequent commands.

Do not investigate only the two commands explicitly named in the alert.

Review the complete session.

---

## 19. Privileged Activity Analysis

The presence of:

```text
id
sudo -l
```

indicates enumeration of identity and available privilege.

These commands are legitimate administrative commands and can occur during normal maintenance.

Their presence becomes more suspicious when combined with:

* repeated failed authentication;
* unexpected successful authentication;
* unexpected source IP;
* unexpected account use;
* unusual timing;
* subsequent privilege escalation;
* persistence;
* lateral movement.

---

## 20. False Positive Review

Potential legitimate explanations include:

* administrator mistyped a password;
* automated administrative tooling generated failures;
* password manager supplied an outdated password;
* legitimate administrator accessed the host;
* system automation authenticated repeatedly;
* administrator checked privileges;
* scheduled maintenance occurred.

Document the expected explanation if verified.

Never close an alert merely because the commands are common administrative commands.

---

## 21. False Positive Decision

Classify the case as:

### Benign

Use only when sufficient evidence confirms authorized activity.

### Suspicious

Use when evidence remains incomplete or authorization cannot yet be established.

### Confirmed unauthorized access

Use only when reliable evidence establishes that access was not authorized.

### Confirmed compromise

Use only when evidence supports actual account compromise or attacker control.

---

## 22. Evidence Preservation

Preserve:

* original alert JSON;
* authentication logs;
* session logs;
* command logs;
* endpoint telemetry;
* network telemetry;
* account metadata;
* relevant configuration;
* timestamps;
* supporting event IDs;
* investigation notes;
* hashes of collected evidence where appropriate.

Preserve original evidence before modifying affected systems.

---

## 23. Evidence Integrity

Evidence should be:

* attributable;
* timestamped;
* preserved;
* reproducible;
* traceable to its source.

Never edit original telemetry to make the timeline easier to understand.

If normalization is required, create a separate analyst-normalized copy.

---

## 24. Timeline Construction

Build a chronological timeline.

Required fields:

| Time | Event ID | Event Type | User | Host | Source IP | Session | Analyst Note |
| ---- | -------- | ---------- | ---- | ---- | --------- | ------- | ------------ |

CASE-004 timeline begins with:

```text
2026-09-08T11:22:03+00:00
|
+-- authentication failures
|
+-- EVT-004007 successful authentication
|
+-- EVT-004008 session start
|
+-- EVT-004009 through EVT-004012 command activity
|
+-- 2026-09-08T11:24:19+00:00 last observed activity
```

The exact event ordering must be taken from the case evidence.

---

## 25. Indicators

Potential indicators include:

### Account

```text
admin
```

### Host

```text
lab-linux-01
```

### Source IP

```text
198.51.100.60
```

### Session

```text
SES-004-C
```

### Commands

```text
id
sudo -l
```

### Event IDs

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

Indicators must be classified as observed, derived, or analyst-generated.

---

## 26. Indicator Validation

Do not automatically classify every indicator as malicious.

For each indicator determine:

* observed or inferred;
* source;
* first seen;
* last seen;
* confidence;
* relationship to incident;
* whether it requires external enrichment.

Example:

```text
198.51.100.60
Observed source IP
Laboratory documentation address
No external maliciousness claim
```

---

## 27. Threat Intelligence

Threat intelligence may be used to enrich:

* source IPs;
* domains;
* hashes;
* usernames;
* infrastructure;
* known attack patterns.

However, external reputation must never override local evidence.

For laboratory indicators, clearly state that the value is synthetic or documentation-only.

Do not fabricate reputation results.

---

## 28. MITRE ATT&CK Mapping

CASE-004 maps to:

### T1110 — Brute Force

Supported by repeated authentication failures.

### T1078 — Valid Accounts

Potentially relevant to successful use of an account.

This mapping does not establish malicious use without supporting evidence.

### T1087 — Account Discovery

Relevant to `id`-style identity/account enumeration.

### T1069.001 — Permission Groups Discovery: Local

Relevant to:

```text
sudo -l
```

when interpreted as local privilege/permission enumeration.

### T1059.004 — Unix Shell

Relevant where Unix shell command execution is represented by the telemetry.

ATT&CK mappings should remain evidence-based.

---

## 29. Authentication Correlation

Correlate with:

* DET-AUTH-001;
* DET-AUTH-002;
* DET-AUTH-003.

Questions:

1. Was the source IP involved in brute-force activity?
2. Was password spraying observed?
3. Was the same account targeted elsewhere?
4. Were other accounts accessed?
5. Did successful authentication occur after failures?
6. Was the session followed by privileged activity?

---

## 30. Endpoint Correlation

Correlate the account activity with endpoint telemetry.

Look for:

* process execution;
* shell creation;
* suspicious binaries;
* persistence;
* file modifications;
* security-control changes;
* malware indicators;
* unusual parent/child relationships.

Potential related detections include:

* `DET-ENDPOINT-001`
* `DET-MALWARE-001`
* `DET-HOST-001`
* `DET-LINUX-001`

---

## 31. Network Correlation

Review network activity around the account session.

Look for:

* unusual outbound connections;
* new destinations;
* unusual ports;
* DNS activity;
* remote administration;
* lateral movement;
* command-and-control indicators.

Potential related detection:

`DET-NET-001`

Do not infer network compromise merely because a network connection exists.

---

## 32. Persistence Correlation

Review:

* cron;
* systemd;
* SSH configuration;
* authorized keys;
* shell profiles;
* startup scripts;
* scheduled jobs;
* newly created accounts;
* privilege changes.

Potential related detection:

`DET-LINUX-001`

A persistence finding significantly increases incident severity.

---

## 33. Account Compromise Decision Tree

```text
Suspicious authentication alert
          |
          v
Validate telemetry
          |
          v
Was successful authentication observed?
       /       \
     No         Yes
     |           |
Review auth     Validate session
activity            |
                    v
             Review commands
                    |
                    v
          Privileged activity?
              /          \
            No            Yes
            |              |
      Continue review   Validate authorization
                             |
                    +--------+--------+
                    |                 |
                 Authorized       Unauthorized
                    |                 |
                 Benign       Escalate/contain
```

---

## 34. Authorization Verification

Before containment where practical, establish:

* account owner;
* expected access;
* expected source;
* expected time;
* expected administrative task;
* approved change or maintenance window.

If authorization cannot be established and risk is high, escalate.

Do not delay urgent containment when strong evidence indicates active unauthorized access.

---

## 35. Containment

Potential containment actions in an authorized environment include:

* disable affected account;
* revoke active sessions;
* rotate credentials;
* revoke authentication keys;
* restrict source IP;
* isolate affected host;
* restrict network access;
* preserve evidence before destructive actions where feasible.

Containment must be proportionate to confidence and impact.

---

## 36. Credential Response

If compromise is confirmed or strongly suspected:

1. Preserve relevant evidence.
2. Disable or restrict the affected account.
3. Terminate unauthorized sessions.
4. Rotate credentials.
5. Rotate SSH keys where applicable.
6. Review group memberships.
7. Review privileged access.
8. Review authentication configuration.
9. Search for reuse of the same credentials or keys.

Never place recovered credentials into the repository.

---

## 37. Session Response

For active suspicious sessions:

* identify session;
* identify user;
* identify host;
* identify source;
* preserve relevant telemetry;
* determine current activity;
* determine whether privileged commands are executing;
* terminate session if authorized and required.

Record every response action.

---

## 38. Eradication

After containment:

* remove unauthorized keys;
* remove unauthorized accounts;
* remove persistence;
* reverse unauthorized configuration changes;
* remove malicious tooling where confirmed;
* repair modified security settings;
* rotate compromised credentials.

Do not delete evidence before preservation.

---

## 39. Recovery

Recovery should include:

* restoring normal authentication;
* validating account state;
* validating group memberships;
* confirming authorized keys;
* reviewing system integrity;
* confirming security controls;
* monitoring subsequent authentication activity.

Increase monitoring temporarily when justified by the evidence.

---

## 40. Post-Recovery Monitoring

Monitor for:

* repeated authentication failures;
* successful logins from unusual sources;
* new sessions;
* privilege escalation;
* suspicious commands;
* persistence;
* outbound connections;
* additional accounts showing similar behavior.

Correlate new activity against the original incident.

---

## 41. Threat Hunting

Hunt across the laboratory dataset for:

```text
same source IP
same username
same host
same session
same command
same authentication pattern
```

Expand the time window.

Look for:

* earlier failed authentication;
* later successful authentication;
* other targeted accounts;
* other hosts;
* other sessions;
* privilege changes;
* persistence.

---

## 42. Source-IP Hunting

Search all authentication events for:

```text
198.51.100.60
```

Determine:

* number of targeted accounts;
* number of hosts;
* first appearance;
* last appearance;
* successful authentications;
* related command activity.

Do not automatically label the IP malicious.

---

## 43. Account Hunting

Search for:

```text
admin
```

Across:

* authentication;
* sessions;
* commands;
* privilege changes;
* persistence;
* endpoint telemetry;
* network telemetry.

Identify whether the account was used elsewhere.

---

## 44. Password-Spraying Correlation

Check whether the source IP generated:

`DET-AUTH-002`

If multiple users were targeted, investigate whether the event represents:

* account-specific brute force;
* password spraying;
* credential stuffing;
* legitimate automation.

Avoid double-counting related alerts.

---

## 45. Brute-Force Correlation

Check for:

`DET-AUTH-001`

If present, establish:

* temporal relationship;
* source relationship;
* account relationship;
* successful-authentication relationship.

This can strengthen the authentication attack hypothesis.

---

## 46. Malware Correlation

Check:

`DET-MALWARE-001`

Questions:

* Was malware execution observed?
* Did malware execute under the affected account?
* Did execution occur after authentication?
* Are hashes available?
* Are YARA results available?
* Are process relationships available?

No malware claim should be made without evidence.

---

## 47. PowerShell Correlation

For Windows environments, check:

`DET-ENDPOINT-001`

Determine whether suspicious PowerShell activity occurred under the affected account.

The presence of PowerShell alone is not proof of malicious activity.

---

## 48. File Integrity Correlation

Check:

`DET-HOST-001`

Look for:

* modified system files;
* modified security configuration;
* modified authentication configuration;
* newly created scripts;
* unauthorized files.

---

## 49. Linux Persistence Correlation

Check:

`DET-LINUX-001`

Look for:

* suspicious cron jobs;
* download-and-execute behavior;
* unauthorized scheduled execution;
* persistence under the affected account.

If persistence is established, increase incident severity.

---

## 50. Adversarial Review

An attacker may attempt to evade this detection.

Potential evasion patterns include:

* fewer failed attempts;
* distributed attempts across IP addresses;
* slow authentication attempts;
* rotating usernames;
* rotating source addresses;
* successful authentication without preceding failures;
* session manipulation;
* command fragmentation;
* deleting logs;
* manipulating timestamps;
* avoiding obvious privileged commands.

The detector should therefore be treated as one detection layer rather than complete account-compromise coverage.

---

## 51. Detection Limitation — Low Failure Volume

The current detector requires four failed authentications.

An attacker using:

```text
1 failed attempt
1 successful attempt
```

may not trigger DET-AUTH-003.

Improvement:

* correlate additional identity signals;
* consider impossible-travel logic where appropriate;
* add risk-based authentication scoring;
* correlate endpoint and network anomalies.

---

## 52. Detection Limitation — Distributed Sources

An attacker may distribute authentication attempts across multiple source IPs.

Because the current correlation uses matching source IP and user, distributed activity may avoid this specific correlation.

Improvement:

* user-centric aggregation;
* source reputation;
* distributed authentication analytics;
* identity-risk scoring.

---

## 53. Detection Limitation — Legitimate Administration

Administrative users may legitimately:

* fail passwords;
* authenticate;
* establish sessions;
* run `id`;
* run `sudo -l`.

Therefore authorization validation remains mandatory.

---

## 54. Detection Limitation — Privilege Indicators

The current detector requires at least one privileged indicator.

Attackers can avoid known command patterns.

Improvement:

* behavioral privilege analytics;
* command sequence analysis;
* privilege-transition monitoring;
* unusual administrative action detection.

---

## 55. Timestamp Manipulation

Investigate timestamp integrity.

Check:

* source timestamps;
* ingestion timestamps;
* sequence ordering;
* impossible chronology;
* clock drift.

If timestamps appear manipulated or inconsistent, record the limitation.

Do not silently reorder evidence without documenting the reason.

---

## 56. Duplicate Events

Check for duplicated authentication and command events.

Duplicates can:

* inflate failure counts;
* inflate command counts;
* distort timelines;
* produce misleading confidence.

Where possible, identify duplicate event IDs or identical event fingerprints.

---

## 57. Evidence Deletion

A sophisticated attacker may attempt to remove logs.

Look for:

* gaps;
* logging-service restarts;
* log truncation;
* unusual administrative actions;
* audit configuration changes;
* timestamp discontinuities.

Absence of evidence is not evidence that activity did not occur.

---

## 58. Multi-Stage Correlation

An account-compromise investigation should be connected to:

```text
Credential Attack
       |
       v
Successful Authentication
       |
       v
Session
       |
       v
Privilege / Discovery
       |
       v
Persistence
       |
       v
Network Activity
       |
       v
Malware / Endpoint Activity
```

This allows the SOC to move from isolated alerts toward attack-chain analysis.

---

## 59. Evidence Package

A completed investigation should contain:

```text
alert.json
investigation.md
timeline.md
indicators.md
threat-intelligence.md
hunting.md
response.md
final-report.md
lessons-learned.md
```

Where applicable, include:

* preserved telemetry;
* hashes;
* screenshots;
* detection output;
* test results.

---

## 60. Investigation Notes

The analyst should record:

* what was observed;
* what was validated;
* what was inferred;
* what remains unknown;
* what evidence supports each conclusion;
* what response actions were taken;
* who authorized response actions;
* what detection gaps were identified.

---

## 61. Analyst Conclusion Standard

Use language such as:

> The telemetry shows a suspicious authentication-to-session sequence involving repeated authentication failures, successful authentication, session establishment, and privileged-account activity.

Avoid unsupported statements such as:

> The attacker definitely compromised the server.

unless additional evidence establishes that conclusion.

---

## 62. Escalation Criteria

Escalate when:

* unauthorized access is confirmed;
* privileged access is confirmed;
* persistence is discovered;
* multiple accounts are affected;
* multiple hosts are affected;
* lateral movement is suspected;
* malware is identified;
* sensitive resources may have been accessed;
* active attacker control is suspected;
* evidence integrity is at risk.

---

## 63. Escalation Information

Provide:

* case ID;
* alert ID;
* detection ID;
* affected account;
* affected host;
* source IP;
* session ID;
* first seen;
* last seen;
* severity;
* confidence;
* observed evidence;
* analyst interpretation;
* containment status;
* outstanding questions.

---

## 64. Closure Criteria

Close only after:

* alert validity was established;
* evidence was preserved;
* authorization was assessed;
* investigation was completed;
* related telemetry was reviewed;
* indicators were documented;
* ATT&CK mapping was completed;
* response actions were recorded;
* detection gaps were identified;
* final classification was recorded.

---

## 65. Case Classification

Use one final classification:

```text
BENIGN
SUSPICIOUS
UNAUTHORIZED_ACCESS
CONFIRMED_COMPROMISE
```

The classification must be supported by evidence.

---

## 66. Lessons Learned

Document:

1. What triggered the investigation?
2. What evidence was most useful?
3. Which telemetry was missing?
4. Which detection logic worked?
5. Which evasion paths remain?
6. Which false positives are possible?
7. What detection should be improved?
8. What new test should be added?

---

## 67. Detection Feedback Loop

The investigation should feed back into detection engineering.

```text
Investigation
     |
     v
Detection weakness
     |
     v
Engineering improvement
     |
     v
New test
     |
     v
Validation
     |
     v
Documentation
```

Possible improvements include:

* user-centric correlation;
* distributed-source detection;
* identity-risk scoring;
* privilege-transition detection;
* session anomaly detection;
* stronger event deduplication;
* timestamp integrity checks.

---

## 68. Validation Requirements

PB-006 should be validated against:

### Normal

* legitimate administrator login;
* legitimate failed password;
* legitimate session;
* legitimate `id`;
* legitimate `sudo -l`.

### Malformed

* missing user;
* missing source IP;
* missing session ID;
* malformed timestamp;
* malformed event type;
* empty command;
* invalid event structure.

### Boundary

* exactly four failures;
* three failures;
* exactly two commands;
* one command;
* exactly five-minute window;
* activity outside the window.

### Correlation

* matching source IP;
* mismatched source IP;
* matching user;
* mismatched user;
* matching session ID;
* mismatched session ID.

### Adversarial

* distributed source IPs;
* slow failures;
* command variation;
* timestamp manipulation;
* duplicate events;
* missing telemetry.

---

## 69. Quality Gates

The repository should pass the applicable quality gates before release:

```bash
pytest
ruff check .
bandit -r src
mypy src
pip-audit
python -m compileall src
git diff --check
```

Only report results that were actually executed.

---

## 70. Reproducibility

A reviewer should be able to reproduce the laboratory scenario using:

* documented telemetry;
* documented detection configuration;
* documented commands;
* documented expected alerts;
* documented expected evidence.

Avoid undocumented analyst-only steps.

---

## 71. Portfolio Evidence

PB-006 demonstrates capability in:

* authentication monitoring;
* account compromise triage;
* session correlation;
* privileged activity analysis;
* evidence preservation;
* timeline reconstruction;
* indicator analysis;
* threat intelligence boundaries;
* ATT&CK mapping;
* incident response;
* threat hunting;
* detection engineering feedback;
* adversarial validation.

It should be presented as hands-on SOC laboratory evidence.

It must not be represented as professional SOC employment.

---

## 72. Cross-Project Integration

PB-006 can integrate with:

* `cybernova-siem-detection-lab`;
* `cybernova-threat-hunting-toolkit`;
* `cybernova-malware-analysis-sandbox`;
* `cybernova-windows-security-monitoring-lab`;
* `linux-security-audit-toolkit`;
* `cybernova-cloud-security-monitoring-lab`.

The purpose is to demonstrate an evidence chain across security capabilities.

---

## 73. Analyst Checklist

### Alert

* [ ] Alert ID validated
* [ ] Detection ID validated
* [ ] Severity validated
* [ ] Confidence validated
* [ ] Supporting events identified

### Authentication

* [ ] Failed attempts reviewed
* [ ] Successful authentication reviewed
* [ ] Source IP validated
* [ ] User validated
* [ ] Authentication sequence reconstructed

### Session

* [ ] Session ID validated
* [ ] Session start validated
* [ ] Complete session reviewed
* [ ] Commands reviewed

### Privilege

* [ ] Privileged indicators reviewed
* [ ] Authorization checked
* [ ] Group membership reviewed
* [ ] Privilege escalation assessed

### Correlation

* [ ] Brute force checked
* [ ] Password spraying checked
* [ ] Endpoint activity checked
* [ ] Network activity checked
* [ ] Malware checked
* [ ] File integrity checked
* [ ] Persistence checked

### Evidence

* [ ] Alert preserved
* [ ] Logs preserved
* [ ] Timeline created
* [ ] Indicators documented
* [ ] Evidence classification recorded

### Response

* [ ] Containment assessed
* [ ] Credential response assessed
* [ ] Session response assessed
* [ ] Eradication completed if required
* [ ] Recovery completed
* [ ] Monitoring established

### Closure

* [ ] ATT&CK mapping completed
* [ ] False positive assessment completed
* [ ] Hunting completed
* [ ] Detection gaps documented
* [ ] Lessons learned completed
* [ ] Final report completed

---

## 74. Case-004 Reference

CASE-004 demonstrates the intended workflow.

Observed sequence:

```text
4 failed authentication attempts
        |
        v
successful authentication
        |
        v
session established
        |
        v
4 command events
        |
        v
id
sudo -l
```

Observed context:

```text
Host:
lab-linux-01

User:
admin

Source:
198.51.100.60

Session:
SES-004-C
```

The case interpretation remains:

> Suspicious authentication-to-session sequence involving a privileged account and subsequent enumeration activity.

The case does not independently prove account compromise.

---

## 75. Final Report Requirements

The final report should answer:

### What happened?

Describe the observed authentication and session sequence.

### Why was it suspicious?

Explain the relationship between failed authentication, successful authentication, session creation, and privileged activity.

### What evidence supports the finding?

Reference event IDs and preserved telemetry.

### What remains unknown?

Identify authorization, ownership, intent, and missing telemetry questions.

### What was the impact?

Only report impact supported by evidence.

### What response occurred?

Record actual containment and recovery actions.

### What should improve?

Document detection, telemetry, and process improvements.

---

## 76. Final Analyst Statement

A suitable final statement for CASE-004 is:

> The laboratory telemetry produced a high-confidence DET-AUTH-003 alert after four failed authentication attempts were followed by successful authentication, a correlated session, and four post-authentication command events involving `id` and `sudo -l`. The observed sequence is suspicious and warrants authorization and session validation. The available telemetry does not independently prove account compromise or malicious intent.

---

## 77. Playbook Limitations

This playbook does not guarantee detection of all account-compromise activity.

Limitations include:

* dependence on available authentication telemetry;
* dependence on accurate timestamps;
* source-IP correlation limitations;
* detection thresholds;
* distributed attack activity;
* slow attacks;
* legitimate administrative activity;
* missing endpoint telemetry;
* missing network telemetry;
* missing identity context;
* attacker log manipulation;
* incomplete session telemetry.

These limitations must be disclosed in portfolio materials.

---

## 78. Laboratory-Only Disclaimer

This playbook represents a controlled defensive security laboratory workflow.

It does not represent:

* professional SOC employment;
* production incident response experience;
* real-world compromise;
* real-world threat intelligence findings;
* production security metrics.

The objective is to demonstrate practical SOC investigation methodology and engineering discipline.

---

## 79. Engineering Standard

PB-006 follows the CYBERNOVA SOC evidence chain:

```text
Event
  |
  v
Detection
  |
  v
Alert
  |
  v
Triage
  |
  v
Validation
  |
  v
Investigation
  |
  v
Timeline
  |
  v
Indicators
  |
  v
Threat Intelligence
  |
  v
Hunting
  |
  v
ATT&CK
  |
  v
Severity
  |
  v
Response
  |
  v
Impact
  |
  v
Final Report
  |
  v
Detection Improvement
  |
  v
Test
  |
  v
Security Validation
```

---

## 80. Completion Standard

PB-006 is considered complete when:

* the playbook is committed;
* the playbook is pushed;
* the README registers PB-006;
* the README status is `Implemented`;
* `git diff --check` passes;
* repository status is clean;
* local and remote commits are synchronized.

**Author:** Ibrahim Mukhtar Saidu
**Project:** CYBERNOVA SOC Operations Laboratory
