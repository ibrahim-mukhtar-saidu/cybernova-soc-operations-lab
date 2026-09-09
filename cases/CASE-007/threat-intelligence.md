# CASE-007 — Threat Intelligence

## Intelligence Summary

**Case ID:** CASE-007

**Scenario:** File Integrity Violation

**Detection:** `DET-HOST-001` — File Integrity Violation Detection

**Alert ID:** `ALERT-CASE-007-DET-HOST-001`

**Host:** `lab-host-01`

**Environment:** Controlled cybersecurity laboratory using synthetic telemetry

## 1. Intelligence Handling Principle

Threat intelligence in this case is used to provide investigative context rather than to manufacture attribution.

The available CASE-007 telemetry does not contain:

- a known malicious IP address;
- a known malicious domain;
- a real malware hash;
- a confirmed threat actor;
- a confirmed campaign;
- a real production incident;
- external intelligence matching the observed file contents.

Therefore, no threat actor or malware attribution is made.

## 2. Relevant Security Context

The two files associated with the detection are security-sensitive Linux files:

- `/etc/ssh/sshd_config`
- `/etc/passwd`

Changes to these files can have significant security implications.

`/etc/ssh/sshd_config` controls aspects of SSH server behavior and authentication configuration.

`/etc/passwd` contains local account information.

Unexpected changes to either file therefore justify investigation and corroboration.

## 3. ATT&CK Context

The current detection contract maps the activity to:

**Technique:** `T1070`

**Name:** Indicator Removal

**Tactic:** Defense Evasion

This mapping should be treated as **contextual rather than confirmed behavior**.

The current telemetry demonstrates file modifications but does not establish that an adversary was attempting to remove indicators of compromise.

Additional evidence would be required before concluding that the activity represents a specific ATT&CK technique.

## 4. Potential ATT&CK Investigation Areas

The observed file modifications justify investigation of several possible behaviors.

### Account Modification

Because `/etc/passwd` was modified, investigators should determine whether local account information changed.

Potential evidence includes:

- newly created accounts;
- modified account attributes;
- UID/GID changes;
- privileged group membership;
- password changes;
- shell changes.

No such changes are claimed as observed in the current telemetry.

### SSH Configuration Modification

Because `/etc/ssh/sshd_config` was modified, investigators should determine whether remote-access behavior changed.

Potential areas include:

- authentication configuration;
- permitted authentication methods;
- privileged remote access;
- forwarding settings;
- listening configuration;
- SSH key configuration.

No specific configuration change is claimed because the telemetry does not contain file-content diffs.

### Privilege Activity

The events identify `root` as the associated user.

This does not establish how the activity obtained root-level context.

Investigators should therefore review:

- authentication events;
- SSH sessions;
- `sudo` activity;
- privilege escalation telemetry;
- process execution;
- administrative sessions.

## 5. Threat Intelligence Questions

The investigation should attempt to answer:

1. Is the modified SSH configuration consistent with a known hardening change?
2. Did the account database modification correspond to an approved account-management operation?
3. Were new privileged accounts created?
4. Were SSH authentication controls weakened?
5. Did the host show evidence of suspicious remote access?
6. Did a suspicious process modify the files?
7. Did the modifications occur shortly after an authentication event?
8. Were other security-sensitive files modified?
9. Were unusual outbound connections observed?
10. Does additional evidence identify a known malware family or campaign?

The current CASE-007 telemetry does not answer these questions.

## 6. Hash Intelligence

The telemetry contains synthetic SHA-256-style values.

These values are useful for demonstrating file-state change tracking within the laboratory.

They must not be submitted to external threat-intelligence systems as real malware indicators.

No malicious hash match is claimed.

The observed hash transitions are:

```text
EVT-007001
/etc/ssh/sshd_config
old → new

EVT-007002
/etc/passwd
old → new

The actual values remain evidence from the synthetic laboratory dataset.

7. Network Intelligence

CASE-007 does not contain network indicators directly associated with the file modifications.

Therefore, no IP address, domain, URL, or network destination is attributed to the activity.

If additional telemetry becomes available, investigators should correlate:

source and destination IP addresses;
DNS activity;
outbound connections;
process-to-network relationships;
unusual remote administration traffic.

Any resulting indicators should be validated independently before classification.

8. Malware Intelligence

No malware sample is associated with CASE-007.

The file integrity events do not provide enough information to identify:

malware family;
malware hash;
payload;
persistence mechanism;
command-and-control infrastructure;
threat actor.

Any such attribution would exceed the available evidence.

9. Threat Actor Attribution

Attribution status: Not established

There is insufficient evidence to associate the observed file changes with a specific:

threat actor;
criminal group;
intrusion set;
campaign;
malware family.

A professional SOC investigation should avoid attribution when the available evidence cannot support it.

10. Intelligence Confidence
Intelligence Area	Assessment
File modification	Observed
Security-sensitive file targeting	Observed
Unauthorized-change field	Observed in synthetic telemetry
Malicious intent	Not established
Compromise	Not established
Persistence	Not established
Malware	Not established
Threat actor	Not established
Campaign	Not established
External IOC match	Not established
11. Intelligence Collection Plan

Additional intelligence should be collected only when it can answer a specific investigative question.

Host Intelligence

Collect:

package history;
configuration-management records;
filesystem audit records;
process execution telemetry;
account-management activity.
Authentication Intelligence

Collect:

SSH authentication;
successful and failed logins;
privileged sessions;
source addresses;
session duration.
Process Intelligence

Collect:

process creation;
parent-child relationships;
command lines;
executable paths;
process users.
Network Intelligence

Collect:

DNS queries;
outbound connections;
inbound connections;
destination reputation where applicable;
process-to-network relationships.
12. Intelligence Decision

The current intelligence assessment is:

Suspicious activity requiring corroboration.

The file modifications are security-relevant and clustered in time.

However, available evidence does not establish malicious intent, compromise, persistence, or attribution.

The appropriate SOC response is to continue evidence collection and correlation rather than prematurely classify the activity as a confirmed intrusion.

13. Detection Improvement Implications

Threat-intelligence review identifies several opportunities for future detection improvement:

Correlate file modifications with authentication events.
Correlate file modifications with process execution.
Detect modifications to security-sensitive files with configurable path policies.
Track account database changes separately from generic file modifications.
Correlate SSH configuration changes with subsequent authentication anomalies.
Preserve process and user context in file-integrity alerts.
Allow authorized-change context to reduce false positives.
Maintain clear separation between observed indicators and threat-intelligence attribution.

These improvements should be implemented only after they are supported by additional telemetry and regression tests.

14. Laboratory Limitations

This threat-intelligence assessment is based entirely on synthetic laboratory telemetry.

No external threat actor, malware family, campaign, production infrastructure, or real-world compromise is being claimed.

The ATT&CK mapping is contextual and should be validated against additional evidence before being treated as confirmed adversary behavior.

Conclusion

CASE-007 provides sufficient evidence to justify further investigation of clustered modifications to security-sensitive Linux files.

It does not provide sufficient evidence for threat attribution or confirmation of malicious activity.

The strongest professional conclusion is therefore:

Observed file integrity violations are suspicious and require corroborating host, authentication, process, and administrative evidence.
