# CASE-007 — Indicators

## Indicator Summary

**Case ID:** CASE-007

**Scenario:** File Integrity Violation

**Host:** `lab-host-01`

**Detection:** `DET-HOST-001` — File Integrity Violation Detection

**Alert ID:** `ALERT-CASE-007-DET-HOST-001`

**Environment:** Controlled cybersecurity laboratory using synthetic telemetry

## 1. Indicator Handling Principles

Indicators in this case are derived from synthetic laboratory telemetry.

An indicator is treated as an observable artifact that may support investigation. Its presence does not independently establish malicious activity.

The indicators are therefore classified according to their evidentiary role:

- **Observed:** Directly present in telemetry or alert evidence.
- **Contextual:** Relevant to investigation but not independently suspicious.
- **Requires validation:** Requires additional telemetry before an analyst can determine significance.

## 2. Host Indicator

### Host

```text
lab-host-01

Type: Host identifier

Classification: Observed

Source: EVT-007001, EVT-007002, EVT-007003

Assessment: All three file integrity events originate from the same laboratory host.

The shared host identity is one of the conditions used by DET-HOST-001 for correlation.

3. File Indicators
/etc/ssh/sshd_config

Type: Security-sensitive configuration file

Event: EVT-007001

Change: Modified

Timestamp: 2026-09-08T12:00:00Z

Authorization field: authorized_change=false

Classification: Observed — requires validation

Assessment: The file was modified according to the synthetic FIM telemetry.

Changes to SSH configuration can affect authentication or remote-access behavior, so the modification warrants investigation.

The event does not independently establish malicious modification.

/etc/passwd

Type: Local account database

Event: EVT-007002

Change: Modified

Timestamp: 2026-09-08T12:02:00Z

Authorization field: authorized_change=false

Classification: Observed — requires validation

Assessment: The local account database was modified according to the synthetic FIM telemetry.

Because /etc/passwd contains local account information, the modification warrants investigation.

The event does not independently establish account compromise or persistence.

/opt/application/config.yml

Type: Application configuration file

Event: EVT-007003

Change: Modified

Timestamp: 2026-09-08T12:20:00Z

Authorization field: authorized_change=true

Classification: Contextual

Assessment: This change is explicitly marked as authorized in the laboratory telemetry and occurs outside the detection window.

It is therefore not treated as an indicator supporting the generated alert.

4. Event Indicators

The following event IDs directly support the generated alert:

EVT-007001
EVT-007002

Classification: Observed

These events are referenced by:

ALERT-CASE-007-DET-HOST-001

The event IDs provide traceability from the detection output back to the source telemetry.

5. Detection Indicator
Alert ID
ALERT-CASE-007-DET-HOST-001

Detection: DET-HOST-001

Severity: High

Confidence: High

Classification: Observed

The alert represents the output of the laboratory detection engine after two qualifying file integrity events were correlated on the same host.

6. Change-Type Indicators

The case contains the following observed change type:

modified

Classification: Observed

The detector also supports:

created
deleted

Those change types are part of the detection logic but were not observed in the CASE-007 telemetry.

7. User Indicator
root

Type: User identity

Classification: Observed

All three telemetry events identify root as the user associated with the file changes.

The user field alone does not establish that the root account was compromised.

Further authentication and session telemetry would be required to determine how the activity occurred.

8. Hash Indicators

The telemetry records previous and new SHA-256-style hash values for the modified files.

EVT-007001
File: /etc/ssh/sshd_config
Old hash: sha256:1111111111111111111111111111111111111111111111111111111111111111
New hash: sha256:2222222222222222222222222222222222222222222222222222222222222222
EVT-007002
File: /etc/passwd
Old hash: sha256:3333333333333333333333333333333333333333333333333333333333333333
New hash: sha256:4444444444444444444444444444444444444444444444444444444444444444

Classification: Observed

The differing old and new hashes demonstrate that the recorded file state changed.

Because these are synthetic laboratory values, they should not be interpreted as hashes of real production files.

9. Temporal Indicator

The first two qualifying modifications occurred two minutes apart:

12:00:00Z → 12:02:00Z

Classification: Observed

This temporal relationship satisfies the configured five-minute correlation window.

10. Authorization Indicators
EVT-007001
authorized_change=false
EVT-007002
authorized_change=false
EVT-007003
authorized_change=true

The first two values increase investigative priority within this laboratory scenario.

The authorization field is nevertheless telemetry supplied by the scenario and should be validated against independent administrative or change-management evidence in a real investigation.

11. Indicators Requiring Additional Evidence

The following potential indicators are not present in the current CASE-007 telemetry and must not be claimed as observed:

suspicious process names;
malicious command lines;
new local accounts;
unauthorized SSH keys;
privilege escalation;
suspicious authentication;
persistence mechanisms;
unexpected network connections;
malware artifacts;
known malicious hashes;
external threat-intelligence matches.

These should be investigated through additional telemetry rather than inferred from the file changes.

12. Indicator Relationships

The principal observed relationship is:

lab-host-01
    │
    ├── EVT-007001
    │     └── /etc/ssh/sshd_config modified
    │
    └── EVT-007002
          └── /etc/passwd modified
                 │
                 └── within 5 minutes
                        │
                        ↓
             DET-HOST-001
                        │
                        ↓
       ALERT-CASE-007-DET-HOST-001

The third event is separate from this correlation:

EVT-007003
    └── /opt/application/config.yml modified
           └── authorized_change=true
           └── outside detection window
13. Indicator Validation Plan

For a production-quality investigation, each important indicator should be corroborated using independent evidence.

File Modification

Review:

file metadata;
filesystem audit logs;
process execution telemetry;
package-management logs;
configuration-management records.
Root Activity

Review:

authentication logs;
SSH sessions;
privilege escalation records;
session start and termination events;
command execution telemetry.
SSH Configuration

Review:

authentication configuration changes;
new or modified SSH keys;
remote-access policy changes;
unexpected listening services.
Account Database

Review:

account creation;
account modification;
UID/GID changes;
password changes;
privileged group membership.
Network Context

Review:

outbound connections;
inbound connections;
unusual destinations;
process-to-network relationships.
14. Indicator Conclusion

The strongest observed indicators are:

Two security-sensitive files modified on the same host.
The modifications occurred within two minutes.
Both events are marked as unauthorized within the laboratory telemetry.
Both events are directly linked to the generated alert.
The recorded file hashes changed.

These indicators justify continued investigation.

They do not independently prove compromise, malicious execution, persistence, or unauthorized access.

Laboratory Limitations

This indicator set is derived from synthetic laboratory telemetry.

No real production indicators, credentials, infrastructure, or malicious artifacts are represented.

Any production investigation would require independent corroboration before classifying these observations as confirmed malicious indicators.
