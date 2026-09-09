# CASE-002 — Password Spraying Investigation

## Overview

CASE-002 demonstrates an end-to-end SOC investigation of a synthetic SSH password-spraying event.

The detection engine identified repeated password authentication failures from a single source against multiple accounts within a short time window.

A successful password authentication for `alice` was also observed during the activity and was treated as a priority investigation pivot.

## Detection

| Field | Value |
|---|---|
| Detection ID | `DET-AUTH-002` |
| Detection Name | Password Spraying Authentication Detection |
| Detection Version | `1.0` |
| Alert ID | `ALERT-CASE-002-DET-AUTH-002` |
| Severity | High |
| Confidence | High |
| Status | Open |
| Protocol | SSH |
| Authentication Method | Password |
| Source IP | `198.51.100.40` |
| Host | `lab-auth-01` |
| Failed Attempts | 13 |
| Distinct Users | 7 |
| Detection Window | 5 minutes |

## Observed Activity

The source `198.51.100.40` targeted:

- `alice`
- `bob`
- `carol`
- `david`
- `erin`
- `frank`
- `grace`

The activity produced 13 failed password authentication attempts within approximately 4 minutes and 25 seconds.

A successful password authentication for `alice` was observed in `EVT-002008`.

## Investigation Outcome

### Confirmed

- Password-spraying behavior is confirmed within the laboratory telemetry.
- The detection threshold was satisfied.
- Seven distinct accounts were targeted.
- A successful password authentication for `alice` was observed.

### Not Established

The available telemetry does not establish:

- unauthorized access
- account compromise
- credential theft
- persistence
- privilege escalation
- lateral movement
- malware execution
- data access
- data exfiltration
- real-world attribution

The case remains open pending validation of the successful authentication and associated post-authentication activity.

## MITRE ATT&CK

Primary mapping:

- **T1110 — Brute Force**
- **T1110.003 — Password Spraying**

The mapping describes the observed authentication behavior and does not independently establish compromise.

## Investigation Workflow

The case follows the SOC evidence chain:

```text
Telemetry
   ↓
Detection
   ↓
Alert
   ↓
Triage
   ↓
Investigation
   ↓
Timeline
   ↓
Indicators
   ↓
Threat Intelligence
   ↓
Threat Hunting
   ↓
Response
   ↓
Final Report
   ↓
Lessons Learned
Evidence
Detection Evidence
alert.json
../../telemetry/authentication/CASE-002-authentication-events.jsonl
Investigation Artifacts
investigation.md
timeline.md
indicators.md
threat-intelligence.md
hunting.md
response.md
final-report.md
lessons-learned.md
Key Investigation Pivot

The highest-priority follow-up event is:

EVT-002008

Timestamp: 2026-09-08T10:01:51Z
User: alice
Source: 198.51.100.40
Action: login_success
Authentication: password

This event occurred during the detected password-spraying sequence.

It is treated as observed evidence and not as proof of compromise.

Recommended Follow-Up

In an authorized environment, investigators should correlate:

SSH session activity
post-authentication commands
privilege escalation
endpoint telemetry
network activity
account changes
authentication history
additional activity from 198.51.100.40
repeated targeting of the same accounts
Detection Engineering Lessons

This case identifies opportunities to improve future coverage:

account-centric correlation
cross-source correlation
cross-host correlation
longer windows for low-and-slow activity
source-rotation detection
successful-authentication escalation
post-authentication session correlation

Any detection improvements should be validated with positive and negative laboratory telemetry.

Security and Evidence Principles

This case intentionally separates:

Observed evidence

from

Analyst interpretation

and from

Unestablished conclusions

This prevents a suspicious authentication event from being incorrectly represented as confirmed account compromise.

Laboratory Scope

This case uses synthetic SOC laboratory telemetry.

The IP addresses, usernames, hostname, and authentication events are test data.

No real-world maliciousness, attacker attribution, production containment, confirmed compromise, or professional SOC employment experience is claimed.

Portfolio Evidence

CASE-002 demonstrates practical capability in:

authentication detection engineering
alert analysis
SOC triage
investigation
timeline reconstruction
indicator analysis
threat intelligence assessment
threat hunting
incident response planning
MITRE ATT&CK mapping
evidence-based reporting
detection improvement
Case Status

Investigation workflow complete.

The case remains analytically open because the available laboratory telemetry does not establish whether the successful authentication resulted in unauthorized activity.
