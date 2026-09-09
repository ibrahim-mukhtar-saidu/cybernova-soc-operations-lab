# CASE-002 — Final Investigation Report

## Executive Summary

CASE-002 documents a synthetic SSH password-spraying investigation.

The detection engine identified 13 failed password authentication attempts from source IP `198.51.100.40` against 7 distinct accounts on `lab-auth-01` within approximately 4 minutes and 25 seconds.

A successful password authentication for `alice` was subsequently observed from the same source.

The authentication pattern is consistent with password spraying and maps to MITRE ATT&CK technique `T1110.003 — Password Spraying`.

The successful authentication increases investigation priority but does not independently establish account compromise.

## Alert Summary

| Field | Value |
|---|---|
| Alert ID | `ALERT-CASE-002-DET-AUTH-002` |
| Detection ID | `DET-AUTH-002` |
| Detection | Password Spraying Authentication Detection |
| Version | `1.0` |
| Severity | High |
| Confidence | High |
| Status | Open |
| Host | `lab-auth-01` |
| Source IP | `198.51.100.40` |
| Protocol | SSH |
| Authentication method | Password |
| Failed attempts | 13 |
| Distinct targeted users | 7 |
| Detection window | 5 minutes |
| First observed | `2026-09-08T10:00:03Z` |
| Last observed failure | `2026-09-08T10:04:28Z` |
| Successful authentication | `EVT-002008` |
| Successful user | `alice` |

## Detection Assessment

The configured detection requires:

- at least 6 failed password authentication attempts
- at least 6 distinct targeted users
- activity within a 5-minute window

The observed activity exceeded both volume thresholds:

- 13 failed attempts
- 7 distinct users
- approximately 4 minutes and 25 seconds of observed activity

The detection therefore correctly identified the laboratory password-spraying pattern.

## Attack Sequence

The observed sequence was:

1. Source `198.51.100.40` attempted password authentication against `alice`.
2. The source continued targeting additional accounts.
3. Seven distinct accounts were targeted.
4. A successful password authentication occurred for `alice` at `10:01:51Z`.
5. Additional failed authentication attempts continued against the targeted accounts.
6. Activity ended at `10:04:28Z` in the supplied sequence.

The successful authentication is an important investigation pivot because it occurred during the detected password-spraying activity.

## Evidence Reviewed

Primary evidence:

- `cases/CASE-002/alert.json`
- `telemetry/authentication/CASE-002-authentication-events.jsonl`

Supporting events:

- `EVT-002001` through `EVT-002014`

Key event:

- `EVT-002008` — successful password authentication for `alice`

Contrast telemetry was also reviewed to distinguish the detected source from unrelated authentication activity.

## Investigation Findings

### Finding 1 — Password Spraying

**Assessment: Confirmed within laboratory telemetry**

One source IP targeted seven distinct accounts using password authentication within a short period.

This behavior satisfies the configured password-spraying detection criteria.

### Finding 2 — Successful Authentication

**Assessment: Observed**

`EVT-002008` records a successful password authentication for `alice` from `198.51.100.40`.

The event is genuine observed telemetry within the laboratory dataset.

### Finding 3 — Account Compromise

**Assessment: Not established**

The available evidence does not establish that:

- the successful credential was obtained through the spraying activity
- the login was unauthorized
- the account was compromised
- the account was abused after authentication

Additional session and endpoint telemetry would be required.

### Finding 4 — Broader Attack Activity

**Assessment: Not established**

The supplied dataset does not provide sufficient evidence for:

- lateral movement
- persistence
- privilege escalation
- malware execution
- data access
- data exfiltration
- additional compromised hosts

## MITRE ATT&CK Mapping

| Tactic | Technique | Assessment |
|---|---|---|
| Credential Access | `T1110` — Brute Force | Observed behavior |
| Credential Access | `T1110.003` — Password Spraying | Primary detection mapping |

The ATT&CK mapping describes the observed behavior and does not establish actor attribution or successful compromise.

## Indicator Summary

### Source

`198.51.100.40`

Observed as the common source of the detected authentication sequence.

### Destination

`lab-auth-01`

Laboratory authentication host receiving the detected activity.

### Targeted Accounts

- `alice`
- `bob`
- `carol`
- `david`
- `erin`
- `frank`
- `grace`

### Successful Authentication

`EVT-002008`

User: `alice`

Source: `198.51.100.40`

## Impact Assessment

**Current impact determination: Not established**

The telemetry confirms suspicious authentication behavior but does not provide sufficient evidence to determine:

- unauthorized access
- account takeover
- privilege escalation
- persistence
- lateral movement
- data access
- data loss
- data exfiltration

The case should therefore remain open pending validation of the successful authentication and any associated session activity.

## Threat Intelligence Assessment

The primary intelligence value is behavioral.

The source demonstrated multi-account password authentication attempts within a short period.

No external reputation, ownership, geographic attribution, or actor attribution is assigned to `198.51.100.40`.

The IP address is laboratory telemetry and must not be interpreted as a real-world malicious indicator.

## Hunting Summary

Recommended pivots include:

- source IP across authentication logs
- targeted accounts before and after the event
- `alice` authentication history
- SSH session creation
- post-authentication commands
- privilege escalation
- network activity
- account changes
- repeated targeting of the same account set
- source rotation across longer time windows

The current dataset does not contain sufficient telemetry to complete these pivots.

## Response Summary

Recommended response actions in an authorized operational environment would include:

1. Validate whether the source and successful authentication were authorized.
2. Preserve the supporting authentication evidence.
3. Investigate the successful `alice` authentication.
4. Review associated SSH session activity.
5. Assess affected accounts and hosts.
6. Contain confirmed unauthorized activity according to organizational policy.
7. Reset affected credentials if compromise is established.
8. Monitor for recurrence.

No real containment or eradication action is claimed for this laboratory case.

## Detection Improvement

The investigation identifies several future detection improvements:

- account-centric aggregation
- cross-host source correlation
- multi-source correlation
- longer windows for low-and-slow spraying
- source rotation detection
- successful-authentication escalation
- post-authentication session correlation

Detection changes should be validated with positive and negative regression telemetry before adoption.

## Lessons for SOC Operations

This case demonstrates several important SOC practices:

- Detection thresholds should be tied to observable behavior.
- A high-confidence detection does not automatically prove compromise.
- Successful authentication after suspicious failures deserves priority investigation.
- Evidence should distinguish observed facts from analyst interpretation.
- Hunting should continue beyond the original detection window.
- Response actions should be proportional to validated evidence.
- Detection engineering should incorporate lessons from investigations.

## Final Determination

**Password-spraying activity: Confirmed in laboratory telemetry.**

**Successful password authentication: Observed.**

**Unauthorized access: Not established.**

**Account compromise: Not established.**

**Broader host or data impact: Not established.**

The case remains open because the available evidence does not contain sufficient post-authentication telemetry to determine whether the successful `alice` login resulted in unauthorized activity.

## Laboratory Limitation

This report is based entirely on synthetic SOC laboratory telemetry.

The IP addresses, usernames, hostname, authentication events, and outcomes are test data. They demonstrate defensive detection, investigation, hunting, and response methodology.

This case does not represent a real-world incident, real attacker attribution, production SOC activity, or confirmed compromise.
