# CASE-002 — Indicators and Evidence

## Indicator Summary

This document records indicators directly observed in the CASE-002 laboratory telemetry and separates them from analyst interpretation.

No real-world reputation, attribution, or maliciousness claim is made for any IP address or username.

## Primary Indicators

| Indicator Type | Value | Evidence | Assessment |
|---|---|---|---|
| Source IP | `198.51.100.40` | EVT-002001–EVT-002014 | Primary source associated with detected spray |
| Destination Host | `lab-auth-01` | EVT-002001–EVT-002020 | Target authentication host |
| Destination IP | `192.0.2.10` | EVT-002001–EVT-002020 | Authentication destination in laboratory telemetry |
| Protocol | SSH | EVT-002001–EVT-002020 | Observed authentication protocol |
| Authentication Method | password | EVT-002001–EVT-002016, EVT-002018 | Authentication method associated with failures |
| Targeted Users | `alice`, `bob`, `carol`, `david`, `erin`, `frank`, `grace` | EVT-002001–EVT-002014 | Seven distinct accounts targeted |
| Failed Attempts | 13 | EVT-002001–EVT-002007, EVT-002009–EVT-002014 | Exceeds detection threshold |
| Successful Authentication | `alice` | EVT-002008 | Successful password authentication observed |
| Successful Authentication Source | `198.51.100.40` | EVT-002008 | Same source as detected spray |
| Successful Authentication Event | `EVT-002008` | Alert evidence | Event requiring further validation |
| Detection ID | `DET-AUTH-002` | alert.json | Password spraying detection |
| Alert ID | `ALERT-CASE-002-DET-AUTH-002` | alert.json | Case alert identifier |
| ATT&CK Technique | T1110.003 | alert.json / analysis | Password Spraying |

## Behavioral Indicators

### Multi-Account Targeting

The source `198.51.100.40` attempted password authentication against seven distinct accounts within the detection window.

This is the primary behavioral characteristic supporting the password-spraying assessment.

### Repeated Password Authentication Failures

The source generated 13 failed password authentication attempts against `lab-auth-01`.

The configured detection threshold is six failures against at least six distinct users within five minutes. The observed activity exceeded both requirements.

### Short Authentication Window

The first observed failure occurred at:

`2026-09-08T10:00:03Z`

The last detected failure occurred at:

`2026-09-08T10:04:28Z`

The observed sequence therefore spans approximately four minutes and 25 seconds.

### Successful Authentication During the Sequence

`EVT-002008` records a successful password authentication for `alice` at:

`2026-09-08T10:01:51Z`

This is a significant investigation indicator because it originated from the same source IP as the detected password-spraying activity.

The event does not, by itself, prove that `alice` was compromised.

## Authentication Indicators

The primary activity consistently identifies:

- Process: `sshd`
- Protocol: `ssh`
- Authentication method: `password`
- Destination host: `lab-auth-01`
- Destination IP: `192.0.2.10`

The repeated use of the same source and destination while changing the targeted username supports the password-spraying interpretation.

## Event ID Evidence

### Primary Detection Evidence

The alert identifies the following supporting events:

- `EVT-002001`
- `EVT-002002`
- `EVT-002003`
- `EVT-002004`
- `EVT-002005`
- `EVT-002006`
- `EVT-002007`
- `EVT-002009`
- `EVT-002010`
- `EVT-002011`
- `EVT-002012`
- `EVT-002013`
- `EVT-002014`
- `EVT-002008`

These events collectively represent the detected password-spraying sequence and the observed successful authentication.

### Contrast Evidence

The following events use different sources and are not attributed to the detected spray:

- `EVT-002015` — password failure for `heidi` from `203.0.113.45`
- `EVT-002016` — password failure for `heidi` from `203.0.113.45`
- `EVT-002017` — expected-source public-key authentication for `alice`
- `EVT-002018` — password failure for `bob` from `192.0.2.22`
- `EVT-002019` — expected-source public-key authentication for `bob`
- `EVT-002020` — expected-source public-key authentication for `carol`

These events provide comparison evidence and help distinguish the detected source from unrelated authentication activity.

## Observed Versus Interpreted Evidence

### Directly Observed

The telemetry directly records:

- Source IP `198.51.100.40`
- Seven targeted usernames
- 13 failed password authentication attempts
- Successful password authentication for `alice`
- SSH protocol
- Destination host `lab-auth-01`
- Authentication timestamps
- Event IDs
- Authentication-method metadata

### Analyst Interpretation

The activity is consistent with password spraying because:

1. One source targeted multiple accounts.
2. Password authentication was used.
3. Attempts occurred within a short time window.
4. The number of failures exceeded the configured detection threshold.
5. A successful authentication from the same source was observed during the sequence.

### Not Established

The available evidence does not establish:

- that `198.51.100.40` represents a real malicious actor
- that the source was unauthorized
- that Alice's credentials were compromised
- that the successful authentication was malicious
- that any account was taken over
- that privileged activity occurred after authentication
- that data was accessed or exfiltrated
- that persistence was established
- that lateral movement occurred
- that additional hosts were compromised

## Indicator Handling Recommendations

For a real authorized environment, the following indicators would be suitable for correlation:

- Source IP
- Targeted username
- Destination host
- Authentication method
- SSH session identifier, where available
- Authentication timestamp
- Successful-login source
- Subsequent session activity
- Related endpoint and network telemetry

IP addresses should be correlated with organizational context rather than automatically treated as malicious based solely on this case.

## Laboratory Limitation

The indicators in this case are synthetic laboratory evidence designed for defensive SOC training and detection validation.

The IP ranges used in the dataset are documentation/test values. They should not be interpreted as real-world malicious infrastructure or used for attribution.
