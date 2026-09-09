# CASE-002 — Threat Hunting

## Hunting Objective

The objective of this hunt is to determine whether the observed password-spraying activity from `198.51.100.40` represents an isolated authentication event or part of a broader activity pattern.

The hunt also evaluates whether the successful authentication for `alice` was followed by additional suspicious activity.

This hunt is based on the available CASE-002 laboratory telemetry. No additional compromise is assumed.

## Primary Hunt — Source-Centric

### Pivot

`source_ip = 198.51.100.40`

### Questions

- Did the source target additional hosts?
- Did the source attempt additional usernames?
- Were there other successful authentications?
- Did the source use other authentication methods?
- Did activity continue outside the original five-minute detection window?

### Available Evidence

Within the supplied telemetry, `198.51.100.40` is associated with:

- 13 failed password authentication attempts
- 7 distinct targeted users
- 1 successful password authentication for `alice`
- Destination host `lab-auth-01`

No additional destination host or successful authentication from this source is present in the supplied dataset.

### Assessment

The available evidence supports the detected source-centric activity but is insufficient to determine whether the source interacted with other systems outside this telemetry set.

## Account-Centric Hunt — Alice

### Pivot

`user = alice`

### Questions

- What authentication events occurred before `EVT-002008`?
- Was the successful password authentication expected?
- What activity followed the successful authentication?
- Did Alice authenticate from additional sources?
- Were privileged or unusual actions recorded?

### Observed Evidence

Before `EVT-002008`, Alice had one failed password authentication:

- `EVT-002001` at `10:00:03Z`
- Source: `198.51.100.40`

The successful password authentication occurred at:

- `EVT-002008` at `10:01:51Z`
- Source: `198.51.100.40`

A later successful public-key authentication was observed:

- `EVT-002017` at `10:06:02Z`
- Source: `192.0.2.21`
- Metadata identifies the source as expected.

No post-authentication session, command, privilege, file, or network telemetry for Alice is present in the supplied dataset.

### Assessment

The successful password authentication requires validation, but the available evidence does not establish account compromise.

## Host-Centric Hunt

### Pivot

`host = lab-auth-01`

### Questions

- Did other sources exhibit similar authentication behavior?
- Were multiple accounts targeted?
- Were authentication methods changed?
- Were there signs of coordinated activity?

### Observed Evidence

The host received the detected spray from `198.51.100.40`.

Other authentication activity includes:

- `203.0.113.45` targeting `heidi`
- `192.0.2.21` successfully authenticating as `alice` using public key
- `192.0.2.22` authenticating as `bob`
- `192.0.2.23` successfully authenticating as `carol`

These sources are distinct from the detected spray source.

### Assessment

The available telemetry does not establish coordination between these sources and the detected password-spraying activity.

## Account-Set Hunt

A useful detection-engineering pivot is the set of accounts targeted by the source:

`alice`, `bob`, `carol`, `david`, `erin`, `frank`, `grace`

### Questions

- Was the same account set targeted repeatedly?
- Were additional users targeted before or after this event?
- Did another source target the same accounts?
- Did targeting move between hosts?

### Assessment

The supplied telemetry contains one concentrated seven-account targeting sequence.

Additional telemetry would be required to determine whether this account set was targeted elsewhere or at other times.

## Successful-Authentication Hunt

The successful authentication is the highest-priority follow-up pivot.

### Pivot

- Source: `198.51.100.40`
- User: `alice`
- Event: `EVT-002008`
- Timestamp: `2026-09-08T10:01:51Z`

### Recommended Correlation

Search an authorized telemetry platform for:

- subsequent SSH session creation
- session duration
- command execution
- privilege escalation
- file access
- configuration changes
- network connections
- additional authentication attempts
- password changes
- account lockouts

### Current Result

None of these post-authentication evidence sources are included in the CASE-002 dataset.

Therefore, the successful authentication remains an investigation lead rather than proof of compromise.

## Low-and-Slow Hunt

Password spraying can evade a short detection window by spreading authentication attempts over longer periods.

A defensive hunt should therefore examine:

- source IP over longer time windows
- username diversity over time
- repeated low-volume failures
- multiple sources targeting the same accounts
- the same source targeting multiple hosts
- authentication failures separated by significant intervals

### Current Result

The supplied CASE-002 telemetry demonstrates a concentrated sequence rather than a low-and-slow pattern.

No conclusion about longer-term activity can be made without additional telemetry.

## Source-Rotation Hunt

A distributed password-spraying campaign may use multiple source addresses.

Recommended correlation:

1. Group authentication failures by username.
2. Count distinct source IPs.
3. Identify repeated targeting of the same account set.
4. Compare timestamps across sources.
5. Correlate with destination hosts.

### Current Result

The supplied dataset contains additional authentication sources, but there is insufficient evidence to establish that they form a coordinated campaign.

## Hunting Limitations

The current dataset does not include:

- authentication events from other hosts
- long-term authentication history
- SSH session telemetry
- command execution
- endpoint telemetry
- network flow telemetry
- identity-provider logs
- password-reset events
- account lockout history
- privilege escalation events

These limitations prevent a complete determination of campaign scope or post-authentication impact.

## Hunting Conclusion

The available telemetry confirms a concentrated password-spraying pattern from `198.51.100.40` against seven accounts on `lab-auth-01`.

The successful password authentication for `alice` is the highest-priority hunting pivot.

No additional evidence in the supplied dataset establishes:

- broader source activity
- additional compromised hosts
- post-authentication abuse
- privilege escalation
- lateral movement
- persistence
- data access
- data exfiltration

Further authorized telemetry correlation is required before assigning a confirmed compromise outcome.

## Detection Improvement Opportunities

Future hunting and detection coverage should consider:

- longer time windows
- account-centric aggregation
- cross-host correlation
- multi-source correlation
- successful-authentication escalation
- post-authentication session correlation
- source rotation
- low-and-slow authentication patterns
- baseline-aware authentication analytics

All improvements should be tested against both positive and negative laboratory scenarios to control false positives.
