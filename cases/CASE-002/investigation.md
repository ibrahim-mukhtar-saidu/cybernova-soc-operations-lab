# CASE-002 — Password Spraying Investigation

## Case Summary

| Field | Value |
|---|---|
| Case ID | CASE-002 |
| Alert ID | ALERT-CASE-002-DET-AUTH-002 |
| Detection | DET-AUTH-002 |
| Detection Name | Password Spraying Authentication Detection |
| Severity | High |
| Confidence | High |
| Status | Open |
| Host | lab-auth-01 |
| Source IP | 198.51.100.40 |
| Protocol | SSH |
| Authentication Method | Password |
| First Seen | 2026-09-08T10:00:03Z |
| Last Seen | 2026-09-08T10:04:28Z |
| Failed Attempts | 13 |
| Distinct Targeted Users | 7 |
| Successful Authentication Observed | Yes |
| Successful Authentication User | alice |
| Successful Authentication Event | EVT-002008 |
| ATT&CK Technique | T1110.003 — Password Spraying |

## Alert Assessment

The detection identified repeated password-based SSH authentication failures originating from `198.51.100.40` against multiple user accounts on `lab-auth-01`.

The alert threshold was six or more failed password authentication attempts against six or more distinct users within five minutes. The observed activity exceeded both thresholds:

- 13 failed authentication attempts
- 7 distinct targeted users
- 4 minutes and 25 seconds between the first and last observed failed attempt
- Common source IP: `198.51.100.40`
- Common destination host: `lab-auth-01`
- Authentication method: password

The activity is consistent with a password-spraying pattern.

The detection also recorded a successful password authentication for `alice` at `2026-09-08T10:01:51Z`. This increases investigation priority, but the successful authentication alone does **not** establish account compromise.

## Evidence Reviewed

Primary evidence reviewed:

- `cases/CASE-002/alert.json`
- `telemetry/authentication/CASE-002-authentication-events.jsonl`

Supporting alert evidence:

- `EVT-002001` through `EVT-002007`
- `EVT-002009` through `EVT-002014`
- `EVT-002008` — successful authentication for `alice`

Additional telemetry reviewed for comparison:

- `EVT-002015` and `EVT-002016` — password failures for `heidi` from `203.0.113.45`
- `EVT-002017` — successful public-key authentication for `alice` from `192.0.2.21`
- `EVT-002018` — password failure for `bob` from `192.0.2.22`
- `EVT-002019` — successful public-key authentication for `bob` from `192.0.2.22`
- `EVT-002020` — successful public-key authentication for `carol` from `192.0.2.23`

The additional events provide useful baseline and contrast evidence but do not establish that the alternate sources were involved in the detected spray.

## Observed Attack Pattern

The source `198.51.100.40` attempted password authentication against seven different accounts:

1. `alice`
2. `bob`
3. `carol`
4. `david`
5. `erin`
6. `frank`
7. `grace`

The first seven failures occurred rapidly between `10:00:03Z` and `10:01:34Z`, covering all seven accounts.

A successful password authentication for `alice` then occurred at `10:01:51Z`.

Further password failures against `bob`, `carol`, `david`, `erin`, `frank`, and `grace` continued through `10:04:28Z`.

This sequence demonstrates broad account targeting rather than repeated failures against a single account, which is characteristic of password spraying.

## Successful Authentication Assessment

`EVT-002008` records:

- User: `alice`
- Source IP: `198.51.100.40`
- Host: `lab-auth-01`
- Action: `login_success`
- Authentication method: password
- Timestamp: `2026-09-08T10:01:51Z`

The event is genuine observed telemetry within the laboratory dataset.

However, the available evidence does not establish whether the successful authentication resulted from the same password material used during the preceding failed attempt, whether the credentials were authorized, or whether the resulting session was malicious.

Therefore:

**Account compromise is not confirmed by the authentication telemetry alone.**

Further investigation would require session, endpoint, identity, and subsequent activity evidence.

## Scope

Confirmed observed scope:

- Source: `198.51.100.40`
- Destination host: `lab-auth-01`
- Users targeted: `alice`, `bob`, `carol`, `david`, `erin`, `frank`, `grace`
- Protocol: SSH
- Authentication method: password
- Detection window: approximately five minutes

No evidence in the supplied telemetry establishes:

- additional compromised hosts
- credential theft
- persistence
- privilege escalation
- lateral movement
- data access
- data exfiltration
- malware execution
- attribution to a real-world actor

## Initial Severity and Confidence Assessment

**Severity: High**

The severity is appropriate because the activity demonstrates coordinated password authentication attempts against multiple accounts and includes an observed successful authentication from the same source.

**Confidence: High**

Confidence is high because the telemetry contains explicit authentication actions, timestamps, source IP information, targeted usernames, and authentication-method metadata that directly support the detected pattern.

Confidence in the specific conclusion of **account compromise** remains lower because the supplied telemetry does not contain sufficient post-authentication evidence to establish compromise.

## Investigation Questions

The following questions remain open:

1. Was `198.51.100.40` an authorized source?
2. Was the successful `alice` authentication authorized?
3. What session activity followed `EVT-002008`?
4. Were there privileged commands or configuration changes after the successful authentication?
5. Did `alice` access sensitive resources after authentication?
6. Were the same credentials attempted against other hosts?
7. Did the source IP appear in other authentication or network telemetry?
8. Were any additional authentication successes associated with the source?
9. Was the account password subsequently changed or reset?
10. Are there identity-provider, endpoint, or network records that corroborate or contradict the alert?

## Required Evidence for Further Validation

Recommended additional evidence:

- SSH authentication logs surrounding `EVT-002008`
- Account/session records for `alice`
- Successful-login source and session metadata
- Shell history or command telemetry where legally and operationally appropriate
- Privilege escalation events
- File and configuration changes
- Network connections following successful authentication
- Identity-provider or authentication-service records
- Authentication activity from `198.51.100.40` against other hosts
- Account password-reset or lockout events

## ATT&CK Mapping

The observed behavior maps analytically to:

- **T1110 — Brute Force**
- **T1110.003 — Password Spraying**

The sub-technique mapping is based on the observed pattern of attempting password authentication against multiple distinct accounts from a common source within a short period.

This mapping describes observed behavior and does not establish actor identity, intent, or successful compromise.

## Preliminary Conclusion

The evidence supports a **high-confidence password-spraying authentication event** against `lab-auth-01` from `198.51.100.40`.

The source attempted password authentication against seven distinct accounts and generated 13 failed attempts within approximately five minutes. A successful password authentication for `alice` was also observed from the same source.

The successful authentication materially increases investigation priority, but **compromise of `alice` is not established by the available telemetry**.

The case should remain open until the successful authentication and any subsequent activity can be validated against additional authorized evidence sources.

## Investigation Limitation

This case uses synthetic laboratory telemetry for defensive SOC training and portfolio evidence.

No real-world attribution, malicious-IP reputation, production compromise, credential theft, or confirmed account takeover should be inferred from this dataset alone.
