# CASE-002 — Investigation Timeline

## Timeline Summary

The timeline shows a concentrated password-authentication sequence from `198.51.100.40` against seven accounts on `lab-auth-01`, followed by a successful password authentication for `alice`.

All timestamps are UTC.

| Time | Event ID | User | Source IP | Action | Authentication | Assessment |
|---|---|---|---|---|---|---|
| 10:00:03 | EVT-002001 | alice | 198.51.100.40 | login_failure | password | First observed spray failure |
| 10:00:17 | EVT-002002 | bob | 198.51.100.40 | login_failure | password | Distinct account targeted |
| 10:00:31 | EVT-002003 | carol | 198.51.100.40 | login_failure | password | Distinct account targeted |
| 10:00:45 | EVT-002004 | david | 198.51.100.40 | login_failure | password | Distinct account targeted |
| 10:01:02 | EVT-002005 | erin | 198.51.100.40 | login_failure | password | Distinct account targeted |
| 10:01:18 | EVT-002006 | frank | 198.51.100.40 | login_failure | password | Distinct account targeted |
| 10:01:34 | EVT-002007 | grace | 198.51.100.40 | login_failure | password | Seventh distinct account targeted |
| 10:01:51 | EVT-002008 | alice | 198.51.100.40 | login_success | password | Successful authentication observed |
| 10:02:20 | EVT-002009 | bob | 198.51.100.40 | login_failure | password | Spray activity continues |
| 10:02:44 | EVT-002010 | carol | 198.51.100.40 | login_failure | password | Spray activity continues |
| 10:03:11 | EVT-002011 | david | 198.51.100.40 | login_failure | password | Spray activity continues |
| 10:03:39 | EVT-002012 | erin | 198.51.100.40 | login_failure | password | Spray activity continues |
| 10:04:02 | EVT-002013 | frank | 198.51.100.40 | login_failure | password | Spray activity continues |
| 10:04:28 | EVT-002014 | grace | 198.51.100.40 | login_failure | password | Last observed spray failure |
| 10:05:01 | EVT-002015 | heidi | 203.0.113.45 | login_failure | password | Separate source; outside detected spray |
| 10:05:19 | EVT-002016 | heidi | 203.0.113.45 | login_failure | password | Separate source; outside detected spray |
| 10:06:02 | EVT-002017 | alice | 192.0.2.21 | login_success | publickey | Expected-source baseline event |
| 10:06:37 | EVT-002018 | bob | 192.0.2.22 | login_failure | password | Separate source |
| 10:07:03 | EVT-002019 | bob | 192.0.2.22 | login_success | publickey | Expected public-key authentication |
| 10:07:41 | EVT-002020 | carol | 192.0.2.23 | login_success | publickey | Expected public-key authentication |

## Attack Sequence

### Initial Account Targeting

Between `10:00:03Z` and `10:01:34Z`, the source `198.51.100.40` generated seven password authentication failures against seven different users.

The rapid change of targeted username while maintaining the same source IP and destination host is consistent with password spraying.

### Successful Authentication

At `10:01:51Z`, `EVT-002008` recorded a successful password authentication for `alice` from the same source.

This event is important because it occurred during the broader suspicious authentication sequence.

The telemetry does not establish that the successful authentication represents unauthorized access or that the credentials used were obtained through the preceding failures.

### Continued Failed Authentication

Following the successful `alice` authentication, the same source continued attempting password authentication against `bob`, `carol`, `david`, `erin`, `frank`, and `grace` through `10:04:28Z`.

This continued activity strengthens the interpretation that the source was systematically testing multiple accounts rather than performing an isolated login attempt.

## Post-Detection Contrast Events

`EVT-002015` and `EVT-002016` show two password failures for `heidi` from `203.0.113.45`. These events use a different source IP and therefore are not attributed to the detected `198.51.100.40` spray.

`EVT-002017`, `EVT-002019`, and `EVT-002020` record successful public-key authentication from separate sources. Their telemetry identifies those sources as expected and does not connect them to the detected password-spraying sequence.

These events provide useful negative or contrast evidence but do not independently prove that the case source was malicious.

## Temporal Findings

- First detected failure: `10:00:03Z`
- First seven-account coverage completed: `10:01:34Z`
- Successful `alice` authentication: `10:01:51Z`
- Continued spray activity after successful authentication: `10:02:20Z`–`10:04:28Z`
- Last detected failure: `10:04:28Z`
- Total detected sequence duration: 4 minutes 25 seconds
- Failed attempts attributed to detected source: 13
- Distinct targeted users: 7

## Investigation Significance

The timeline supports the automated detection because the observed events satisfy the configured five-minute password-spraying criteria.

The successful `alice` authentication raises the priority of the investigation, but the timeline alone does not demonstrate:

- account compromise
- unauthorized access
- privilege escalation
- persistence
- lateral movement
- data access
- data exfiltration

Those conclusions require additional post-authentication evidence.

## Evidence Limitation

This timeline is based exclusively on the supplied synthetic laboratory authentication telemetry.

Timestamps and event attributes represent observed laboratory evidence. Interpretive statements are explicitly separated from observed facts, and no real-world attribution or production compromise is inferred.
