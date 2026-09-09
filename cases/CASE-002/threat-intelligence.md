# CASE-002 — Threat Intelligence Assessment

## Intelligence Summary

CASE-002 contains synthetic authentication telemetry representing a password-spraying pattern against an SSH service.

The strongest intelligence value in this case is behavioral rather than reputation-based. The observed source `198.51.100.40` attempted password authentication against multiple accounts on `lab-auth-01` within a short period.

No external reputation, attribution, or real-world maliciousness claim is made for the source IP because this case uses laboratory telemetry.

## Observed Behavioral Intelligence

The following characteristics support a password-spraying assessment:

- One source IP targeted multiple user accounts.
- Password authentication was used.
- Seven distinct users were targeted.
- 13 failed attempts were observed.
- The activity occurred within approximately 4 minutes and 25 seconds.
- The source continued authentication attempts after a successful login for `alice`.
- The same source and destination host were maintained while the targeted username changed.

This behavior is more consistent with broad credential testing than with repeated authentication failures against one account.

## ATT&CK Context

The observed behavior maps to:

- **T1110 — Brute Force**
- **T1110.003 — Password Spraying**

The ATT&CK mapping describes the observed authentication behavior. It does not establish:

- actor identity
- motivation
- successful credential compromise
- unauthorized access
- persistence
- lateral movement

## Indicator Assessment

### Source IP

`198.51.100.40`

Assessment:

- Observed as the common source of the detected password-spraying activity.
- Suitable for correlation within an authorized environment.
- Not classified as globally malicious based on this laboratory case.
- Reputation and ownership are intentionally not asserted.

### Target Host

`lab-auth-01`

Assessment:

- Laboratory authentication host.
- Confirmed destination for the detected authentication sequence.
- Useful as a pivot for host-level authentication and session investigation.

### Targeted Accounts

The observed targeted users are:

- `alice`
- `bob`
- `carol`
- `david`
- `erin`
- `frank`
- `grace`

These usernames are laboratory identities and should not be interpreted as real-world identities.

## Successful Authentication Intelligence

`EVT-002008` records a successful password authentication for `alice` from `198.51.100.40`.

This is an important intelligence signal because the successful authentication occurred during the broader password-spraying sequence.

However, the event does not provide sufficient intelligence to determine whether:

- the authentication was authorized
- the correct credential was intentionally used
- the credential was obtained through the preceding attempts
- the resulting session was malicious
- the account was subsequently abused

The correct analytical position is therefore:

**Successful authentication observed; compromise not established.**

## Intelligence Gaps

The current telemetry does not provide:

- source ownership information
- source reputation
- geographic attribution
- identity-provider context
- account risk information
- authentication history outside this dataset
- SSH session identifiers
- post-authentication commands
- privilege escalation telemetry
- endpoint activity
- network activity after successful authentication
- file or configuration changes
- credential-reset information
- evidence of lateral movement
- evidence of data access or exfiltration

These gaps prevent a complete determination of impact or compromise.

## Recommended Intelligence Pivots

In an authorized environment, investigators should correlate:

1. `198.51.100.40` across authentication logs.
2. `198.51.100.40` across other monitored hosts.
3. `alice` authentication history before and after `EVT-002008`.
4. SSH session activity associated with the successful login.
5. Privileged command execution after successful authentication.
6. Account changes or password resets.
7. Endpoint telemetry for `lab-auth-01`.
8. Network connections originating from the authenticated session.
9. Similar multi-account authentication patterns from other sources.
10. Repeated targeting of the same user set across time.

## Detection-Evasion Considerations

A password-spraying operator could attempt to reduce detection visibility by:

- rotating source IP addresses
- increasing the delay between attempts
- distributing attempts across multiple hosts
- reducing the number of targeted users per source
- using multiple authentication methods
- blending attempts with normal authentication traffic

These techniques are relevant to detection engineering but are not observed in this case.

## Detection Improvement Opportunities

Future detection engineering could consider:

- correlation across multiple source IPs
- longer behavioral windows for low-and-slow activity
- account-centric aggregation
- host-centric aggregation
- source reputation only when backed by trusted intelligence
- identity-provider context
- successful-authentication escalation within a bounded investigation window
- correlation with post-authentication session activity

Any such improvement should be validated against both positive and negative laboratory telemetry before deployment.

## Intelligence Confidence

| Assessment | Confidence |
|---|---|
| Password-spraying behavior observed | High |
| Source IP associated with detected activity | High |
| Seven accounts targeted | High |
| Successful password authentication observed | High |
| Unauthorized authentication | Not established |
| Account compromise | Not established |
| Persistence | Not established |
| Lateral movement | Not established |
| Data access or exfiltration | Not established |
| Real-world attribution | Not established |

## Laboratory Limitation

This assessment is based on synthetic SOC laboratory telemetry.

The IP addresses, usernames, hostnames, and authentication events are test data. They are intended to demonstrate defensive investigation methodology and detection engineering rather than provide real-world threat attribution or reputation intelligence.
