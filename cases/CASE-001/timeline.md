# CASE-001 — Investigation Timeline

## 1. Timeline Purpose

This timeline reconstructs the authentication activity associated with CASE-001 using the original telemetry stored in:

`telemetry/authentication/CASE-001-authentication-events.jsonl`

The timeline preserves the distinction between:

- **Observed evidence** — directly represented by telemetry events.
- **Analyst interpretation** — conclusions drawn from observed event relationships.
- **Hypothesis** — a possible explanation requiring additional validation.

All timestamps are represented in UTC.

---

## 2. Event Timeline

| Time (UTC) | Event ID | Source IP | User | Action | Status | Protocol | Analyst Note |
|---|---|---|---|---|---|---|---|
| 2026-09-08 09:10:00 | EVT-001001 | 192.0.2.21 | alice | login | success | SSH | Successful public-key authentication. |
| 2026-09-08 09:10:18 | EVT-001002 | 192.0.2.22 | bob | login | failure | SSH | Single failed authentication attempt. |
| 2026-09-08 09:10:32 | EVT-001003 | 192.0.2.22 | bob | login | success | SSH | Successful authentication follows one failure. |
| 2026-09-08 09:14:03 | EVT-001004 | 198.51.100.25 | root | login_failure | failure | SSH | First observed failed authentication in the detected sequence. |
| 2026-09-08 09:14:11 | EVT-001005 | 198.51.100.25 | root | login_failure | failure | SSH | Second failed authentication. |
| 2026-09-08 09:14:19 | EVT-001006 | 198.51.100.25 | root | login_failure | failure | SSH | Third failed authentication. |
| 2026-09-08 09:14:27 | EVT-001007 | 198.51.100.25 | root | login_failure | failure | SSH | Fourth failed authentication. |
| 2026-09-08 09:14:35 | EVT-001008 | 198.51.100.25 | root | login_failure | failure | SSH | Fifth failed authentication; DET-AUTH-001 threshold reached. |
| 2026-09-08 09:14:43 | EVT-001009 | 198.51.100.25 | root | login_failure | failure | SSH | Sixth failed authentication after threshold. |
| 2026-09-08 09:14:51 | EVT-001010 | 198.51.100.25 | root | login_failure | failure | SSH | Seventh failed authentication after threshold. |
| 2026-09-08 09:15:01 | EVT-001011 | 198.51.100.25 | root | login_failure | failure | SSH | Eighth failed authentication after threshold. |
| 2026-09-08 09:15:09 | EVT-001012 | 198.51.100.25 | root | login | success | SSH | Successful root authentication follows eight failures from the same source. |
| 2026-09-08 09:16:20 | EVT-001013 | 192.0.2.23 | alice | login | success | SSH | Successful public-key authentication. |
| 2026-09-08 09:17:00 | EVT-001014 | 203.0.113.45 | admin | login_failure | failure | SSH | Failed authentication attempt. |
| 2026-09-08 09:17:12 | EVT-001015 | 203.0.113.45 | admin | login_failure | failure | SSH | Second failed authentication. |
| 2026-09-08 09:17:24 | EVT-001016 | 203.0.113.45 | admin | login_failure | failure | SSH | Third failed authentication. |
| 2026-09-08 09:17:36 | EVT-001017 | 203.0.113.45 | admin | login_failure | failure | SSH | Fourth failed authentication; below DET-AUTH-001 threshold. |
| 2026-09-08 09:20:00 | EVT-001018 | 192.0.2.21 | alice | login | success | SSH | Successful public-key authentication. |
| 2026-09-08 09:21:00 | EVT-001019 | 192.0.2.22 | bob | login | success | SSH | Successful public-key authentication. |
| 2026-09-08 09:22:00 | EVT-001020 | 192.0.2.23 | alice | login | success | SSH | Successful public-key authentication. |

---

## 3. Detection-Relevant Sequence

The primary detection sequence is:

198.51.100.25
       │
       ├── EVT-001004  Failed SSH authentication
       ├── EVT-001005  Failed SSH authentication
       ├── EVT-001006  Failed SSH authentication
       ├── EVT-001007  Failed SSH authentication
       ├── EVT-001008  Failed SSH authentication
       │                └── DET-AUTH-001 threshold reached
       ├── EVT-001009  Failed SSH authentication
       ├── EVT-001010  Failed SSH authentication
       ├── EVT-001011  Failed SSH authentication
       └── EVT-001012  Successful SSH authentication

Observed sequence:

8 failed SSH authentication attempts → successful root SSH authentication

Detection threshold:

5 failed attempts within 5 minutes

Observed failed-attempt count:

8

4. Temporal Analysis
4.1 First Detection-Relevant Failure
Event: EVT-001004
Timestamp: 2026-09-08T09:14:03Z
Source IP: 198.51.100.25
User: root
Action: login_failure

This is the beginning of the primary suspicious authentication sequence.

4.2 Threshold Reached
Event: EVT-001008
Timestamp: 2026-09-08T09:14:35Z
Failed attempts in sequence: 5

The fifth failed authentication occurs approximately 32 seconds after the first failure.

This satisfies the DET-AUTH-001 condition of at least five failed SSH authentication attempts within five minutes for the same source IP and user.

4.3 Continued Authentication Failures

Three additional failed attempts occur after the threshold:

EVT-001009
EVT-001010
EVT-001011

The sequence therefore reaches eight failed attempts before the successful authentication.

4.4 Successful Authentication
Event: EVT-001012
Timestamp: 2026-09-08T09:15:09Z
Source IP: 198.51.100.25
User: root
Status: success

The successful authentication occurs approximately 66 seconds after the first detection-relevant failure.

The telemetry therefore establishes an observed sequence of repeated authentication failures followed by a successful authentication using the same source IP and user.

5. Supporting Authentication Activity

Additional authentication events provide useful comparison context.

5.1 Bob — 192.0.2.22

Observed:

EVT-001002 — one failed authentication.
EVT-001003 — successful authentication.

This represents a single failure followed by success and does not meet the DET-AUTH-001 threshold.

5.2 Admin — 203.0.113.45

Observed:

EVT-001014 — failure.
EVT-001015 — failure.
EVT-001016 — failure.
EVT-001017 — failure.

Four failed attempts are observed without a subsequent successful authentication in the provided telemetry.

This remains below the five-failure detection threshold.

5.3 Normal Successful Authentication Activity

Successful public-key authentications are observed from:

192.0.2.21
192.0.2.23
192.0.2.22

These events provide baseline authentication activity for comparison against the suspicious password-failure sequence.

6. Evidence Classification
Observed Evidence

The telemetry directly establishes:

Eight failed SSH authentication attempts occurred for user root.
All eight failures originated from 198.51.100.25.
The failures occurred within the DET-AUTH-001 five-minute detection window.
A successful SSH authentication for root was subsequently observed from 198.51.100.25.
The detection engine generated ALERT-CASE-001-DET-AUTH-001.
The successful authentication event is EVT-001012.
Analyst Interpretation

The sequence is consistent with a potential SSH brute-force or password-guessing attempt.

The successful authentication following repeated failures increases investigative priority because the same source IP and target account are involved.

Hypothesis

A possible hypothesis is:

An unauthorized actor may have repeatedly attempted to authenticate to the root account and subsequently obtained successful authentication.

This hypothesis requires additional evidence before compromise can be confirmed.

7. What the Timeline Does Not Establish

The authentication telemetry alone does not establish:

who controlled 198.51.100.25;
whether the successful authentication was authorized;
whether the correct password was guessed;
whether credentials were obtained elsewhere;
whether the root account was actually compromised;
whether commands were executed after authentication;
whether persistence was established;
whether data was accessed or exfiltrated;
whether the source system itself was compromised.

These questions require additional endpoint, identity, network, or other authorized laboratory evidence.

8. Investigation Pivot Points

The following events should be prioritized for further investigation:

Priority	Event	Reason
High	EVT-001012	Successful root authentication after eight failures.
High	EVT-001004–EVT-001011	Complete failed-authentication sequence supporting the alert.
Medium	EVT-001014–EVT-001017	Separate repeated failures from another source.
Low	EVT-001002–EVT-001003	Single failure followed by success; useful for baseline comparison.
9. Recommended Next Evidence

The next investigation phase should attempt to correlate the authentication sequence with:

SSH session activity after EVT-001012.
Endpoint process activity on lab-auth-01.
Commands executed by the root account, if available in the laboratory telemetry.
Network connections initiated after successful authentication.
Account and privilege changes.
File modifications.
Persistence mechanisms.
Additional authentication activity from 198.51.100.25.
Related indicators across available laboratory telemetry.

No additional evidence should be represented as observed until it exists in the authorized telemetry dataset.

10. Timeline Determination

Current determination: Suspicious authentication sequence requiring further investigation.

The evidence supports escalation from a medium-severity authentication detection to a high-priority investigation because eight failed SSH authentication attempts against root were followed by a successful authentication from the same source IP.

The successful authentication is an observed event, but it is not sufficient by itself to confirm account compromise.

11. Evidence References

Primary telemetry:

telemetry/authentication/CASE-001-authentication-events.jsonl

Detection:

detections/authentication/DET-AUTH-001-ssh-brute-force.yml

Generated alert:

alerts/CASE-001-DET-AUTH-001.json

Preserved case alert:

cases/CASE-001/alert.json

Case record:

cases/CASE-001/README.md
