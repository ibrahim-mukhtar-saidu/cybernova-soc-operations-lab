# CASE-004 — Investigation Timeline

## Timeline Overview

This timeline reconstructs the observed authentication-to-session sequence associated with:

- **Case:** `CASE-004`
- **Alert:** `ALERT-CASE-004-DET-AUTH-003`
- **Detection:** `DET-AUTH-003`
- **Detection Name:** Suspicious Post-Authentication Privileged Session
- **Host:** `lab-linux-01`
- **User:** `admin`
- **Source IP:** `198.51.100.60`
- **Session:** `SES-004-C`
- **Observation Window:** `2026-09-08T11:22:03+00:00` to `2026-09-08T11:24:19+00:00`
- **Severity:** High
- **Confidence:** High

All timestamps represented in the alert artifact are in UTC.

---

## 1. Chronological Event Sequence

| Event ID | Event Type | Activity | Account | Source IP | Host | Session | Evidence Significance |
|---|---|---|---|---|---|---|---|
| `EVT-004003` | Authentication | Failed password authentication | `admin` | `198.51.100.60` | `lab-linux-01` | — | First failed authentication in the correlated sequence |
| `EVT-004004` | Authentication | Failed password authentication | `admin` | `198.51.100.60` | `lab-linux-01` | — | Repeated authentication failure |
| `EVT-004005` | Authentication | Failed password authentication | `admin` | `198.51.100.60` | `lab-linux-01` | — | Repeated authentication failure |
| `EVT-004006` | Authentication | Failed password authentication | `admin` | `198.51.100.60` | `lab-linux-01` | — | Fourth failed authentication preceding successful login |
| `EVT-004007` | Authentication | Successful password authentication | `admin` | `198.51.100.60` | `lab-linux-01` | `SES-004-C` | Successful authentication follows four failures |
| `EVT-004008` | Session | Session start | `admin` | `198.51.100.60` | `lab-linux-01` | `SES-004-C` | Establishes the correlated post-authentication session |
| `EVT-004009` | Command Execution | `whoami` | `admin` | `198.51.100.60` | `lab-linux-01` | `SES-004-C` | Identity discovery activity |
| `EVT-004010` | Command Execution | `id` | `admin` | `198.51.100.60` | `lab-linux-01` | `SES-004-C` | Account, group, and privilege-context discovery |
| `EVT-004011` | Command Execution | `sudo -l` | `admin` | `198.51.100.60` | `lab-linux-01` | `SES-004-C` | Sudo permission enumeration |
| `EVT-004012` | Command Execution | `uname -a` | `admin` | `198.51.100.60` | `lab-linux-01` | `SES-004-C` | System information discovery |

---

## 2. Timestamp Precision

The alert artifact provides the exact overall observation boundaries:

- **First seen:** `2026-09-08T11:22:03+00:00`
- **Last seen:** `2026-09-08T11:24:19+00:00`

The generated alert identifies all ten supporting events but does not expose individual timestamps for every supporting event.

Therefore, this timeline intentionally uses event sequence order rather than inventing timestamps for events whose exact timestamps are not present in the alert artifact.

The authoritative source for individual event timestamps remains:

`telemetry/authentication/CASE-004-authentication-events.jsonl`

---

## 3. Authentication Phase

The initial phase consists of four failed password authentication attempts against the same account:

```text
EVT-004003
      |
      v
EVT-004004
      |
      v
EVT-004005
      |
      v
EVT-004006

Common attributes:

User: admin
Source IP: 198.51.100.60
Host: lab-linux-01
Protocol: SSH
Authentication method: password
Result: authentication failure

The four failures satisfy the minimum failed-authentication requirement configured by DET-AUTH-003.

4. Successful Authentication

The sequence then transitions to:

EVT-004007 — Successful password authentication

Relevant correlation attributes:

User: admin
Source IP: 198.51.100.60
Host: lab-linux-01
Session: SES-004-C

The successful authentication is significant because it follows the four failed authentication attempts within the detection correlation window.

This transition is one of the primary reasons the detection escalates the sequence.

5. Session Establishment

Following successful authentication, the telemetry records:

EVT-004008 — Session start

Session identifier:

SES-004-C

The shared session identifier allows the authentication event and subsequent command execution activity to be correlated into a single observed session.

This correlation is important because isolated authentication failures or isolated administrative commands would provide substantially less context.

6. Post-Authentication Command Activity

Four command execution events were correlated with SES-004-C.

EVT-004009

Command:

whoami

Assessment:

The command identifies the current execution identity.

This is commonly used by legitimate administrators and therefore is not inherently malicious.

Within this case, however, it forms part of the broader post-authentication activity sequence.

EVT-004010

Command:

id

Assessment:

The command provides account and group information and can reveal the current privilege context.

The detection treats this as a privileged-account or privilege-context enumeration indicator.

The command itself is not inherently malicious.

EVT-004011

Command:

sudo -l

Assessment:

The command enumerates the commands the current account may execute through sudo.

This is treated as a privilege-related enumeration indicator by DET-AUTH-003.

The command can be legitimate administrative activity and does not independently establish malicious intent.

EVT-004012

Command:

uname -a

Assessment:

The command retrieves system information such as the kernel and operating-system details.

This is consistent with system discovery activity.

It is not inherently malicious and must be interpreted within the wider authentication and session context.

7. Complete Evidence Chain

The observed sequence can be represented as:

             AUTHENTICATION PHASE
                    |
                    v
      +-----------------------------+
      | 4 failed password attempts  |
      | EVT-004003 -> EVT-004006    |
      +--------------+--------------+
                     |
                     v
      +-----------------------------+
      | Successful authentication   |
      | EVT-004007                  |
      +--------------+--------------+
                     |
                     v
      +-----------------------------+
      | Session established         |
      | EVT-004008                  |
      | SES-004-C                   |
      +--------------+--------------+
                     |
                     v
          POST-AUTHENTICATION
             ACTIVITY PHASE
                     |
       +-------------+-------------+
       |             |             |
       v             v             v
   EVT-004009    EVT-004010    EVT-004011
     whoami          id          sudo -l
       |             |             |
       +-------------+-------------+
                     |
                     v
                EVT-004012
                 uname -a

The complete chain contains:

4 failed authentications
1 successful authentication
1 session-start event
4 post-authentication command events
2 privileged activity indicators
10 supporting events in total
8. Detection Correlation

DET-AUTH-003 correlates the sequence using:

Same source IP
Same user
Same host
SSH authentication context
Failed authentication sequence
Successful authentication
Session identifier
Post-authentication command execution
Privileged activity indicators
Five-minute correlation window

The generated alert confirms that all required conditions were satisfied.

9. Detection Outcome

The detection engine generated:

Alert ID: ALERT-CASE-004-DET-AUTH-003

Severity: High

Confidence: High

Alert status: Open

Evidence classification: observed_evidence

The alert contains ten supporting event IDs:

EVT-004003
EVT-004004
EVT-004005
EVT-004006
EVT-004007
EVT-004008
EVT-004009
EVT-004010
EVT-004011
EVT-004012
10. Timeline Assessment

The most significant transition in the timeline is the successful authentication of the admin account after four failed password authentication attempts from the same source.

The subsequent session activity increases the investigative significance because the account performed identity, privilege, and system discovery commands.

The combination of these events is sufficient to classify the sequence as suspicious and to justify the High severity and High confidence detection outcome.

However, the commands observed are individually compatible with legitimate administrative activity.

The timeline therefore supports suspicious activity observed, rather than confirmed malicious activity.

11. Evidence Classification
Observed Evidence

The following are directly represented by the laboratory telemetry:

Four failed password authentication attempts.
Successful password authentication.
Source IP 198.51.100.60.
Account admin.
Host lab-linux-01.
Session SES-004-C.
Session establishment.
Four post-authentication commands.
id command.
sudo -l command.
whoami command.
uname -a command.
Correlation of all ten supporting events.
Analyst Interpretation

The observed sequence is consistent with suspicious authentication followed by privileged-account session activity and system/privilege enumeration.

Hypothesis

A possible investigative hypothesis is that an unauthorized actor may have attempted to authenticate to the privileged account and, after succeeding, performed initial discovery activity.

This remains a hypothesis.

Confirmed Finding

The following finding is confirmed within the laboratory:

A suspicious authentication-to-session sequence involving the admin account was observed and successfully detected by DET-AUTH-003.

The following are not confirmed:

Account compromise.
Credential theft.
Unauthorized access.
Malicious intent.
Persistence.
Lateral movement.
Data access.
Data exfiltration.
Successful privilege escalation.
12. MITRE ATT&CK Context

The detection specification associates the observed behavior with the following techniques:

Technique	Name	Timeline Relevance
T1110	Brute Force	Four failed authentication attempts precede successful authentication
T1078	Valid Accounts	Successful authentication using the admin account
T1087	Account Discovery	whoami and id provide identity/account context
T1069.001	Permission Groups Discovery: Local	id provides group and privilege-context information
T1059.004	Unix Shell	Shell-based post-authentication command execution

These mappings provide behavioral classification for the observed telemetry. They do not independently prove malicious use of any technique.

13. Investigation Gaps

The current timeline does not establish:

Whether source IP 198.51.100.60 was authorized.
Whether the admin account owner initiated the session.
Whether the password authentication was legitimate.
Whether the observed commands were routine administrative activity.
Whether additional commands occurred outside the captured telemetry.
Whether credentials were compromised.
Whether persistence was established.
Whether lateral movement occurred.
Whether data was accessed or exfiltrated.
Whether privilege escalation actually occurred.

These questions require additional telemetry and identity validation.

14. Recommended Follow-Up

The investigation should continue with:

Validate whether the admin login was authorized.
Validate ownership and expected use of source IP 198.51.100.60.
Review the complete SSH history for session SES-004-C.
Review commands immediately before and after the observed sequence.
Correlate with endpoint telemetry from lab-linux-01.
Correlate with network telemetry involving the source IP.
Search for additional failed authentications involving admin.
Search for successful authentications involving admin from the same source.
Search for the same source IP against other accounts or hosts.
Escalate to account-compromise response procedures if unauthorized access is confirmed.
15. Current Case Determination

Classification: Suspicious activity observed

Severity: High

Confidence: High

- **Compromise status:** Not confirmed

Current state: Open / Continue Investigation

The available evidence demonstrates a high-confidence suspicious authentication-to-session sequence involving the privileged admin account. DET-AUTH-003 correctly identified and correlated the sequence.

The evidence is sufficient to warrant continued investigation but is insufficient to independently prove account compromise or malicious intent.

16. Evidence Integrity Note

This case is part of the CYBERNOVA SOC Operations Laboratory and uses synthetic, authorized laboratory telemetry.

The IP addresses used in this scenario belong to documentation/test address space and must not be interpreted as real-world malicious infrastructure.

All conclusions in this timeline are limited to the evidence represented by the laboratory dataset.
