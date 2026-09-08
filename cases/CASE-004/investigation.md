# CASE-004 — Investigation

## 1. Investigation Overview

**Case ID:** CASE-004  
**Detection:** DET-AUTH-003 — Suspicious Post-Authentication Privileged Session  
**Alert ID:** ALERT-CASE-004-DET-AUTH-003  
**Severity:** High  
**Confidence:** High  
**Status:** Open  
**Evidence classification:** Observed evidence

This investigation examines a suspicious SSH authentication-to-session sequence involving the `admin` account on `lab-linux-01`.

The observed sequence contains four failed password authentication attempts from source IP `198.51.100.60`, followed by successful authentication, session establishment, and four post-authentication command executions. The commands include `id` and `sudo -l`, which are treated as privileged-account and privilege-related enumeration indicators.

The available telemetry supports classification of the sequence as suspicious activity. It does not independently establish that the account was compromised or that the observed activity was malicious.

---

## 2. Alert Summary

The detection engine generated one alert:

| Field | Value |
|---|---|
| Alert ID | `ALERT-CASE-004-DET-AUTH-003` |
| Detection | `DET-AUTH-003` |
| Detection name | Suspicious Post-Authentication Privileged Session |
| Severity | High |
| Confidence | High |
| Source IP | `198.51.100.60` |
| Host | `lab-linux-01` |
| User | `admin` |
| Session | `SES-004-C` |
| Failed authentications | 4 |
| Successful authentication | `EVT-004007` |
| Session start | `EVT-004008` |
| Post-authentication commands | 4 |
| Correlation window | 5 minutes |
| First observed | `2026-09-08T11:22:03+00:00` |
| Last observed | `2026-09-08T11:24:19+00:00` |

---

## 3. Initial Triage

The alert was reviewed against the detection criteria.

The observed sequence satisfies the primary escalation conditions:

- Four failed password authentication attempts occurred against the same account and source IP.
- A successful authentication followed the failed attempts.
- The successful authentication established session `SES-004-C`.
- A correlated session-start event was observed.
- Four post-authentication command events were observed.
- Privileged activity indicators `id` and `sudo -l` were present.

The combination of authentication failures, subsequent successful authentication, privileged account usage, and post-authentication enumeration warrants further investigation.

---

## 4. Authentication Analysis

The authentication sequence associated with the alert is:

| Event | Activity | Source | User |
|---|---|---|---|
| `EVT-004003` | Failed authentication | `198.51.100.60` | `admin` |
| `EVT-004004` | Failed authentication | `198.51.100.60` | `admin` |
| `EVT-004005` | Failed authentication | `198.51.100.60` | `admin` |
| `EVT-004006` | Failed authentication | `198.51.100.60` | `admin` |
| `EVT-004007` | Successful authentication | `198.51.100.60` | `admin` |

The four failures and subsequent successful authentication form the primary authentication anomaly.

The source IP is part of the synthetic documentation/test address space used by this laboratory. It must therefore not be treated as a real-world malicious IP address.

---

## 5. Session Correlation

The successful authentication event `EVT-004007` is associated with session `SES-004-C`.

The subsequent session-start event is:

- **Event:** `EVT-004008`
- **Session:** `SES-004-C`
- **User:** `admin`
- **Host:** `lab-linux-01`
- **Privilege context:** `admin`

The shared session identifier provides a correlation point between authentication and subsequent activity.

---

## 6. Post-Authentication Activity

Four command execution events were correlated with session `SES-004-C`:

| Event | Command | Activity interpretation |
|---|---|---|
| `EVT-004009` | `whoami` | Identity discovery |
| `EVT-004010` | `id` | Account/group and privilege context discovery |
| `EVT-004011` | `sudo -l` | Sudo permission enumeration |
| `EVT-004012` | `uname -a` | System information discovery |

The commands are not inherently malicious. They are commonly used by administrators and legitimate users.

However, in combination with the preceding failed authentication attempts and subsequent successful login to a privileged account, they increase the investigative significance of the sequence.

---

## 7. Evidence Assessment

### Observed Evidence

The following facts are directly represented in the telemetry:

- Four failed password authentication attempts.
- Successful authentication of `admin` from the same source IP.
- Session `SES-004-C`.
- Four post-authentication command executions.
- `id` and `sudo -l` activity.
- Source IP `198.51.100.60`.
- Host `lab-linux-01`.

### Analyst Interpretation

The telemetry represents a suspicious authentication-to-session sequence involving a privileged account followed by account, privilege, and system enumeration.

### Hypothesis

A possible hypothesis is that an unauthorized actor obtained or used valid credentials after repeated authentication attempts and then performed initial post-authentication discovery.

This remains a hypothesis until additional evidence establishes authorization status, credential ownership, source attribution, or malicious intent.

### Confirmed Finding

**Confirmed:** Suspicious authentication and post-authentication activity was observed and successfully detected by `DET-AUTH-003`.

**Not confirmed:** Account compromise, unauthorized access, credential theft, or malicious intent.

---

## 8. MITRE ATT&CK Mapping

The detection maps the observed behavior to the following ATT&CK techniques:

| Technique | Name | Relevance |
|---|---|---|
| `T1110` | Brute Force | Repeated failed authentication attempts |
| `T1078` | Valid Accounts | Successful authentication using the `admin` account |
| `T1087` | Account Discovery | `whoami` / `id` activity |
| `T1069.001` | Permission Groups Discovery: Local | `id` / privilege-context discovery |
| `T1059.004` | Unix Shell | Bash command execution |

These mappings describe behavioral similarities and should not be interpreted as proof that an ATT&CK technique was maliciously executed.

---

## 9. Investigation Gaps

The current telemetry does not establish:

- Whether `198.51.100.60` was authorized to access `lab-linux-01`.
- Whether the `admin` account owner initiated the session.
- Whether the password was legitimately entered.
- Whether the commands were part of normal administration.
- Whether additional commands occurred outside the observed telemetry window.
- Whether credentials were compromised.
- Whether persistence, lateral movement, or data access occurred.

Additional identity, endpoint, network, and session telemetry would be required to answer these questions.

---

## 10. Recommended Investigative Actions

1. Verify ownership and expected use of the `admin` account.
2. Determine whether the source IP was authorized for the account and host.
3. Review the complete SSH/session history for `SES-004-C`.
4. Correlate authentication activity with endpoint and network telemetry.
5. Search for additional authentication failures involving the same source IP.
6. Search for other successful authentications involving the `admin` account.
7. Review commands executed before and after the observed four-command sequence.
8. If unauthorized access is confirmed, initiate the organization's account-compromise response procedure.
9. Preserve relevant telemetry before containment or credential changes where operationally appropriate.

---

## 11. Current Determination

**Classification:** Suspicious activity observed.

The laboratory telemetry demonstrates a high-confidence suspicious authentication-to-session sequence involving the privileged `admin` account. The sequence was correctly detected by `DET-AUTH-003`.

The available evidence is insufficient to independently confirm account compromise or malicious intent.

**Recommended case state:** Continue investigation pending authorization and identity validation.
