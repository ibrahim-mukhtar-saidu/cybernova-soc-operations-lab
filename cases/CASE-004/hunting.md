# CASE-004 — Threat Hunting

## 1. Document Control

| Field | Value |
|---|---|
| Case ID | CASE-004 |
| Alert ID | ALERT-CASE-004-DET-AUTH-003 |
| Detection | DET-AUTH-003 |
| Detection Name | Suspicious Post-Authentication Privileged Session |
| Host | lab-linux-01 |
| User | admin |
| Source IP | 198.51.100.60 |
| Session | SES-004-C |
| Severity | High |
| Confidence | High |
| Environment | Synthetic authorized SOC laboratory |

---

## 2. Hunting Objective

The objective of this hunt is to determine whether the suspicious authentication-to-session sequence observed in CASE-004 is isolated or part of a broader behavioral pattern.

The hunt focuses on:

- repeated authentication failures
- successful authentication following failures
- privileged-account authentication
- post-authentication command execution
- account discovery
- privilege enumeration
- repeated source activity
- activity across additional hosts
- possible session expansion

The hunt must distinguish observed evidence from analyst interpretation and hypothesis.

---

## 3. Primary Hunting Hypothesis

### Hypothesis H-004-01

> An unauthorized actor may have obtained or used valid credentials for the `admin` account, authenticated through SSH after repeated failures, and performed account or privilege discovery after establishing a session.

This is a hypothesis only.

The available CASE-004 telemetry does not independently confirm credential compromise or malicious intent.

---

## 4. Secondary Hunting Hypotheses

### Hypothesis H-004-02 — Source Expansion

The source IP may have attempted authentication against additional accounts or hosts.

### Hypothesis H-004-03 — Account Expansion

The same source may have targeted other privileged or high-value accounts.

### Hypothesis H-004-04 — Session Expansion

The `admin` account may have established additional sessions from the same or other sources.

### Hypothesis H-004-05 — Post-Authentication Discovery

The same account or source may have executed similar discovery commands after authentication.

### Hypothesis H-004-06 — Persistence or Follow-On Activity

Additional telemetry may reveal persistence, privilege changes, file modification, or network activity following the suspicious session.

---

## 5. Observed Evidence Driving the Hunt

The initial alert is based on:

```text
4 failed password authentications
        |
        v
successful password authentication
        |
        v
session start
        |
        v
whoami
        |
        v
id
        |
        v
sudo -l
        |
        v
uname -a

Correlation:

Source IP: 198.51.100.60
Host:      lab-linux-01
User:      admin
Session:   SES-004-C

Supporting events:

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
6. Hunt Data Sources

A real authorized SOC hunt should consider the following sources.

Data Source	Hunt Purpose
SSH authentication logs	Identify failures and successful authentication
Identity provider logs	Correlate account and authentication behavior
VPN logs	Determine source ownership and access path
Endpoint telemetry	Identify post-authentication processes
Linux audit logs	Investigate command and privilege activity
Shell history	Review interactive command activity where legally and operationally appropriate
Firewall logs	Identify network activity
DNS logs	Identify domain resolution
EDR telemetry	Identify process, file, and persistence activity
File-integrity telemetry	Identify system modifications
Privilege escalation logs	Identify sudo or privilege changes
7. Hunt Query Concept — Source IP
Objective

Determine whether 198.51.100.60 generated authentication activity against other accounts or hosts.

Conceptual query
authentication
WHERE source_ip = "198.51.100.60"
GROUP BY host, user, action, status
ORDER BY timestamp
Expected result

The analyst should identify:

number of targeted hosts
number of targeted accounts
failed authentication count
successful authentication count
authentication methods
time range
CASE-004 expectation

The supplied dataset contains activity against:

Host: lab-linux-01
User: admin

The source is a documentation/test address.

8. Hunt Query Concept — Failed-to-Successful Authentication
Objective

Identify authentication sequences in which multiple failures are followed by a successful login.

Conceptual logic
For each source_ip + user:

1. Find failed password authentication events.
2. Count failures inside a 5-minute window.
3. Identify a subsequent successful authentication.
4. Correlate the successful authentication to a session.
5. Examine post-authentication activity.
Threshold

Minimum:

4 failed attempts
within 5 minutes
followed by success
Expected result

Potentially suspicious authentication sequences should be escalated for session correlation.

9. Hunt Query Concept — Privileged Accounts
Objective

Identify suspicious authentication behavior involving privileged accounts.

Conceptual logic
authentication
WHERE user is privileged
AND status in ("failure", "success")
GROUP BY source_ip, user, host
Investigative questions
Is the account expected to authenticate remotely?
Is the source approved?
Is the authentication time expected?
Was password authentication expected?
Did the account normally use public-key authentication?
Did the account perform administrative commands afterward?
10. Hunt Query Concept — Post-Authentication Discovery
Objective

Identify discovery commands following successful authentication.

Candidate commands
whoami
id
sudo -l
uname -a
Conceptual logic
successful authentication
FOLLOWED BY
command execution
WITHIN 5 MINUTES
WHERE command in:
    whoami
    id
    sudo -l
    uname -a
Interpretation

These commands can be legitimate administrative commands.

They become more significant when correlated with:

suspicious authentication
privileged accounts
unexpected source addresses
unusual login times
additional discovery
privilege changes
network activity
persistence behavior
11. Hunt Query Concept — Session Correlation
Objective

Track all activity associated with session SES-004-C.

Conceptual logic
WHERE session_id = "SES-004-C"
ORDER BY timestamp
Expected sequence
EVT-004007
successful authentication

EVT-004008
session start

EVT-004009
whoami

EVT-004010
id

EVT-004011
sudo -l

EVT-004012
uname -a
Hunt significance

Session correlation reduces the risk of incorrectly linking unrelated authentication and command events.

12. Hunt Query Concept — Account Expansion
Objective

Determine whether the same source targeted other accounts.

Conceptual logic
authentication
WHERE source_ip = "198.51.100.60"
GROUP BY user
Investigative questions
Were other accounts targeted?
Were other privileged accounts targeted?
Did another account successfully authenticate?
Did the source attempt password spraying?
Did the source move from one account to another?
13. Hunt Query Concept — Host Expansion
Objective

Determine whether the same source accessed additional hosts.

Conceptual logic
authentication
WHERE source_ip = "198.51.100.60"
GROUP BY host
Investigative questions
Was lab-linux-01 the only target?
Were additional SSH servers targeted?
Did the same account appear on other hosts?
Did successful authentication occur elsewhere?
14. Hunt Query Concept — Post-Authentication Privilege Activity
Objective

Identify privilege-related activity after authentication.

Candidate indicators
sudo -l
sudo
su
useradd
usermod
passwd
chmod
chown
Conceptual logic
successful authentication
FOLLOWED BY
privilege-related command
WITHIN 10 MINUTES
Interpretation

Privilege-related commands require contextual analysis.

For example:

sudo -l may be normal administration.
sudo may be normal maintenance.
useradd may be legitimate provisioning.
chmod may be legitimate deployment activity.

The analyst must validate authorization before assigning malicious intent.

15. Hunt Query Concept — Persistence Indicators
Objective

Identify possible persistence following the suspicious session.

Candidate areas
~/.ssh/authorized_keys
/etc/cron*
systemd services
/etc/passwd
/etc/shadow
shell startup files
new user accounts
sudoers configuration
Investigative questions
Were SSH keys modified?
Were new scheduled tasks created?
Were services created or modified?
Were accounts created?
Were sudo permissions changed?
Were shell startup files modified?

No persistence is confirmed in the current CASE-004 telemetry.

16. Hunt Query Concept — Network Follow-On Activity
Objective

Identify network connections following the suspicious session.

Conceptual logic
session SES-004-C
FOLLOWED BY
network connection
WITHIN 10 MINUTES
Investigative questions
Did the session initiate outbound connections?
Were unusual destinations contacted?
Was DNS activity generated?
Did the host communicate with other internal systems?
Was lateral movement attempted?

The current CASE-004 dataset does not establish such activity.

17. Hunt Query Concept — Cross-Case Correlation

CASE-004 should also be correlated with other cases in the SOC laboratory.

Relevant cases include:

CASE-001 — SSH brute-force activity
CASE-002 — Password spraying
CASE-003 — Suspicious PowerShell execution
CASE-004 — Suspicious post-authentication privileged session
Correlation objectives

Determine whether:

the same source appears across cases
the same account appears across cases
similar authentication behavior occurs
similar discovery behavior occurs
authentication alerts lead to endpoint activity
multiple alerts represent a larger attack sequence

No cross-case compromise relationship is currently confirmed.

18. Hunt Results

Based on the supplied CASE-004 telemetry:

Confirmed observed behavior
four failed password authentication attempts
successful authentication
session establishment
four post-authentication commands
id observed
sudo -l observed
session correlation through SES-004-C
Not established
credential compromise
malicious actor identity
persistence
lateral movement
malware execution
command-and-control activity
data exfiltration
account takeover beyond the observed session
19. False Positive Scenarios

The hunt must account for legitimate administrative behavior.

Potential false positives include:

administrator troubleshooting
authorized penetration testing
approved security validation
password mistakes
routine privilege verification
system maintenance
automated administrative workflows

The presence of whoami, id, sudo -l, or uname -a is not sufficient by itself to establish malicious activity.

20. Hunt Escalation Criteria

Escalate the investigation if hunting identifies one or more of the following:

High-value findings
successful authentication from an unauthorized source
repeated authentication against multiple privileged accounts
successful authentication across multiple hosts
unexpected privilege escalation
new SSH keys
unauthorized account creation
persistence mechanisms
suspicious outbound network activity
suspicious process execution
file modifications
additional security alerts linked to the same source or account
21. Evidence Classification
Observed Evidence

Directly observed:

source IP
host
account
session
authentication events
command execution events
Analyst Interpretation

The authentication-to-session sequence is suspicious and warrants investigation.

Hypothesis

The activity may represent unauthorized credential use followed by discovery.

Confirmed Finding

The suspicious sequence is confirmed in the supplied synthetic telemetry.

Account compromise remains unconfirmed.

22. Hunting Limitations

This hunt is limited by the available synthetic dataset.

The current telemetry does not provide:

complete historical authentication records
complete endpoint process telemetry
complete network telemetry
VPN records
identity-provider data
shell history beyond supplied events
filesystem integrity history
persistence artifacts
complete session duration

Therefore, absence of an indicator in this dataset must not be interpreted as proof that the behavior did not occur.

23. Recommended Hunt Improvements

Future versions of the SOC laboratory should add:

multi-host authentication telemetry
richer Linux audit events
process execution telemetry
network flow telemetry
DNS telemetry
file-integrity events
sudo execution records
SSH key modification events
account-management events
cross-case correlation identifiers

These additions would allow more realistic investigation and threat-hunting scenarios.

24. Current Hunting Determination

Hunt status: Initial hunt defined and partially validated against CASE-004 telemetry.

Behavioral concern: High.

Source classification: Documentation/test address.

Observed suspicious sequence: Confirmed.

Credential compromise: Not confirmed.

Persistence: Not established.

Lateral movement: Not established.

Malware: Not established.

Threat actor attribution: Not established.

25. Evidence Integrity Note

All hunt observations are derived from synthetic authorized laboratory telemetry.

The source address 198.51.100.60 is a documentation/test address.

The hunting hypotheses are investigative hypotheses and must not be presented as confirmed facts.

No real-world malicious infrastructure, organization, threat actor, or victim is attributed by this document.
