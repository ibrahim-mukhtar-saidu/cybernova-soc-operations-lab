# CASE-004 — Incident Response

## 1. Document Control

| Field | Value |
|---|---|
| Case ID | CASE-004 |
| Alert ID | ALERT-CASE-004-DET-AUTH-003 |
| Detection | DET-AUTH-003 |
| Detection Name | Suspicious Post-Authentication Privileged Session |
| Severity | High |
| Confidence | High |
| Host | lab-linux-01 |
| User | admin |
| Source IP | 198.51.100.60 |
| Session | SES-004-C |
| Environment | Synthetic authorized SOC laboratory |

---

## 2. Response Objective

The objective of this response workflow is to define how an analyst should handle the suspicious authentication-to-session sequence identified by DET-AUTH-003.

The workflow emphasizes:

- alert validation
- evidence preservation
- authorization verification
- account verification
- source verification
- session investigation
- containment decision-making
- recovery
- post-incident lessons
- case closure

The response must distinguish observed evidence from analyst interpretation and confirmed findings.

---

## 3. Current Alert State

The detection engine generated:

```text
Alert ID: ALERT-CASE-004-DET-AUTH-003
Severity: high
Confidence: high
Source IP: 198.51.100.60
Host: lab-linux-01
User: admin
Session: SES-004-C
Failed authentications: 4
Post-authentication commands: 4
Privileged indicators: id, sudo -l

The supporting event set contains:

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
4. Evidence Classification
Observed Evidence

The telemetry directly shows:

four failed password authentication attempts
one successful password authentication
session establishment
four command executions
whoami
id
sudo -l
uname -a
Analyst Interpretation

The sequence is suspicious because repeated failures were followed by successful authentication and privileged-session discovery activity.

Hypothesis

Possible unauthorized credential use followed by account and privilege discovery.

Confirmed Finding

Suspicious activity is confirmed in the synthetic telemetry.

Account compromise and malicious intent are not confirmed.

5. Response Phase 1 — Alert Validation

Before taking containment action, the analyst should validate:

detection ID
alert severity
alert confidence
source IP
target host
account
session identifier
supporting event IDs
authentication sequence
post-authentication activity
Validation Result

The alert is supported by the supplied CASE-004 telemetry.

The detection correlation is:

4 failed password authentications
        |
        v
successful authentication
        |
        v
session start
        |
        v
4 post-authentication commands
        |
        v
privilege/account enumeration
6. Response Phase 2 — Authorization Verification

The first operational question is:

Was the activity authorized?

The analyst should verify:

whether the admin user was expected to authenticate
whether the source IP was approved
whether the authentication time was expected
whether password authentication was authorized
whether the session was part of planned maintenance
whether the commands were expected
Laboratory Determination

The source IP is a documentation/test address.

The dataset is synthetic and authorized for laboratory use.

Therefore, no real-world containment action should be performed against the source.

7. Response Phase 3 — Account Verification

The analyst should validate the account involved.

Account

admin

Questions
Who owns the account?
Is the account privileged?
Is remote SSH access expected?
Is password authentication permitted?
Has the password recently changed?
Was the account used from other systems?
Are there recent failed logins?
Are there other active sessions?
Were privilege changes observed?
Recommended Actions in a Real Environment

If the authentication is unauthorized:

disable or suspend the account according to policy
force credential reset
revoke active sessions
rotate exposed credentials
review MFA and authentication controls
investigate additional account activity

These actions should only be performed after authorization and incident-response procedures are verified.

8. Response Phase 4 — Source Verification

The source address is:

198.51.100.60

The address is a documentation/test range.

Laboratory Response

No blocking action is required.

Real-World Response

For a real source address, validate:

ownership
VPN association
endpoint identity
geographic consistency
historical authentication behavior
threat-intelligence reputation
previous security alerts

A source should not be blocked solely because it generated a single suspicious authentication event.

9. Response Phase 5 — Session Investigation

Session:

SES-004-C

The analyst should reconstruct the complete session.

Known sequence:

EVT-004007
Successful authentication

EVT-004008
Session start

EVT-004009
whoami

EVT-004010
id

EVT-004011
sudo -l

EVT-004012
uname -a
Investigation Questions
What happened before authentication?
What happened after uname -a?
Were additional commands executed?
Were files modified?
Were accounts created?
Were SSH keys changed?
Was sudo used?
Were network connections initiated?
Did the user access other hosts?
10. Response Phase 6 — Privilege Review

The commands:

id
sudo -l

are important because they provide account and privilege context.

They are not inherently malicious.

The analyst should determine:

effective UID
group membership
sudo permissions
privilege changes
commands executed through sudo
authorization for administrative activity
Current Evidence

No confirmed privilege escalation is present in the supplied telemetry.

11. Response Phase 7 — Persistence Review

The analyst should check for possible persistence mechanisms.

Potential areas include:

~/.ssh/authorized_keys
/etc/cron*
systemd services
/etc/passwd
/etc/shadow
sudoers configuration
shell startup files
Questions
Were SSH keys added?
Were scheduled jobs created?
Were services created or modified?
Were new users created?
Were sudo permissions modified?
Were shell startup files changed?
Current Determination

No persistence is established by CASE-004 telemetry.

12. Response Phase 8 — Endpoint Review

A real SOC should correlate authentication activity with endpoint telemetry.

Review:

process creation
command execution
file modification
privilege changes
service creation
persistence
malware detections
EDR alerts

The current CASE-004 dataset does not contain complete endpoint telemetry.

Therefore, endpoint compromise cannot be ruled in or ruled out from this case alone.

13. Response Phase 9 — Network Review

Review network telemetry around the session.

Recommended sources:

firewall
DNS
proxy
VPN
network-flow logs
EDR network telemetry

Investigate:

outbound connections
internal connections
unusual destinations
lateral movement
command-and-control indicators

No suspicious network activity is established in the supplied CASE-004 telemetry.

14. Containment Decision

Containment should be proportional to confidence and impact.

Immediate containment may be appropriate when:
unauthorized access is confirmed
credentials are confirmed compromised
active malicious activity is observed
persistence is established
lateral movement is occurring
destructive activity is observed
Containment may be deferred when:
activity is likely authorized
evidence is incomplete
immediate containment could disrupt legitimate operations
the source is a known approved administrative system
CASE-004 Determination

The current evidence supports investigation and validation.

It does not independently justify real-world containment because:

the dataset is synthetic
the source is a documentation/test address
authorization status is part of the laboratory scenario
compromise is not confirmed
15. Evidence Preservation

Before destructive containment actions in a real environment, preserve relevant evidence according to organizational policy.

Potential evidence includes:

authentication logs
session records
audit logs
shell history
EDR telemetry
process information
network telemetry
filesystem metadata
modified files
SSH configuration
account-management events
Evidence Integrity

Preserved artifacts should maintain:

original timestamps
original identifiers
source information
acquisition context
hashes where appropriate
chain-of-custody records when required
16. Recovery Actions

If unauthorized access were confirmed, recovery could include:

terminate unauthorized sessions
disable affected accounts
reset credentials
revoke active authentication tokens
rotate SSH keys if exposed
remove unauthorized persistence
restore modified files
patch exploited weaknesses
verify endpoint integrity
increase monitoring
validate successful recovery

Recovery actions must be approved and documented according to incident-response policy.

17. Post-Incident Monitoring

After response or recovery, monitor for:

repeated authentication attempts
new successful logins
account re-use
new sessions
privilege changes
persistence attempts
unusual commands
network anomalies
related alerts

A temporary monitoring period may be appropriate after confirmed unauthorized access.

18. Escalation Criteria

Escalate the case if additional evidence shows:

confirmed unauthorized authentication
credential compromise
privileged account abuse
lateral movement
persistence
malware
suspicious network communication
data access or exfiltration
activity across multiple hosts
repeated attacks from the same source
19. Closure Criteria

CASE-004 should not be closed as a confirmed compromise based only on the current telemetry.

The case can be closed as suspicious activity after:

alert validation
authorization verification
evidence review
documented investigation gaps
appropriate analyst disposition

If unauthorized access is later confirmed, the case should be reopened or escalated according to the incident-management process.

20. Recommended Analyst Actions
Immediate
validate the authentication sequence
verify account ownership
verify source ownership
reconstruct session activity
review additional telemetry
Short-term
hunt for source expansion
hunt for account expansion
review privileged activity
review persistence indicators
correlate endpoint and network telemetry
Long-term
improve privileged-account monitoring
enrich authentication detections
implement identity-aware baselines
correlate authentication with endpoint behavior
measure false-positive rates
add additional negative datasets
21. MITRE ATT&CK Context

Relevant behavioral mappings:

Technique	Name	Response relevance
T1110	Brute Force	Failed authentication sequence
T1078	Valid Accounts	Successful authentication
T1087	Account Discovery	id
T1069.001	Permission Groups Discovery: Local	id and sudo -l
T1059.004	Unix Shell	Command execution

These mappings describe observed behaviors and do not independently establish malicious activity.

22. Current Response Determination

Alert status: Open for investigation.

Severity: High.

Confidence: High.

Observed suspicious sequence: Confirmed.

Source classification: Documentation/test address.

Containment required in laboratory: No.

Credential compromise: Not confirmed.

Persistence: Not established.

Lateral movement: Not established.

Malware: Not established.

Threat actor attribution: Not established.

Current disposition: Suspicious activity observed; additional validation required.

23. Evidence Integrity Note

This response plan is based on synthetic authorized laboratory telemetry.

The source address 198.51.100.60 is a documentation/test address.

No real-world containment, blocking, account disabling, credential rotation, or other destructive action should be performed based solely on this synthetic case.

All response recommendations for real environments require appropriate authorization and incident-response procedures.
