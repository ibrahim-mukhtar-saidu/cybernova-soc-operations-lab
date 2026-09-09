# CASE-007 — Response

## Response Summary

**Case ID:** CASE-007

**Scenario:** File Integrity Violation

**Detection:** `DET-HOST-001` — File Integrity Violation Detection

**Alert ID:** `ALERT-CASE-007-DET-HOST-001`

**Host:** `lab-host-01`

**Severity:** High

**Confidence:** High

**Environment:** Controlled cybersecurity laboratory using synthetic telemetry

**Response Status:** Investigation-led response planning

## 1. Response Objective

Define an appropriate defensive response to the clustered file integrity violations observed on `lab-host-01`.

The response must preserve evidence, validate the activity, limit potential impact where justified, and avoid treating suspicious telemetry as confirmed compromise without corroborating evidence.

## 2. Current Situation

The detection identified two file modifications within two minutes:

- `/etc/ssh/sshd_config`
- `/etc/passwd`

Both events are associated with the `root` user in the synthetic telemetry and are marked:

```text
authorized_change=false

The detection generated:

ALERT-CASE-007-DET-HOST-001

A third modification to:

/opt/application/config.yml

occurred at 12:20:00Z and is marked as authorized.

3. Initial Response Decision

Decision: Continue controlled investigation and prepare containment actions rather than immediately declaring a confirmed compromise.

The evidence justifies elevated investigation priority because security-sensitive files were modified in a short period.

The available telemetry does not establish:

attacker access;
malicious execution;
persistence;
privilege escalation;
account compromise;
data theft;
command-and-control activity.

Therefore, destructive remediation should not be performed solely on the basis of the current evidence.

4. Response Priorities

The response priorities are:

Preserve evidence.
Validate the file modifications.
Identify the responsible process.
Validate authentication context.
Validate privilege context.
Determine whether the changes were authorized.
Assess whether containment is required.
Restore trusted configuration if unauthorized modification is confirmed.
Monitor for recurrence.
Improve detection coverage.
5. Evidence Preservation

Before modifying the affected host, preserve:

original FIM telemetry;
generated alert;
file hashes;
file metadata;
relevant authentication logs;
process execution records;
privilege escalation records;
package-management records;
configuration-management records;
administrative change records.

The original evidence should remain immutable for investigation and later review.

6. Triage Actions

The analyst should first establish whether the changes can be explained by legitimate activity.

Action 1 — Validate Change Authorization

Check:

approved maintenance;
change-management records;
administrator activity;
configuration-management jobs;
package updates.

Decision point:

If a legitimate change explains both modifications, reduce incident severity and document the authorization evidence.

Action 2 — Validate Authentication

Review authentication activity around:

2026-09-08T11:45:00Z
→
2026-09-08T12:05:00Z

Look for:

successful SSH authentication;
failed authentication;
source IP addresses;
privileged sessions;
unusual login times.
Action 3 — Validate Process Activity

Identify the process responsible for modifying:

/etc/ssh/sshd_config
/etc/passwd

Review:

executable;
process ID;
parent process;
command line;
process user;
execution timestamp.
Action 4 — Validate Account Changes

Determine whether /etc/passwd changes correspond to:

new users;
deleted users;
UID changes;
GID changes;
shell changes;
administrative account changes.
Action 5 — Validate SSH Configuration

Determine whether the SSH configuration change affected:

authentication methods;
root login;
allowed users;
allowed groups;
SSH keys;
forwarding;
remote-access policy.
7. Containment Decision Matrix
Evidence	Response
Authorized administrative change confirmed	No containment; document authorization
Package/configuration management explains changes	No containment; document source
Suspicious process identified but no active threat	Increase monitoring and continue investigation
Unauthorized modification confirmed	Consider host isolation and credential/session review
Active malicious process identified	Isolate host and preserve volatile evidence where possible
Evidence of active compromise	Escalate to incident-response procedure
Insufficient evidence	Continue investigation without unsupported containment claims
8. Containment

Containment should be proportional to evidence.

If independent evidence confirms unauthorized or malicious modification, potential containment actions include:

isolating the affected host;
restricting network access;
terminating malicious processes;
disabling compromised accounts;
rotating affected credentials;
blocking confirmed malicious infrastructure.

These actions should be performed only within an authorized environment.

For this laboratory case, no real containment action is being claimed.

9. Eradication

If malicious modification is confirmed, eradication should address the identified root cause.

Potential actions include:

Remove unauthorized changes.
Restore trusted versions of affected files.
Remove unauthorized accounts.
Remove unauthorized SSH keys.
Remove malicious persistence.
Terminate malicious processes.
Remove malicious software.
Apply required security patches.
Correct the initial access or privilege pathway.

The exact remediation must depend on confirmed evidence.

No eradication action is claimed for CASE-007 because the available dataset does not establish compromise.

10. Recovery

If the host is determined to be compromised, recovery should include:

restoring trusted configuration;
validating file integrity;
validating account configuration;
validating SSH configuration;
reviewing authentication;
confirming required services;
monitoring for recurrence;
documenting recovery actions.

Recovery should not rely solely on the absence of another FIM alert.

11. Credential Considerations

Because /etc/passwd was modified, investigators should determine whether associated account information changed.

If independent evidence indicates credential compromise, appropriate actions may include:

resetting affected credentials;
rotating privileged credentials;
invalidating active sessions;
reviewing SSH keys;
reviewing privileged account membership.

No compromised credential is identified in the current CASE-007 telemetry.

12. SSH Security Considerations

Because /etc/ssh/sshd_config changed, investigators should validate the effective SSH configuration.

Particular attention should be given to:

root authentication;
password authentication;
public-key authentication;
allowed users;
allowed groups;
forwarding;
unexpected configuration directives.

No specific configuration alteration is claimed because the telemetry contains hashes rather than file-content differences.

13. Escalation Criteria

Escalate the investigation if any of the following are confirmed:

unauthorized administrative access;
malicious process execution;
privilege escalation;
unauthorized account creation;
unauthorized SSH key installation;
persistence;
suspicious network activity;
additional security-sensitive file modifications;
evidence of active compromise.

The escalation decision should be based on corroborating evidence.

14. Communication

A professional incident record should communicate:

what was observed;
when it occurred;
affected host;
affected files;
detection logic;
supporting evidence;
current confidence;
known limitations;
actions performed;
actions pending;
escalation status.

Avoid describing the activity as a confirmed breach unless the evidence supports that conclusion.

15. Response Evidence

The following evidence supports the response assessment:

ALERT-CASE-007-DET-HOST-001
        ↓
EVT-007001
        ↓
/etc/ssh/sshd_config modified
        ↓
EVT-007002
        ↓
/etc/passwd modified

The response decision is based on the observed telemetry and the limitations of that evidence.

16. Response Validation

After any remediation or containment action, validate:

file integrity;
SSH configuration;
account configuration;
authentication behavior;
running processes;
network connections;
persistence locations;
monitoring coverage.

The validation results should be recorded as separate evidence.

17. Detection Feedback

The response workflow identifies opportunities to improve DET-HOST-001.

Potential improvements include:

correlate sensitive file changes with authentication;
correlate file changes with process execution;
identify privilege transitions;
distinguish authorized administrative changes;
assign path-specific risk;
preserve richer process context;
correlate file changes with network activity.

Each improvement should receive regression tests before being considered implemented.

18. Closure Criteria

CASE-007 should not be considered fully closed until the investigation determines whether the observed changes were:

authorized;
benign but unexpected;
suspicious but unresolved;
unauthorized;
confirmed malicious.

Closure should also document:

evidence reviewed;
investigation outcome;
response actions;
residual risk;
detection improvements;
lessons learned.
19. Current Case Decision

Current decision: Investigation continues.

The available evidence supports a high-priority investigation because two security-sensitive files were modified within a two-minute interval.

The available evidence does not independently establish compromise.

No production containment, eradication, recovery, or credential-reset action is being claimed.

20. Laboratory Limitations

This response plan is based on synthetic laboratory telemetry.

No real production system has been isolated, modified, or remediated.

No real credentials have been exposed or rotated.

The response actions described above are defensive procedures that would require authorization and corroborating evidence in a real environment.

Conclusion

CASE-007 demonstrates an evidence-driven response process for file integrity violations.

The appropriate response is to preserve evidence, validate authorization and process context, investigate related authentication and privilege activity, and escalate only when corroborating evidence supports doing so.

The central response principle is:

Suspicious file modification should trigger disciplined investigation—not unsupported claims of compromise.
