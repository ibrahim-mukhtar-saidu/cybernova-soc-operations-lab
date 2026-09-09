# CASE-007 — Hunting

## Hunting Summary

**Case ID:** CASE-007

**Scenario:** File Integrity Violation

**Host:** `lab-host-01`

**Detection:** `DET-HOST-001` — File Integrity Violation Detection

**Alert ID:** `ALERT-CASE-007-DET-HOST-001`

**Environment:** Controlled cybersecurity laboratory using synthetic telemetry

## 1. Hunting Objective

Extend the investigation beyond the two file integrity events that generated the alert.

The objective is to determine whether additional authentication, process, privilege, account, file, or network activity can corroborate or explain the observed modifications to:

- `/etc/ssh/sshd_config`
- `/etc/passwd`

The hunting process must not assume compromise.

Each hypothesis should be tested against available evidence.

## 2. Known Investigation Anchor

The primary investigation anchor is:

```text
2026-09-08T12:00:00Z
        ↓
/etc/ssh/sshd_config modified
        ↓
2026-09-08T12:02:00Z
        ↓
/etc/passwd modified

The two events occurred on:

lab-host-01

and were associated with:

root
3. Hunt Hypothesis 1 — Authentication Precursor
Hypothesis

An authentication event may have preceded the file modifications.

Hunt Question

Did lab-host-01 experience successful or failed authentication activity shortly before 12:00:00Z?

Search Window
2026-09-08T11:45:00Z
→
2026-09-08T12:05:00Z
Relevant Evidence

Search for:

successful SSH authentication;
failed SSH authentication;
authentication source IP;
authenticated user;
session start;
session termination.
Expected Value

A related authentication event could provide context for how the root-associated activity occurred.

Current Result

Not available in CASE-007 telemetry.

No authentication event is claimed as observed.

4. Hunt Hypothesis 2 — Privilege Escalation
Hypothesis

The file modifications may have followed a privilege transition.

Hunt Question

Was there evidence of sudo, privilege escalation, or another transition into a privileged context before the file changes?

Search Window
2026-09-08T11:45:00Z
→
2026-09-08T12:05:00Z
Relevant Evidence

Search for:

sudo execution;
privilege changes;
setuid activity;
administrative sessions;
privilege escalation detections.
Current Result

Not available in CASE-007 telemetry.

The root user field is observed, but the mechanism by which the activity obtained root context is unknown.

5. Hunt Hypothesis 3 — Process Attribution
Hypothesis

A process responsible for modifying the files may provide the strongest explanation for the activity.

Hunt Question

Which process wrote to /etc/ssh/sshd_config and /etc/passwd?

Search Window
2026-09-08T11:55:00Z
→
2026-09-08T12:05:00Z
Relevant Evidence

Search for:

process creation;
executable path;
command line;
parent process;
process user;
file access events.
Expected Value

Process attribution could distinguish:

approved administration;
package management;
configuration management;
manual modification;
suspicious execution.
Current Result

Not available in CASE-007 telemetry.

6. Hunt Hypothesis 4 — Additional File Modifications
Hypothesis

The two observed modifications may be part of a larger cluster of file changes.

Hunt Question

Were other security-sensitive files modified around the same time?

Search Window
2026-09-08T11:55:00Z
→
2026-09-08T12:10:00Z
Priority Paths

Investigate changes involving:

/etc/passwd
/etc/shadow
/etc/group
/etc/sudoers
/etc/sudoers.d/*
/etc/ssh/sshd_config
/etc/ssh/ssh_config
/root/.ssh/*
/home/*/.ssh/*
/etc/crontab
/etc/cron.d/*
/etc/systemd/system/*
Current Result

Only the two alert-supporting file modifications are available in the CASE-007 scenario.

No additional suspicious file modifications are claimed.

7. Hunt Hypothesis 5 — Account Modification
Hypothesis

The /etc/passwd modification may correspond to account creation or modification.

Hunt Question

Did the local account population change around the detection window?

Search For
newly created users;
deleted users;
UID changes;
GID changes;
shell changes;
home-directory changes;
privileged group membership;
password changes.
Current Result

The CASE-007 telemetry records only that /etc/passwd changed.

No specific account modification is observed in the available dataset.

8. Hunt Hypothesis 6 — SSH Configuration Abuse
Hypothesis

The SSH configuration change may have altered remote-access behavior.

Hunt Question

Did the change modify authentication or remote-access controls?

Search For
PermitRootLogin;
PasswordAuthentication;
PubkeyAuthentication;
AuthorizedKeysFile;
AllowUsers;
AllowGroups;
DenyUsers;
DenyGroups;
forwarding configuration;
unexpected SSH ports.
Current Result

The telemetry contains hashes but does not contain file-content diffs.

Therefore, no specific SSH configuration change is claimed.

9. Hunt Hypothesis 7 — Persistence
Hypothesis

The file modifications may have been associated with persistence.

Hunt Question

Were persistence mechanisms created or modified around the same time?

Search For
cron jobs;
systemd units;
SSH authorized keys;
shell startup files;
service configuration;
scheduled tasks;
startup scripts.
Current Result

No persistence mechanism is present in the CASE-007 telemetry.

Persistence must not be inferred from the file modifications alone.

10. Hunt Hypothesis 8 — Network Correlation
Hypothesis

The file modifications may have occurred during or immediately after suspicious network activity.

Hunt Question

Did lab-host-01 communicate with unusual destinations around the detection window?

Search Window
2026-09-08T11:45:00Z
→
2026-09-08T12:15:00Z
Search For
unusual outbound connections;
unexpected inbound connections;
rare destinations;
new external destinations;
suspicious DNS queries;
process-to-network relationships.
Current Result

No network telemetry is included in CASE-007.

No network indicator is therefore claimed.

11. Hunt Hypothesis 9 — Package Management
Hypothesis

The file changes may have resulted from legitimate package installation or update activity.

Hunt Question

Did package management modify either file?

Search For
apt;
dpkg;
package installation;
package upgrades;
package configuration;
unattended updates.
Expected Value

A matching package-management event could provide a legitimate explanation for a configuration change.

Current Result

No package-management telemetry is included in CASE-007.

12. Hunt Hypothesis 10 — Configuration Management
Hypothesis

An approved configuration-management system may have modified the files.

Hunt Question

Did an automated configuration process modify either file?

Search For
Ansible;
Puppet;
Chef;
Salt;
configuration-management agents;
scheduled administrative automation.
Expected Value

A matching configuration-management record could explain the file modifications and reduce the likelihood of malicious interpretation.

Current Result

No configuration-management telemetry is included in CASE-007.

13. Hunt Hypothesis 11 — Same-User Activity
Hypothesis

The root user context may connect both modifications to a common administrative or execution session.

Hunt Question

Can both file changes be correlated to the same session?

Search For
session ID;
source IP;
login event;
process tree;
terminal activity;
command execution.
Current Result

Both file events identify root, but no session identifier is available.

The shared user field therefore provides correlation context but not proof of a common session.

14. Hunt Hypothesis 12 — File Integrity Expansion
Hypothesis

Additional files may have changed outside the initial detection window.

Hunt Question

Did the host experience further file modifications before or after the alert?

Search Window
2026-09-08T11:30:00Z
→
2026-09-08T12:30:00Z
Search Strategy

Group file integrity events by:

host;
user;
directory;
file path;
change type;
timestamp.

Look for:

bursts of modifications;
repeated security-sensitive paths;
creation followed by execution;
deletion of security artifacts;
repeated modifications by the same user.
Current Result

The CASE-007 dataset contains three file integrity events.

Only two are associated with the alert.

15. Hunt Priority

The recommended hunting order is:

Priority	Hunt	Reason
1	Process attribution	Identifies what performed the modifications
2	Authentication	Establishes access context
3	Privilege activity	Explains root context
4	Account modification	Validates /etc/passwd change
5	SSH configuration	Determines security impact
6	Additional file changes	Determines scope
7	Persistence	Determines possible follow-on behavior
8	Network correlation	Determines external context
9	Package management	Tests legitimate explanation
10	Configuration management	Tests authorized automation
16. Evidence Requirements

Every hunt result should record:

query or search logic;
time range;
data source;
returned event IDs;
analyst interpretation;
confidence;
limitations.

A hunt that produces no result should be recorded as no supporting evidence found, not as proof that the activity did not occur.

17. Detection Improvement Opportunities

The hunting process identifies potential enhancements to DET-HOST-001:

Process Context

Include the responsible process where available.

Authentication Context

Correlate file modifications with recent authentication activity.

Privilege Context

Correlate sensitive file changes with privilege transitions.

Path Sensitivity

Assign higher investigation priority to security-sensitive paths.

Authorization Context

Support trusted administrative-change metadata where reliably available.

Multi-Signal Correlation

Combine file integrity, authentication, process, privilege, and network signals.

These improvements should be implemented only after suitable telemetry and regression tests exist.

18. Current Hunting Assessment

The current CASE-007 dataset supports the following conclusion:

Two security-sensitive file modifications occurred on the same host within two minutes.

The dataset does not contain enough additional telemetry to determine:

who initiated the activity;
what process performed the changes;
whether privilege escalation occurred;
whether account data changed;
whether SSH behavior changed;
whether persistence was established;
whether network activity was involved;
whether the changes were malicious.

Therefore, hunting remains an open investigative activity.

19. Laboratory Limitations

This hunting assessment uses synthetic laboratory telemetry.

The absence of an indicator from the current dataset does not prove that the corresponding activity did not occur.

No production security incident is being claimed.

Conclusion

CASE-007 provides a strong starting point for host-level threat hunting because the alert identifies a specific host, user context, security-sensitive files, timestamps, and supporting event IDs.

The next stage of investigation should prioritize process and authentication correlation because those data sources can most directly explain the observed file modifications.
