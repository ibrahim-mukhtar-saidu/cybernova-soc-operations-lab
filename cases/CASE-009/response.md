# CASE-009 — Incident Response

## Purpose

This document defines the recommended defensive response for the suspicious Linux cron persistence activity observed in CASE-009.

The response actions are designed for an authorized laboratory environment and are based only on the available evidence.

The case does not establish successful persistence or host compromise.

## Case Reference

- Case: `CASE-009`
- Alert ID: `ALERT-CASE-009-DET-LINUX-001`
- Detection ID: `DET-LINUX-001`
- Detection: Suspicious Linux Cron Persistence Detection
- Severity: High
- Confidence: High
- Host: `lab-linux-02`
- User: `analyst`

## Response Assessment

The available evidence is consistent with suspicious Linux cron persistence activity.

The observed command attempted to retrieve content and pass it to a shell while referencing:

```text
/etc/cron.d/system-update

The appropriate response posture is to treat the activity as suspicious and preserve evidence before making destructive changes.

The available evidence does not justify claiming confirmed compromise.

Immediate Actions
1. Preserve Evidence

Preserve the original telemetry and generated alert.

Required evidence includes:

Original JSONL telemetry
Generated alert.json
Relevant event IDs
Command-line evidence
File-path evidence
Detection metadata
Investigation timeline

Do not modify the original evidence fixture.

2. Validate the Cron Configuration

In an authorized investigation environment, inspect:

/etc/cron.d/system-update

Determine:

Whether the file exists.
File ownership.
File permissions.
File creation time.
File modification time.
File contents.
Whether the cron service recognizes the configuration.

The current CASE-009 telemetry does not establish that the file was successfully created or activated.

3. Validate Process Activity

Review process telemetry for:

curl
wget
sh
bash

Determine:

Parent process.
Child processes.
Execution timestamp.
Exit status.
User context.
File creation activity.

The current case does not contain sufficient process telemetry to establish successful payload execution.

4. Validate Network Activity

Review authorized network telemetry associated with:

203.0.113.80

Determine whether a connection was actually established and whether content was transferred.

Because the address is from a documentation/example range, the value is treated as a synthetic laboratory observable.

5. Validate the Referenced Payload

If a payload was actually retrieved in a controlled environment:

Preserve the original file.
Calculate cryptographic hashes.
Identify file type.
Perform static analysis.
Perform controlled sandbox analysis where appropriate.
Record analysis results.

Do not assume that /payload.sh represents malware without evidence.

Containment

If additional authorized evidence confirms active malicious persistence, containment actions could include:

Isolating the affected endpoint from the laboratory network.
Preventing further execution of the suspicious cron configuration.
Restricting affected account access where appropriate.
Blocking confirmed malicious network destinations after validation.
Preserving volatile and persistent evidence before cleanup.

Containment should be evidence-driven and should avoid destroying forensic evidence.

Eradication

If persistence is confirmed, eradication could include:

Removing the malicious cron configuration.
Removing confirmed malicious artifacts.
Terminating confirmed malicious processes.
Removing unauthorized persistence mechanisms.
Resetting affected credentials where compromise is established.
Correcting insecure permissions or configurations.

No eradication action is claimed to have occurred in CASE-009.

Recovery

After containment and eradication, recovery should include:

Confirming the suspicious persistence mechanism is no longer active.
Validating expected cron configuration.
Monitoring subsequent process activity.
Monitoring network activity.
Reviewing authentication events.
Confirming system integrity.
Returning the host to normal laboratory operation only after validation.
Escalation Criteria

Escalate the investigation if additional evidence demonstrates:

Confirmed persistence.
Successful payload execution.
Malware identified through analysis.
Unauthorized account activity.
Privilege escalation.
Additional compromised hosts.
Lateral movement.
Data access or exfiltration.
Repeated persistence mechanisms.
Additional related suspicious network activity.

The current evidence alone does not establish these conditions.

Evidence Preservation Requirements

Maintain:

Original telemetry.
Alert output.
Relevant event IDs.
Timeline.
Investigation notes.
Indicator records.
Threat-intelligence assessment.
Hunting results.
Response decisions.
Any subsequent validation evidence.

Evidence should remain traceable to the original event IDs.

Detection Feedback

The response process identifies opportunities to improve detection engineering.

Potential improvements include:

Correlating cron modification with subsequent process execution.
Correlating download activity with file creation.
Correlating network activity with process execution.
Detecting suspicious cron changes that occur without a download command.
Adding process ancestry to alerts.
Adding file hash enrichment.
Adding cron-service execution telemetry.
Testing benign administrative cron activity.

These improvements should be validated through additional laboratory tests before being considered implemented capabilities.

Closure Criteria

CASE-009 should only be considered fully closed after the investigation records:

Alert validation.
Evidence review.
Timeline reconstruction.
Indicator assessment.
Threat-intelligence assessment.
Hunting results.
Response decisions.
Evidence limitations.
Detection improvement opportunities.

If additional evidence becomes available, the case should be reopened and the new evidence incorporated into the investigation.

Current Laboratory Disposition

Based on the available synthetic evidence:

Suspicious activity confirmed; compromise not established.

No production containment, eradication, recovery, or credential-reset action is claimed to have occurred.

Laboratory Boundary

CASE-009 is an authorized defensive laboratory scenario using synthetic telemetry.

This document does not represent a real production incident, real victim, real credential, confirmed malware infection, or real-world compromise.
