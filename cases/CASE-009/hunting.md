# CASE-009 — Threat Hunting

## Purpose

This document defines threat-hunting activities derived from the evidence observed in CASE-009.

The hunting approach focuses on discovering related Linux cron persistence activity, suspicious shell execution, payload retrieval, and similar behavior across authorized laboratory telemetry.

The queries and pivots below are investigative patterns. They do not claim that additional matching events exist.

## Case Reference

- Case: `CASE-009`
- Alert ID: `ALERT-CASE-009-DET-LINUX-001`
- Detection ID: `DET-LINUX-001`
- Primary host: `lab-linux-02`
- Primary user: `analyst`

## Hunting Objectives

The primary objectives are to determine whether similar activity occurred:

1. On the same Linux host.
2. Under the same user account.
3. Against other cron persistence locations.
4. Through other shell download-and-execute commands.
5. Using similar temporary or hidden payload indicators.
6. Across other laboratory hosts or users.

## Hunt 1 — Cron Persistence Locations

Search Linux telemetry for activity involving common cron persistence locations:

```text
/etc/cron.d/
/etc/cron.daily/
/etc/cron.hourly/
/var/spool/cron/
/var/spool/cron/crontabs/
Investigation Question

Are there additional events modifying or referencing cron configuration files?

Relevant Fields
timestamp
event_id
host
user
process
command_line
file_path
action
status
Expected Use

This hunt can identify additional cron-related activity that may require investigation.

Cron administration is not inherently malicious, so results should be evaluated using process, user, command-line, and contextual evidence.

Hunt 2 — Shell Download-and-Execute Behavior

Search for command lines containing download utilities combined with shell execution.

Potential patterns include:

curl ... | sh
curl ... | bash
wget ... | sh
wget ... | bash
Investigation Question

Are there additional Linux events where remote content is retrieved and passed directly to a shell interpreter?

Relevant Fields
timestamp
event_id
host
user
process
command_line
source
status
Assessment

A download-and-execute pattern is suspicious and should be investigated in context.

It does not independently establish malware execution.

Hunt 3 — Temporary and Hidden Payload Activity

Search for command lines or metadata referencing temporary or hidden payload locations.

Potential locations include:

/tmp/
/var/tmp/
/dev/shm/

Also review telemetry containing a hidden-payload indicator.

Investigation Question

Are temporary or hidden locations being used together with shell execution or persistence activity?

Assessment

Temporary and hidden locations can have legitimate administrative uses.

Higher investigative priority should be given when these indicators correlate with suspicious process execution, remote downloads, or persistence configuration changes.

Hunt 4 — Same Host

Pivot from the primary host:

host = lab-linux-02

Review activity surrounding:

2026-09-09 13:00:00 UTC
Investigation Question

Did other suspicious activity occur on lab-linux-02 before or after EVT-009001?

Suggested Review Areas
Authentication activity
Privilege changes
Process execution
File modifications
Network connections
Cron modifications
Shell activity
Temporary-file activity

The available CASE-009 fixture does not contain sufficient additional telemetry to answer these questions.

Hunt 5 — Same User

Pivot on:

user = analyst
Investigation Question

Did the same user perform similar suspicious persistence or shell activity elsewhere in the available telemetry?

Review:

Process execution
Cron changes
Shell commands
Network activity
Authentication events
Privilege-related events

The case evidence does not establish that the user account was compromised or that the activity was unauthorized.

Hunt 6 — Related Command-Line Patterns

Search for related command-line behavior involving:

curl
wget
sh
bash
crontab

Prioritize combinations involving:

/etc/cron
/var/spool/cron
/tmp
/var/tmp
/dev/shm
Investigation Question

Are there additional events combining shell execution, remote retrieval, and persistence-related paths?

This hunt is designed to identify related activity rather than simply search for an exact copy of the original command.

Hunt 7 — Cron Persistence Without Download Activity

Search for suspicious cron modifications that do not contain a network download.

Examples include:

crontab
/etc/cron.d/
/etc/cron.daily/
/etc/cron.hourly/
/var/spool/cron/
Investigation Question

Could persistence activity exist without the shell download indicator?

This hunt helps identify detection blind spots where cron persistence occurs through locally available files or commands.

Hunt 8 — Slow or Distributed Activity

Review longer time windows for activity that may avoid a short detection threshold.

Potential pivots:

Same host across multiple hours
Same user across multiple hosts
Multiple cron modifications
Repeated temporary-file activity
Repeated shell execution
Repeated download behavior
Investigation Question

Could an attacker or malicious process distribute related actions over time rather than producing multiple indicators within a short observation window?

This is particularly relevant because DET-LINUX-001 currently evaluates the supplied event independently rather than correlating multiple events across a longer time period.

Hunt 9 — Benign Administrative Activity

Search for ordinary cron administration such as:

crontab -e

and compare it with suspicious activity.

The supplied benign event is:

Event ID: EVT-009002
User: admin
Process: crontab
Command: crontab -e
File: /var/spool/cron/crontabs/admin
Investigation Question

Can legitimate cron administration be reliably separated from suspicious multi-indicator activity?

This hunt supports false-positive analysis and detection tuning.

Correlation Strategy

When multiple suspicious events are discovered, correlate them using:

Host
User
Timestamp
Process
Parent process
File path
Command line
Source IP
Destination IP
Event type
Action

A stronger investigative finding should be based on multiple related observations rather than a single suspicious string.

Potential Detection Gaps

The current detection evaluates suspicious indicators within an individual linux_persistence event.

Potential future improvements include:

Multi-event correlation.
Longer persistence-focused observation windows.
Process ancestry correlation.
Network-to-process correlation.
File creation correlation.
Cron service execution correlation.
User and host behavioral baselines.
File hash enrichment.
Malware-analysis integration.

These are detection-engineering opportunities, not findings that the current detection is defective.

Hunt Disposition

The supplied CASE-009 telemetry demonstrates one suspicious event and one benign comparison event.

No additional hunting results are claimed because no additional telemetry was supplied.

The hunting procedures documented here provide repeatable investigation pivots for future authorized laboratory telemetry.

Laboratory Boundary

All hunting activities described in this document are intended for authorized defensive laboratory environments.

No real production infrastructure, real credentials, real victims, or real-world threat actors are represented.
