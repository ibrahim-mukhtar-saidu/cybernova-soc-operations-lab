# CASE-005 — Threat Intelligence Assessment

## Intelligence Scope

This assessment evaluates the available threat-intelligence context for CASE-005.

The case uses synthetic laboratory telemetry and documentation/example indicators. Threat-intelligence conclusions are therefore limited to what can be established from the laboratory evidence.

No real-world attribution is made.

## Investigated Indicators

| Indicator | Type | Intelligence Relevance | Assessment |
|---|---|---|---|
| 198.51.100.77 | IPv4 address | Potential network pivot | Synthetic/reserved laboratory indicator |
| cdn-update.example | Domain | Potential network pivot | `.example` laboratory domain |
| 8443 | Destination port | Behavioral context | Non-standard destination port observed in the scenario |
| svchost_update.exe | Process name | Endpoint pivot | Suspicious process identifier within the laboratory |
| C:\Users\Public\svchost_update.exe | File path | Endpoint pivot | User-writable execution location |

## External Reputation

External reputation was **not assessed** for the network indicators.

The destination IP uses documentation/example address space and the domain uses the `.example` namespace. These values are appropriate for controlled laboratory scenarios and should not be interpreted as evidence of real-world malicious infrastructure.

Consequently, an external reputation verdict would not add meaningful evidence to this investigation.

## Intelligence Derived From Laboratory Evidence

The available telemetry provides behavioral intelligence:

- A single process repeatedly communicates with the same destination.
- Seven connections occur at a fixed 60-second interval.
- The destination uses port 8443.
- The process is unsigned.
- The process executes from a user-writable directory.
- Process/network correlation identifies the relationship as suspicious.
- The combined detection risk score is 100.

These observations increase the suspicion of automated command-and-control-style behavior within the laboratory scenario.

They do not establish that the destination is operated by a real attacker.

## MITRE ATT&CK Intelligence Context

The detection engine associates the behavior with:

- T1071 — Application Layer Protocol
- T1071.001 — Web Protocols
- T1573 — Encrypted Channel

These mappings should be treated as analytical hypotheses.

The current telemetry does not independently establish the exact application-layer protocol or malicious use of encryption. TLS-related communication can occur in legitimate software, so encryption alone is insufficient to establish adversarial behavior.

## Intelligence Gaps

A real-world investigation would require additional intelligence and evidence, including:

- file hash reputation;
- certificate information;
- DNS history;
- passive DNS;
- domain registration information;
- IP ownership and hosting context;
- proxy logs;
- firewall telemetry;
- packet or flow metadata;
- URL information;
- malware-family intelligence;
- endpoint process ancestry;
- persistence artifacts;
- sandbox results;
- related infrastructure;
- additional hosts communicating with the destination.

None of these should be fabricated for this laboratory case.

## Intelligence Assessment

**Laboratory assessment:** Suspicious.

**Behavioral rationale:** Highly regular outbound communication from an unsigned process executing from a user-writable path, combined with process/network correlation.

**External reputation:** Not assessed / not applicable to synthetic indicators.

**Threat-actor attribution:** Not established.

**Malware-family attribution:** Not established.

**Confidence in behavioral assessment:** High within the laboratory scenario.

## Recommended Real-SOC Intelligence Workflow

If equivalent telemetry were observed in an authorized real environment, the next intelligence steps would be:

1. Extract hashes and certificate metadata from the process.
2. Enrich the destination IP and domain using approved intelligence sources.
3. Search historical DNS and proxy telemetry.
4. Pivot across the enterprise for the process hash, process name, destination, and domain.
5. Compare infrastructure against known threat-intelligence reporting.
6. Analyze the binary in an isolated malware-analysis environment if authorized.
7. Update the case with only independently verified intelligence.

## Intelligence Limitations

This document intentionally does not assign a real-world reputation, malware family, threat actor, campaign, or infrastructure ownership to the synthetic indicators.

The purpose of the intelligence stage is to demonstrate disciplined enrichment boundaries rather than to manufacture attribution.
