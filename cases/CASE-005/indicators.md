# CASE-005 — Indicators and Evidence

## Indicator Handling

This document records indicators observed during the CASE-005 investigation.

The telemetry is synthetic laboratory data. The IP addresses and domain names used in this scenario are documentation/example indicators and must not be treated as real-world malicious infrastructure.

Indicator status therefore describes the evidence observed within the laboratory, not external reputation.

## Network Indicators

| Indicator | Type | Context | Evidence | Laboratory Assessment |
|---|---|---|---|---|
| 198.51.100.77 | IPv4 address | Destination of repeated outbound connections | EVT-005007–EVT-005014 | Suspicious destination within lab scenario |
| 8443 | TCP destination port | Repeated outbound communication | EVT-005007–EVT-005014 | Non-standard web/service port in this scenario |
| cdn-update.example | Domain | Destination associated with suspicious connections | EVT-005007–EVT-005011, EVT-005014 | Suspicious lab destination; not externally reputation-validated |

## Host Indicators

| Indicator | Type | Context | Evidence | Laboratory Assessment |
|---|---|---|---|---|
| lab-ws-01 | Host | Source of suspicious network activity | Alert / EVT-005006–EVT-005015 | Host requiring investigation |
| 192.0.2.50 | IPv4 address | Source address associated with suspicious process/network activity | Alert / telemetry | Source indicator within lab scenario |

## Process Indicators

| Indicator | Type | Context | Evidence | Laboratory Assessment |
|---|---|---|---|---|
| svchost_update.exe | Process name | Source process for repeated connections | EVT-005006–EVT-005014 | Suspicious process name in scenario |
| C:\Users\Public\svchost_update.exe | File path | Process execution location | EVT-005006 | User-writable execution path |
| PID 7331 | Process ID | Process instance | EVT-005006 / EVT-005013 | Host-local process identifier |
| services.exe | Parent process | Parent of suspicious process | EVT-005006 | Requires process-chain investigation |

## Behavioral Indicators

| Indicator | Observation | Evidence |
|---|---|---|
| Repeated outbound connections | 7 connections to the same destination | EVT-005007–EVT-005012, EVT-005014 |
| Fixed interval | 60 seconds between consecutive connections | EVT-005007–EVT-005014 |
| Regularity | 1.0 / 100% | Generated alert |
| User-writable process path | Process executed from `C:\Users\Public\` | EVT-005006 |
| Unsigned process | Process reported as unsigned | EVT-005006 / EVT-005013 |
| Process/network correlation | Correlation recorded for suspicious process and destination | EVT-005013 |
| Non-standard destination port | TCP/8443 | EVT-005007–EVT-005014 |

## Negative / Benign Indicators

The following indicators provide useful comparison evidence:

| Indicator | Context | Evidence | Assessment |
|---|---|---|---|
| 93.184.216.34:443 | Chrome HTTPS traffic | EVT-005001–EVT-005005 | Benign browser baseline in lab |
| windows_update.exe | Expected update process | EVT-005015 | Expected activity in lab |
| C:\Windows\System32\windows_update.exe | System update process path | EVT-005015 | Expected system path in lab |
| 203.0.113.80:443 | Expected update destination | EVT-005015 | Expected update traffic in lab |
| Signed process | windows_update.exe reported signed | EVT-005015 | Negative evidence against indiscriminate network alerting |

## External Threat Intelligence Status

No external reputation determination is made for the IP addresses or domain in this case.

The scenario uses reserved/documentation address space and an `.example` domain. External reputation lookup would therefore not provide meaningful evidence about a real-world threat actor or infrastructure.

The appropriate intelligence classification for this laboratory case is:

**External reputation: Not assessed / not applicable to the synthetic indicators.**

## Indicator Confidence

### High-confidence laboratory indicators

- `svchost_update.exe`
- `C:\Users\Public\svchost_update.exe`
- `198.51.100.77:8443`
- Seven regular outbound connections
- 60-second interval
- Unsigned process characteristic
- Process/network correlation

### Context-dependent indicators

- `cdn-update.example`
- `services.exe` as parent process
- `192.0.2.50` as source address

These indicators are meaningful within the laboratory scenario but do not establish maliciousness outside the scenario.

## Recommended Hunting Use

The following indicators should be used for additional laboratory hunting:

1. Search for `svchost_update.exe` across all available endpoint telemetry.
2. Search for the process path `C:\Users\Public\svchost_update.exe`.
3. Search for connections to `198.51.100.77`.
4. Search for destination port `8443` associated with the process.
5. Search for `cdn-update.example`.
6. Search for the source host `lab-ws-01`.
7. Search for additional process/network correlation events involving PID 7331.
8. Search for other hosts communicating with the same destination.

## Indicator Limitations

No file hash, certificate fingerprint, mutex, registry persistence key, user account, URL path, DNS record, packet capture, or external infrastructure attribution is available in the current telemetry.

These missing indicators limit the ability to determine whether the simulated activity represents a complete intrusion chain.

## Handling Recommendation

Treat the suspicious indicators as investigation pivots within the laboratory environment.

Do not block, attribute, or classify the example IP/domain as real-world malicious infrastructure solely from this case.
