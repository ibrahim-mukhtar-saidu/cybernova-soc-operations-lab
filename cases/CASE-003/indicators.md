# CASE-003 Indicators

## Indicator Summary

This document records observable indicators associated with CASE-003.

All indicators originate from synthetic laboratory telemetry.

## Host and User

| Indicator | Type | Observation |
|---|---|---|
| `lab-win-04` | Host | Host associated with suspicious PowerShell execution |
| `david` | User | User associated with suspicious process chain |

## Process Indicators

| Indicator | Type | Observation |
|---|---|---|
| `powershell.exe` | Process | Suspicious PowerShell execution |
| `winword.exe` | Parent process | Parent of suspicious PowerShell processes |
| `cmd.exe` | Child process | Child of PowerShell PID 4638 |
| `4638` | Process ID | PowerShell process correlated with network and child activity |
| `4671` | Process ID | Child `cmd.exe` process |

## Command-Line Indicators

- `-EncodedCommand`
- `-WindowStyle Hidden`
- `command_type: encoded_command`
- `encoding: base64`

These indicators are observed in EVT-003006 and EVT-003007.

## Network Indicators

| Indicator | Type | Observation |
|---|---|---|
| `192.0.2.53` | Source IP | Synthetic/documentation address |
| `203.0.113.80` | Destination IP | Synthetic/documentation address |
| `updates.example.test` | Domain | Documentation/test domain |
| TCP/443 | Port | HTTPS connection |
| HTTPS | Protocol | Outbound connection EVT-003008 |

## Classification

These values are **observed evidence**, not automatically malicious indicators.

The IP addresses are documentation/test ranges and the domain is a laboratory test domain.

No external attribution is made from these indicators.

## Recommended Enrichment

In a production environment, analysts would enrich these observables with asset context, EDR telemetry, DNS history, proxy/firewall records, file reputation, process lineage, and threat-intelligence sources.

No external enrichment was performed for this synthetic case.
