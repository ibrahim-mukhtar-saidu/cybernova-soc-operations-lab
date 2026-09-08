# CASE-003 — Suspicious PowerShell Execution

## Case Summary

- **Case ID:** CASE-003
- **Detection:** DET-ENDPOINT-001 — Suspicious PowerShell Execution
- **Severity:** High
- **Confidence:** High
- **Status:** Open
- **Environment:** Synthetic Windows endpoint telemetry
- **Primary host:** `lab-win-04`
- **Primary user:** `david`
- **Primary process:** `powershell.exe`
- **MITRE ATT&CK:** T1059.001 — PowerShell

## Executive Summary

CASE-003 investigates suspicious PowerShell execution observed on `lab-win-04` under user `david`.

The detection generated two high-severity alerts. The first involved PowerShell execution using an encoded command with `winword.exe` as the parent process.

The second involved encoded PowerShell execution with a hidden window, the same suspicious Office parent process, correlated outbound HTTPS activity, and a child `cmd.exe` process.

The telemetry is consistent with suspicious endpoint execution and warrants analyst investigation.

The available laboratory evidence does not independently establish confirmed malware execution, successful compromise, persistence, or data exfiltration.

## Key Observations

1. `powershell.exe` executed with `-EncodedCommand`.
2. `winword.exe` was the parent process for both suspicious PowerShell processes.
3. The second PowerShell process used `-WindowStyle Hidden`.
4. PowerShell process ID `4638` correlated with outbound HTTPS event `EVT-003008`.
5. PowerShell process ID `4638` spawned `cmd.exe` in `EVT-003009`.
6. The destination `updates.example.test` is a documentation/test domain.
7. All telemetry is synthetic laboratory data.

## Current Determination

**Suspicious activity confirmed in synthetic telemetry. Compromise not confirmed.**

Further investigation is required to determine whether the execution was authorized, what the encoded commands represented, and whether the network activity was expected.

## Evidence Classification

This case distinguishes:

- **Observed evidence:** directly represented in telemetry or detection output.
- **Analyst interpretation:** reasoned assessment based on observed evidence.
- **Confirmed finding:** a conclusion supported by available evidence.
- **Hypothesis:** an investigative possibility requiring validation.

## Scope and Limitations

This case is part of a controlled SOC operations laboratory.

It does not represent production security monitoring or a real-world compromise.

No external attribution is made from this dataset.
