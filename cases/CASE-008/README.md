# CASE-008 — Malware Execution Investigation

## Scenario

Synthetic SOC laboratory investigation of suspicious malware execution activity detected on a workstation.

## Detection

- Detection ID: `DET-MALWARE-001`
- Detection name: Suspicious Malware Execution Detection
- Alert ID: `ALERT-CASE-008-DET-MALWARE-001`
- Severity: High
- Confidence: High

## Primary Host

- Host: `lab-ws-02`
- User: `analyst`
- Process: `invoice_viewer.exe`
- File: `/tmp/invoice_viewer.exe`

## Triggering Evidence

The detection observed multiple suspicious execution indicators associated with `EVT-008001`:

1. Executable from a user-writable path
2. Suspicious executable extension
3. Known malware indicator
4. High-entropy executable
5. Suspicious process name

The second event, `EVT-008002`, represents benign execution activity and did not generate an alert.

## Investigation Objective

Determine whether the observed execution should be treated as potentially malicious, preserve the available laboratory evidence, identify investigation pivots, and document appropriate containment and follow-up actions.

## Scope

This is synthetic laboratory telemetry. It does not represent a real-world production incident or confirmed malware infection.

## Evidence Chain

Telemetry → Detection → Alert → Triage → Investigation → Indicators → Threat Intelligence → Hunting → Response → Final Report → Lessons Learned
