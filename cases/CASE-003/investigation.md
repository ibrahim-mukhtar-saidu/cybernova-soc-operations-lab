# CASE-003 — Investigation

## 1. Investigation Objective

Determine whether the detected PowerShell execution represents suspicious or potentially unauthorized endpoint activity and identify the strongest evidence available for triage.

## 2. Initial Triage

### Observed Evidence

The detection engine produced two high-severity, high-confidence alerts.

Both alerts involve:

- Host: `lab-win-04`
- User: `david`
- Process: `powershell.exe`
- Parent process: `winword.exe`
- Encoded PowerShell command execution

The second alert contains additional correlation:

- Hidden PowerShell window
- Outbound HTTPS activity
- Child `cmd.exe` process

### Analyst Interpretation

The combination of an Office application spawning encoded PowerShell is significantly more suspicious than routine PowerShell administration. The additional hidden-window, network, and child-process correlations increase investigative priority.

## 3. Alert 1 — EVT-003006

### Observed Evidence

- Event ID: `EVT-003006`
- Process ID: `4632`
- Parent: `winword.exe`
- Command contains `-EncodedCommand`
- Risk score: `100`
- Severity: high
- Confidence: high

### Interpretation

The execution chain is suspicious because PowerShell was launched from Microsoft Word while using an encoded command.

No network or child-process correlation was associated with this specific process ID in the detection window.

## 4. Alert 2 — EVT-003007

### Observed Evidence

- Event ID: `EVT-003007`
- Process ID: `4638`
- Parent: `winword.exe`
- Command contains `-EncodedCommand`
- Command contains `-WindowStyle Hidden`
- Network event: `EVT-003008`
- Child process event: `EVT-003009`
- Risk score: `100`
- Severity: high
- Confidence: high

### Interpretation

This is the stronger alert because multiple independent telemetry characteristics correlate to the same process.

The process lineage and subsequent network/child-process activity are consistent with suspicious execution.

## 5. Network Correlation

`EVT-003008` records outbound HTTPS activity associated with PowerShell process ID `4638`.

Observed destination:

- IP: `203.0.113.80`
- Domain: `updates.example.test`
- Port: `443`
- Protocol: HTTPS

The destination belongs to the controlled documentation/test dataset.

Therefore, the network event demonstrates process correlation in the laboratory dataset but does not establish communication with a real malicious infrastructure.

## 6. Child-Process Correlation

`EVT-003009` records:

- Process: `cmd.exe`
- Parent process: `powershell.exe`
- Parent PID: `4638`
- Process ID: `4671`
- Command: `cmd.exe /c whoami`

This establishes a process relationship between PowerShell PID `4638` and the child `cmd.exe` event.

## 7. Negative Evidence

The dataset also contains legitimate PowerShell activity:

- `EVT-003001`
- `EVT-003002`
- `EVT-003004`
- `EVT-003005`
- `EVT-003010`

These events demonstrate that the detection is not intended to alert on every PowerShell process.

Automated testing confirmed that the legitimate subset generated zero alerts.

## 8. Investigation Conclusion

The available telemetry supports a **confirmed suspicious execution pattern within the synthetic laboratory dataset**.

The evidence does not establish:

- confirmed malware execution,
- confirmed compromise,
- persistence,
- credential theft,
- data exfiltration,
- real-world command-and-control,
- or attacker attribution.

Those conclusions would require additional evidence.
