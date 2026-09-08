# CASE-003 Hunting

## Hunting Objective

Determine whether the suspicious PowerShell pattern observed in CASE-003 occurs elsewhere in the available synthetic telemetry.

## Hypothesis 1 — Office-to-PowerShell Execution

**Hypothesis:** Microsoft Office applications may launch PowerShell in suspicious execution chains.

### Search Logic

Look for PowerShell processes whose parent process is:

- `winword.exe`
- `excel.exe`
- `outlook.exe`
- `msaccess.exe`
- `powerpnt.exe`

### Result

The positive dataset contains PowerShell processes launched by `winword.exe`.

This supports the detection hypothesis within the synthetic dataset.

## Hypothesis 2 — Encoded PowerShell

**Hypothesis:** Encoded PowerShell commands may identify execution requiring analyst review.

### Search Logic

Search for:

- `-EncodedCommand`
- `-enc`
- `command_type: encoded_command`
- `encoding: base64`

### Result

EVT-003006 and EVT-003007 contain encoded-command indicators.

## Hypothesis 3 — PowerShell-to-Network Correlation

**Hypothesis:** Suspicious PowerShell execution followed by outbound network activity increases investigative priority.

### Search Logic

Correlate host, user, process ID, process name, and timestamps within the detection window.

### Result

EVT-003008 correlates with PowerShell PID `4638`.

## Hypothesis 4 — PowerShell Child Processes

**Hypothesis:** PowerShell spawning command interpreters provides additional execution context.

### Search Logic

Search for child processes where the parent process is PowerShell and the parent PID matches a suspicious process.

### Result

EVT-003009 identifies `cmd.exe` PID `4671` as a child of PowerShell PID `4638`.

## Negative Hunting Evidence

Routine PowerShell events EVT-003001, EVT-003002, EVT-003004, EVT-003005, and EVT-003010 are represented as benign baseline activity and do not trigger DET-ENDPOINT-001.

## Limitations

The dataset is intentionally small and synthetic.

Absence of additional matches cannot be interpreted as evidence that the behavior does not exist elsewhere.
