# CASE-003 Timeline

## Timeline Summary

CASE-003 contains a suspicious PowerShell execution chain on `lab-win-04` involving Microsoft Word as the parent process, encoded PowerShell commands, a hidden PowerShell window, outbound HTTPS activity, and a child `cmd.exe` process.

All timestamps are represented in UTC.

## Event Timeline

| Event ID | Host | User | Event | Key Observation |
|---|---|---|---|---|
| EVT-003001 | lab-win-01 | alice | process_creation | Routine PowerShell `Get-Service` |
| EVT-003002 | lab-win-02 | bob | process_creation | Routine PowerShell `Get-Process` |
| EVT-003003 | lab-win-01 | alice | process_creation | Routine `cmd.exe /c whoami` |
| EVT-003004 | lab-win-03 | carol | process_creation | Routine PowerShell `Get-Date` |
| EVT-003005 | lab-win-02 | bob | process_creation | Routine service enumeration |
| EVT-003006 | lab-win-04 | david | process_creation | Encoded PowerShell launched by `winword.exe` |
| EVT-003007 | lab-win-04 | david | process_creation | Hidden encoded PowerShell launched by `winword.exe` |
| EVT-003008 | lab-win-04 | david | network_connection | PowerShell PID 4638 makes outbound HTTPS connection |
| EVT-003009 | lab-win-04 | david | process_creation | `cmd.exe` child of PowerShell PID 4638 |
| EVT-003010 | lab-win-05 | erin | process_creation | Routine PowerShell `Get-WinEvent` |

## Critical Execution Chain

`winword.exe` → `powershell.exe` PID 4638 → encoded/hidden execution → HTTPS EVT-003008 → `cmd.exe` PID 4671 EVT-003009

## Correlation

EVT-003008 correlates with PowerShell PID `4638`.

EVT-003009 identifies `cmd.exe` PID `4671` as a child of PowerShell PID `4638`.

The suspicious events occur within the detection engine's five-minute correlation window.

## Evidence Boundary

The timeline establishes an observed process and network sequence in synthetic telemetry.

It does not independently establish malicious intent, successful compromise, persistence, credential theft, privilege escalation, or data exfiltration.
