# SOC Telemetry Standard

## Purpose

This directory contains synthetic and authorized laboratory telemetry used
by the CYBERNOVA SOC Operations Lab.

The telemetry model is designed to support repeatable Security Operations
Center workflows including:

- Detection engineering
- Alert generation
- Alert triage
- Investigation
- Timeline reconstruction
- Indicator extraction
- Threat hunting
- MITRE ATT&CK mapping
- Incident response
- Detection validation

Telemetry in this repository must never contain unauthorized production data,
real credentials, private information, or confidential third-party data.

---

## Telemetry Design Principles

All telemetry should be:

1. Synthetic or explicitly authorized.
2. Deterministic where practical.
3. Traceable to a detection or investigation.
4. Timestamped using UTC.
5. Structured for machine processing.
6. Readable by human analysts.
7. Reproducible.
8. Suitable for testing detection logic.
9. Clearly separated from analyst conclusions.
10. Safe for publication in a public GitHub repository.

---

## Common Event Schema

Telemetry events should use a common structure wherever practical.

```json
{
  "event_id": "EVT-000001",
  "timestamp": "2026-09-08T10:15:00Z",
  "event_type": "authentication",
  "source": "linux-auth",
  "host": "lab-auth-01",
  "user": "alice",
  "source_ip": "192.0.2.50",
  "destination_ip": null,
  "action": "login_failure",
  "status": "failure",
  "process": null,
  "command_line": null,
  "file_path": null,
  "domain": null,
  "port": null,
  "protocol": null,
  "message": "Failed password authentication attempt",
  "metadata": {}
}
Required Fields

The following fields should be present whenever applicable.

Field	Description
event_id	Unique laboratory event identifier
timestamp	UTC timestamp
event_type	Category of the event
source	Telemetry source
host	System associated with the event
action	Action represented by the event
status	Outcome of the action
message	Human-readable event description
metadata	Additional structured information

Fields that do not apply to an event may use null.

Optional Security Fields

The following fields may be included when relevant:

user
source_ip
destination_ip
source_port
destination_port
protocol
process
process_id
parent_process
command_line
file_path
file_hash
file_size
domain
url
http_method
http_status
authentication_method
logon_type
severity
Event Categories
Authentication

Authentication telemetry represents events involving:

Successful authentication
Failed authentication
Account lockout
Password changes
Privilege changes
Authentication method changes
Suspicious authentication patterns

Example sources:

Linux authentication logs
Windows security events
Synthetic identity-provider events
Application authentication logs
Endpoint

Endpoint telemetry represents activity occurring on a host.

Examples include:

Process creation
Process termination
File creation
File modification
File deletion
Script execution
Persistence activity
Security-control changes
Network

Network telemetry represents communications between systems.

Examples include:

Connection attempts
DNS requests
HTTP connections
TLS connections
Unusual outbound traffic
Port activity
Repeated connection attempts
Web

Web telemetry represents application and HTTP activity.

Examples include:

HTTP requests
Authentication requests
Web errors
Suspicious parameters
Repeated requests
Authentication attacks
Web exploitation indicators
Timestamp Standard

All timestamps should use UTC.

Preferred format:

YYYY-MM-DDTHH:MM:SSZ

Example:

2026-09-08T10:15:00Z

Investigations should preserve the original event timestamp.

If a source uses another timezone, the original timezone should be documented
and the normalized UTC representation should be used for correlation.

Event Identifiers

Event identifiers should be unique within the laboratory.

Recommended format:

EVT-000001
EVT-000002
EVT-000003

Identifiers should not be reused after an event is published.

Case Correlation

Events associated with an investigation should be traceable to the relevant
case.

Where appropriate, case metadata may be maintained separately from raw
telemetry so that original evidence remains unchanged.

Example relationship:

CASE-001
   |
   +-- EVT-000101
   +-- EVT-000102
   +-- EVT-000103
   +-- EVT-000104
Detection Correlation

Telemetry should also support traceability to detection rules.

Example:

DET-AUTH-001
      |
      +-- EVT-000101
      +-- EVT-000102
      +-- EVT-000103

The detection should explain why the events collectively satisfy the
detection condition.

Evidence Integrity

Raw telemetry should be treated as evidence.

Analysts must distinguish between:

Raw observed event
Derived field
Analyst interpretation
Hypothesis
Confirmed finding
Recommended action

Raw telemetry should not be silently rewritten to make an investigation
appear stronger.

Evidence handling requirements are defined in:

docs/evidence-integrity.md
Synthetic IP Addressing

Public documentation should use documentation or laboratory address ranges
where possible.

Examples include:

192.0.2.0/24
198.51.100.0/24
203.0.113.0/24

These ranges are reserved for documentation and examples.

Real public IP addresses should not be introduced into synthetic incidents
unless there is a documented and authorized reason.

Sensitive Data Restrictions

The repository must not contain:

Real passwords
API keys
Access tokens
Private keys
Session cookies
Personal identifying information
Confidential corporate information
Unauthorized production logs
Private customer information

Synthetic values should be used instead.

Reproducibility

Where practical, telemetry generation should be deterministic.

A future telemetry generator may support:

seed
scenario
event_count
start_time
interval
source_host
user
source_ip

This allows detection tests and investigations to be reproduced consistently.

Quality Requirements

Before telemetry is accepted into the laboratory, verify:

 Event identifiers are unique.
 Timestamps are valid.
 Timestamps use UTC.
 Required fields are present.
 Event types are valid.
 No unauthorized sensitive information exists.
 Synthetic values are clearly identifiable.
 Events can be correlated to a case or detection where applicable.
 JSON or structured data parses correctly.
 Formatting passes repository validation.
Current Implementation Status

The telemetry directory currently establishes the standard and storage
structure.

Individual datasets will be introduced incrementally as detection and
investigation scenarios are implemented.

The repository must not imply that telemetry sources or integrations exist
until they have been implemented and validated.

Future Expansion

The telemetry model may later support:

ECS-style normalization
Sigma-compatible detection fields
Windows Event Logs
Linux authentication logs
Sysmon-style endpoint events
DNS telemetry
HTTP access logs
Firewall events
Process execution telemetry
File-integrity events
Identity-provider events
Cloud audit events

Any future schema extension should preserve backward compatibility where
practical and document the change.

Standard

The objective of this telemetry model is not to simulate an entire enterprise
environment.

The objective is to provide sufficiently realistic, structured, reproducible,
and defensible telemetry for demonstrating professional SOC analysis.
