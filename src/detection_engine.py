#!/usr/bin/env python3
"""
CYBERNOVA SOC Operations Lab
Detection Engine

Implemented detections:
    DET-AUTH-001 - SSH Brute-Force Authentication Detection
    DET-AUTH-002 - Password Spraying Authentication Detection
    DET-AUTH-003 - Suspicious Post-Authentication Privileged Session
    DET-ENDPOINT-001 - Suspicious PowerShell Execution
    DET-NET-001 - Suspicious C2 Beaconing Activity

Purpose:
    Read normalized telemetry, validate the input,
    evaluate supported detection rules, and generate deterministic
    structured alerts.

Evidence model:
    The engine reports observed telemetry patterns.
    A successful authentication following suspicious activity is
    evidence of an observed sequence, not proof of account compromise.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# DET-AUTH-001: SSH Brute Force
# ---------------------------------------------------------------------------

DETECTION_AUTH_001 = "DET-AUTH-001"
DETECTION_AUTH_001_NAME = "SSH Brute-Force Authentication Detection"
DETECTION_AUTH_001_VERSION = "1.0"

AUTH_001_FAILURE_THRESHOLD = 5
AUTH_001_WINDOW_MINUTES = 5


# ---------------------------------------------------------------------------
# DET-AUTH-002: Password Spraying
# ---------------------------------------------------------------------------

DETECTION_AUTH_002 = "DET-AUTH-002"
DETECTION_AUTH_002_NAME = "Password Spraying Authentication Detection"
DETECTION_AUTH_002_VERSION = "1.0"

AUTH_002_MIN_FAILURES = 6
AUTH_002_MIN_DISTINCT_USERS = 6
AUTH_002_WINDOW_MINUTES = 5


# ---------------------------------------------------------------------------
# DET-AUTH-003: Suspicious Post-Authentication Privileged Session
# ---------------------------------------------------------------------------

DETECTION_AUTH_003 = "DET-AUTH-003"
DETECTION_AUTH_003_NAME = (
    "Suspicious Post-Authentication Privileged Session"
)
DETECTION_AUTH_003_VERSION = "1.0"

AUTH_003_MIN_FAILURES = 4
AUTH_003_MIN_COMMANDS = 2
AUTH_003_WINDOW_MINUTES = 5


# ---------------------------------------------------------------------------
# DET-ENDPOINT-001: Suspicious PowerShell
# ---------------------------------------------------------------------------

DETECTION_ENDPOINT_001 = "DET-ENDPOINT-001"
DETECTION_ENDPOINT_001_NAME = "Suspicious PowerShell Execution"
DETECTION_ENDPOINT_001_VERSION = "1.0"

ENDPOINT_001_CORRELATION_WINDOW_MINUTES = 5


# ---------------------------------------------------------------------------
# DET-NET-001: Suspicious C2 Beaconing
# ---------------------------------------------------------------------------

DETECTION_NET_001 = "DET-NET-001"
DETECTION_NET_001_NAME = "Suspicious C2 Beaconing Activity"
DETECTION_NET_001_VERSION = "1.0"

NET_001_MIN_CONNECTIONS = 5
NET_001_WINDOW_MINUTES = 10
NET_001_EXPECTED_INTERVAL_SECONDS = 60
NET_001_INTERVAL_TOLERANCE_SECONDS = 10
NET_001_MIN_REGULARITY_RATIO = 0.75


# ---------------------------------------------------------------------------
# Telemetry schemas
# ---------------------------------------------------------------------------

AUTH_REQUIRED_FIELDS = {
    "event_id",
    "timestamp",
    "event_type",
    "source",
    "host",
    "user",
    "source_ip",
    "action",
    "status",
}

ENDPOINT_REQUIRED_FIELDS = {
    "event_id",
    "timestamp",
    "event_type",
    "source",
    "host",
    "user",
    "action",
    "status",
    "process",
    "command_line",
    "file_path",
    "metadata",
}

NETWORK_REQUIRED_FIELDS = {
    "event_id",
    "timestamp",
    "event_type",
    "source",
    "direction",
    "action",
    "status",
}

VALID_FAILURE_STATUSES = {"failure"}

VALID_FAILURE_ACTIONS = {
    "login_failure",
    "authentication_failure",
}

SUCCESS_STATUSES = {"success"}

SUCCESS_ACTIONS = {
    "login_success",
    "authentication_success",
}


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class TelemetryValidationError(ValueError):
    """Raised when telemetry does not meet the expected schema."""


# ---------------------------------------------------------------------------
# Generic telemetry helpers
# ---------------------------------------------------------------------------

def parse_timestamp(value: str) -> datetime:
    """Parse an ISO-8601 timestamp and normalize it to UTC."""

    if not isinstance(value, str) or not value.strip():
        raise TelemetryValidationError(
            "timestamp must be a non-empty string"
        )

    normalized = value.strip()

    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"

    try:
        timestamp = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise TelemetryValidationError(
            f"invalid timestamp: {value}"
        ) from exc

    if timestamp.tzinfo is None:
        raise TelemetryValidationError(
            f"timestamp must include timezone information: {value}"
        )

    return timestamp.astimezone(timezone.utc)


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    """Load and validate JSONL telemetry."""

    if not path.exists():
        raise FileNotFoundError(
            f"telemetry file not found: {path}"
        )

    if not path.is_file():
        raise TelemetryValidationError(
            f"input is not a file: {path}"
        )

    events: list[dict[str, Any]] = []
    event_ids: set[str] = set()

    with path.open("r", encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()

            if not line:
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise TelemetryValidationError(
                    f"invalid JSON on line {line_number}: {exc.msg}"
                ) from exc

            if not isinstance(event, dict):
                raise TelemetryValidationError(
                    f"line {line_number}: event must be a JSON object"
                )

            event_id = event.get("event_id")

            if not isinstance(event_id, str) or not event_id.strip():
                raise TelemetryValidationError(
                    f"line {line_number}: event_id must be non-empty"
                )

            if event_id in event_ids:
                raise TelemetryValidationError(
                    f"duplicate event_id on line {line_number}: {event_id}"
                )

            event_ids.add(event_id)

            event["_parsed_timestamp"] = parse_timestamp(
                event["timestamp"]
            )

            validate_event_fields(event, line_number)

            events.append(event)

    if not events:
        raise TelemetryValidationError(
            "telemetry file contains no events"
        )

    events.sort(
        key=lambda event: event["_parsed_timestamp"]
    )

    return events


def validate_event_fields(
    event: dict[str, Any],
    line_number: int,
) -> None:
    """Validate fields according to the telemetry event type."""

    event_type = event["event_type"]

    if event_type == "authentication":
        missing = AUTH_REQUIRED_FIELDS - set(event)

        if missing:
            missing_fields = ", ".join(sorted(missing))
            raise TelemetryValidationError(
                f"line {line_number}: missing authentication fields: "
                f"{missing_fields}"
            )

        for field in ("host", "user", "source_ip"):
            if (
                not isinstance(event[field], str)
                or not event[field].strip()
            ):
                raise TelemetryValidationError(
                    f"line {line_number}: {field} must be non-empty"
                )

        for field in ("status", "action"):
            if not isinstance(event[field], str):
                raise TelemetryValidationError(
                    f"line {line_number}: {field} must be a string"
                )

        return

    if event_type == "session_start":
        required = {
            "event_id",
            "timestamp",
            "event_type",
            "source",
            "host",
            "user",
        }

        missing = required - set(event)

        if missing:
            missing_fields = ", ".join(sorted(missing))
            raise TelemetryValidationError(
                f"line {line_number}: missing session fields: "
                f"{missing_fields}"
            )

        if event["source"] != "authentication":
            raise TelemetryValidationError(
                f"line {line_number}: invalid session source"
            )

        return

    if event_type == "command_execution":
        required = {
            "event_id",
            "timestamp",
            "event_type",
            "source",
            "host",
            "user",
            "command_line",
        }

        missing = required - set(event)

        if missing:
            missing_fields = ", ".join(sorted(missing))
            raise TelemetryValidationError(
                f"line {line_number}: missing command fields: "
                f"{missing_fields}"
            )

        if event["source"] != "authentication":
            raise TelemetryValidationError(
                f"line {line_number}: invalid command source"
            )

        if not isinstance(event["command_line"], str):
            raise TelemetryValidationError(
                f"line {line_number}: command_line must be a string"
            )

        return

    if event_type == "network_connection":
        if event["source"] == "endpoint":
            missing = ENDPOINT_REQUIRED_FIELDS - set(event)

            if missing:
                missing_fields = ", ".join(sorted(missing))
                raise TelemetryValidationError(
                    f"line {line_number}: missing endpoint fields: "
                    f"{missing_fields}"
                )

            return

        if "destination" not in event:
            raise TelemetryValidationError(
                f"line {line_number}: network event missing destination"
            )

        if not isinstance(event["destination"], dict):
            raise TelemetryValidationError(
                f"line {line_number}: destination must be an object"
            )

        for field in ("ip", "port", "protocol"):
            if field not in event["destination"]:
                raise TelemetryValidationError(
                    f"line {line_number}: destination missing {field}"
                )

        if not isinstance(event["source"], dict):
            raise TelemetryValidationError(
                f"line {line_number}: network source must be an object"
            )

        for field in (
            "host",
            "ip",
            "process_name",
            "process_path",
        ):
            if field not in event["source"]:
                raise TelemetryValidationError(
                    f"line {line_number}: network source missing {field}"
                )

        return

    if event_type == "process_start":
        if not isinstance(event["source"], dict):
            raise TelemetryValidationError(
                f"line {line_number}: process source must be an object"
            )

        source = event["source"]

        for field in (
            "host",
            "ip",
            "process_name",
            "process_path",
            "pid",
        ):
            if field not in source:
                raise TelemetryValidationError(
                    f"line {line_number}: process source missing {field}"
                )

        return

    if event_type == "process_network_correlation":
        if not isinstance(event["source"], dict):
            raise TelemetryValidationError(
                f"line {line_number}: correlation source must be an object"
            )

        if not isinstance(event["destination"], dict):
            raise TelemetryValidationError(
                f"line {line_number}: correlation destination must be an object"
            )

        for field in (
            "host",
            "ip",
            "process_name",
            "process_path",
            "pid",
        ):
            if field not in event["source"]:
                raise TelemetryValidationError(
                    f"line {line_number}: correlation source missing {field}"
                )

        for field in ("ip", "port", "protocol"):
            if field not in event["destination"]:
                raise TelemetryValidationError(
                    f"line {line_number}: correlation destination missing {field}"
                )

        if "connection_count" not in event.get("metadata", {}):
            raise TelemetryValidationError(
                f"line {line_number}: correlation metadata missing connection_count"
            )

        return

    if event_type == "process_creation":
        if event["source"] == "endpoint":
            missing = ENDPOINT_REQUIRED_FIELDS - set(event)

            if missing:
                missing_fields = ", ".join(sorted(missing))
                raise TelemetryValidationError(
                    f"line {line_number}: missing endpoint fields: "
                    f"{missing_fields}"
                )

            return

    raise TelemetryValidationError(
        f"line {line_number}: unsupported event type/source combination"
    )


def events_in_window(
    events: list[dict[str, Any]],
    start: datetime,
    end: datetime,
) -> list[dict[str, Any]]:
    """Return events whose timestamps fall within an inclusive window."""

    return [
        event
        for event in events
        if start <= event["_parsed_timestamp"] <= end
    ]


# ---------------------------------------------------------------------------
# DET-AUTH-001 helpers
# ---------------------------------------------------------------------------

def is_failed_authentication(
    event: dict[str, Any],
) -> bool:
    """Return True when an event represents a failed authentication."""

    return (
        event["event_type"] == "authentication"
        and event["status"] in VALID_FAILURE_STATUSES
        and event["action"] in VALID_FAILURE_ACTIONS
    )


def is_successful_authentication(
    event: dict[str, Any],
) -> bool:
    """Return True when an event represents a successful authentication."""

    return (
        event["event_type"] == "authentication"
        and event["status"] in SUCCESS_STATUSES
        and event["action"] in SUCCESS_ACTIONS
    )


def build_auth_001_alert(
    source_ip: str,
    user: str,
    host: str,
    threshold_events: list[dict[str, Any]],
    success_event: dict[str, Any] | None,
) -> dict[str, Any]:
    """Build a deterministic DET-AUTH-001 alert."""

    first_event = threshold_events[0]
    last_event = threshold_events[-1]

    supporting_event_ids = [
        event["event_id"]
        for event in threshold_events
    ]

    if success_event is not None:
        supporting_event_ids.append(
            success_event["event_id"]
        )

    escalated = success_event is not None

    severity = "high" if escalated else "medium"

    if escalated:
        timestamp = success_event["timestamp"]
        successful_authentication_observed = True
        successful_authentication_event_id = (
            success_event["event_id"]
        )
        rationale = (
            f"{len(threshold_events)} failed authentication attempts "
            "from the same source and user were followed by a "
            "successful authentication."
        )
        observed_evidence = [
            f"{len(threshold_events)} failed SSH authentication attempts",
            "successful authentication observed after failures",
        ]
    else:
        timestamp = last_event["timestamp"]
        successful_authentication_observed = False
        successful_authentication_event_id = None
        rationale = (
            f"{len(threshold_events)} failed authentication attempts "
            f"for user '{user}' from {source_ip} occurred within "
            f"{AUTH_001_WINDOW_MINUTES} minutes. No subsequent "
            "successful SSH authentication was observed in the "
            "supplied telemetry."
        )
        observed_evidence = [
            f"{len(threshold_events)} failed SSH authentication attempts",
            "no subsequent successful authentication observed",
        ]

    return {
        "alert_id": "ALERT-CASE-001-DET-AUTH-001",
        "detection_id": DETECTION_AUTH_001,
        "detection_name": DETECTION_AUTH_001_NAME,
        "detection_version": DETECTION_AUTH_001_VERSION,
        "status": "open",
        "severity": severity,
        "confidence": "high",
        "evidence_classification": {
            "observed_evidence": observed_evidence,
            "analyst_interpretation": (
                "The telemetry is consistent with an SSH brute-force "
                "authentication pattern. A successful authentication "
                "after the failures increases investigative priority, "
                "but does not independently prove account compromise."
            ),
        },
        "event_type": "authentication",
        "protocol": "ssh",
        "host": host,
        "source_ip": source_ip,
        "user": user,
        "failed_attempt_count": len(threshold_events),
        "threshold": {
            "failed_attempts": AUTH_001_FAILURE_THRESHOLD,
            "window_minutes": AUTH_001_WINDOW_MINUTES,
        },
        "first_seen": first_event["timestamp"],
        "last_seen": last_event["timestamp"],
        "timestamp": timestamp,
        "successful_authentication_observed": (
            successful_authentication_observed
        ),
        "successful_authentication_event_id": (
            successful_authentication_event_id
        ),
        "supporting_event_ids": supporting_event_ids,
        "rationale": rationale,
        "evidence": {
            "observed_evidence": observed_evidence,
            "analyst_interpretation": (
                "The telemetry is consistent with an SSH brute-force "
                "authentication pattern. A successful authentication "
                "after the failures increases investigative priority, "
                "but does not independently prove account compromise."
            ),
        },
        "mitre_attack": {
            "tactics": ["credential-access"],
            "techniques": ["T1110"],
            "subtechniques": ["T1110.001"],
        },
        "recommended_action": (
            "Validate whether the source and account activity were "
            "authorized. Preserve supporting authentication telemetry, "
            "review endpoint and identity evidence, and investigate "
            "the successful authentication if it was not expected."
        ),
    }

def detect_auth_001(
    events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Detect SSH brute-force authentication activity."""

    alerts: list[dict[str, Any]] = []

    grouped: defaultdict[
        tuple[str, str],
        list[dict[str, Any]],
    ] = defaultdict(list)

    for event in events:
        if not is_failed_authentication(event):
            continue

        key = (
            str(event["source_ip"]),
            str(event["user"]),
        )
        grouped[key].append(event)

    for key, failures in grouped.items():
        failures.sort(
            key=lambda event: event["_parsed_timestamp"]
        )

        for index, first_failure in enumerate(failures):
            window_end = (
                first_failure["_parsed_timestamp"]
                + timedelta(minutes=AUTH_001_WINDOW_MINUTES)
            )

            threshold_events = [
                event
                for event in failures[index:]
                if event["_parsed_timestamp"] <= window_end
            ]

            if len(threshold_events) < AUTH_001_FAILURE_THRESHOLD:
                continue

            threshold_time = threshold_events[
                AUTH_001_FAILURE_THRESHOLD - 1
            ]["_parsed_timestamp"]

            success_event = None

            for candidate in events:
                if not is_successful_authentication(candidate):
                    continue


                if candidate.get("source_ip") != key[0]:
                    continue

                if candidate.get("user") != key[1]:
                    continue

                if candidate["_parsed_timestamp"] <= threshold_time:
                    continue

                success_event = candidate
                break

            host = str(threshold_events[0]["host"])

            alerts.append(
                build_auth_001_alert(
                    source_ip=key[0],
                    user=key[1],
                    host=host,
                    threshold_events=threshold_events,
                    success_event=success_event,
                )
            )

            break

    return alerts

# ---------------------------------------------------------------------------
# DET-AUTH-002 helpers
# ---------------------------------------------------------------------------

def build_auth_002_alert(
    source_ip: str,
    host: str,
    threshold_events: list[dict[str, Any]],
    success_event: dict[str, Any] | None,
) -> dict[str, Any]:
    """Build a deterministic DET-AUTH-002 alert."""

    first_event = threshold_events[0]
    last_event = threshold_events[-1]

    targeted_users = sorted(
        {
            str(event["user"])
            for event in threshold_events
        }
    )

    supporting_event_ids = [
        event["event_id"]
        for event in threshold_events
    ]

    escalated = success_event is not None

    if success_event is not None:
        supporting_event_ids.append(
            success_event["event_id"]
        )

        timestamp = success_event["timestamp"]
        alert_source_ip = success_event["source_ip"]
        alert_host = success_event["host"]
        successful_authentication_observed = True
        successful_authentication_event_id = (
            success_event["event_id"]
        )
        successful_authentication_user = (
            success_event["user"]
        )
        severity = "high"
        confidence = "high"
        observed_evidence = [
            f"{len(threshold_events)} failed authentication attempts",
            f"{len(targeted_users)} distinct targeted users",
            "successful authentication observed",
        ]
        rationale = (
            f"Source {source_ip} targeted "
            f"{len(targeted_users)} users with "
            f"{len(threshold_events)} failed authentication "
            "attempts before a successful login."
        )
    else:
        timestamp = last_event["timestamp"]
        alert_source_ip = source_ip
        alert_host = host
        successful_authentication_observed = False
        successful_authentication_event_id = None
        successful_authentication_user = None
        severity = "medium"
        confidence = "medium"
        observed_evidence = [
            f"{len(threshold_events)} failed authentication attempts",
            f"{len(targeted_users)} distinct targeted users",
            "no successful authentication observed",
        ]
        rationale = (
            f"Source {source_ip} targeted "
            f"{len(targeted_users)} users with "
            f"{len(threshold_events)} failed authentication "
            "attempts within the password-spraying detection window. "
            "No successful authentication from the source was "
            "observed in the supplied telemetry."
        )

    return {
        "alert_id": (
            f"ALERT-CASE-002-{DETECTION_AUTH_002}"
        ),
        "detection_id": DETECTION_AUTH_002,
        "detection_name": DETECTION_AUTH_002_NAME,
        "detection_version": DETECTION_AUTH_002_VERSION,
        "severity": severity,
        "confidence": confidence,
        "status": "open",
        "timestamp": timestamp,
        "source_ip": alert_source_ip,
        "host": alert_host,
        "targeted_user_count": len(targeted_users),
        "targeted_users": targeted_users,
        "failed_attempt_count": len(threshold_events),
        "successful_authentication_observed": (
            successful_authentication_observed
        ),
        "successful_authentication_event_id": (
            successful_authentication_event_id
        ),
        "successful_authentication_user": (
            successful_authentication_user
        ),
        "supporting_event_ids": supporting_event_ids,
        "evidence_classification": {
            "observed_evidence": observed_evidence,
            "analyst_interpretation": (
                "The source exhibited password-spraying behavior "
                "across multiple accounts. A successful authentication "
                "increases risk but does not by itself prove account "
                "compromise."
            ),
        },
        "mitre_attack": {
            "tactics": ["credential_access"],
            "techniques": [
                {
                    "id": "T1110",
                    "name": "Brute Force",
                },
                {
                    "id": "T1110.003",
                    "name": "Password Spraying",
                },
            ],
        },
        "rationale": rationale,
    }

def is_password_authentication(
    event: dict[str, Any],
) -> bool:
    """Return True when an authentication event uses password authentication."""

    metadata = event.get("metadata")

    if not isinstance(metadata, dict):
        return False

    method = str(
        metadata.get("authentication_method") or ""
    ).lower()

    return method == "password"


def detect_auth_002(
    events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Detect password spraying authentication activity."""

    alerts: list[dict[str, Any]] = []

    failures_by_source: defaultdict[
        str,
        list[dict[str, Any]],
    ] = defaultdict(list)

    successes_by_source: defaultdict[
        str,
        list[dict[str, Any]],
    ] = defaultdict(list)

    for event in events:
        if (
            is_failed_authentication(event)
            and is_password_authentication(event)
        ):
            failures_by_source[
                event["source_ip"]
            ].append(event)

        elif is_successful_authentication(event):
            successes_by_source[
                event["source_ip"]
            ].append(event)

    for source_ip, failures in failures_by_source.items():
        if len(failures) < AUTH_002_MIN_FAILURES:
            continue

        failures.sort(
            key=lambda event: event["_parsed_timestamp"]
        )

        qualifying_window: list[dict[str, Any]] | None = None

        for index, first_failure in enumerate(failures):
            window_end = (
                first_failure["_parsed_timestamp"]
                + timedelta(minutes=AUTH_002_WINDOW_MINUTES)
            )

            window_failures = [
                event
                for event in failures[index:]
                if event["_parsed_timestamp"] <= window_end
            ]

            targeted_users = {
                event["user"]
                for event in window_failures
            }

            if (
                len(window_failures) >= AUTH_002_MIN_FAILURES
                and len(targeted_users)
                >= AUTH_002_MIN_DISTINCT_USERS
            ):
                qualifying_window = window_failures
                break

        if qualifying_window is None:
            continue

        first_failure = qualifying_window[0]
        last_failure = qualifying_window[-1]

        successes = [
            event
            for event in successes_by_source.get(source_ip, [])
            if (
                first_failure["_parsed_timestamp"]
                <= event["_parsed_timestamp"]
            )
        ]


        success_event = successes[0] if successes else None

        campaign_failures = [
            event
            for event in failures
            if (
                first_failure["_parsed_timestamp"]
                <= event["_parsed_timestamp"]
                <= last_failure["_parsed_timestamp"]
            )
        ]

        alerts.append(
            build_auth_002_alert(
                source_ip=source_ip,
                host=first_failure["host"],
                threshold_events=campaign_failures,
                success_event=success_event,
            )
        )

    return alerts


# ---------------------------------------------------------------------------
# DET-ENDPOINT-001 helpers
# ---------------------------------------------------------------------------

def is_powershell_event(event: dict[str, Any]) -> bool:
    return (
        event.get("source") == "endpoint"
        and event.get("event_type") == "process_creation"
        and endpoint_process_name(event)
        in {"powershell.exe", "powershell_ise.exe"}
    )


def has_encoded_command(event: dict[str, Any]) -> bool:
    command_line = endpoint_command_line(event)
    metadata = endpoint_metadata(event)

    return (
        "-encodedcommand" in command_line
        or "-enc " in command_line
        or (
            str(metadata.get("command_type") or "").lower()
            == "encoded_command"
            and str(metadata.get("encoding") or "").lower()
            == "base64"
        )
    )


def has_suspicious_parent(event: dict[str, Any]) -> bool:
    metadata = endpoint_metadata(event)
    parent = str(metadata.get("parent_process") or "").lower()

    return parent in {
        "winword.exe",
        "excel.exe",
        "outlook.exe",
        "msaccess.exe",
        "powerpnt.exe",
    }


def has_hidden_window(event: dict[str, Any]) -> bool:
    command_line = endpoint_command_line(event)

    return (
        "-windowstyle hidden" in command_line
        or "-w hidden" in command_line
        or str(endpoint_metadata(event).get("window_style") or "").lower()
        == "hidden"
    )


def get_process_id(event: dict[str, Any]) -> str | None:
    value = endpoint_metadata(event).get("process_id")

    if value is None:
        return None

    return str(value)


def endpoint_process_name(
    event: dict[str, Any],
) -> str:
    """Return the endpoint process name."""

    process = event.get("process", "")

    if isinstance(process, dict):
        return str(process.get("name", ""))

    if isinstance(process, str):
        return process

    return ""


def endpoint_metadata(
    event: dict[str, Any],
) -> dict[str, Any]:
    """Return endpoint metadata safely."""

    metadata = event.get("metadata", {})

    if isinstance(metadata, dict):
        return metadata

    return {}


def endpoint_command_line(
    event: dict[str, Any],
) -> str:
    """Return normalized endpoint command line."""

    value = event.get("command_line", "")

    if isinstance(value, str):
        return value.lower()

    return ""


def endpoint_has_indicator(
    event: dict[str, Any],
    indicator: str,
) -> bool:
    """Check an endpoint event for a named suspicious indicator."""

    metadata = endpoint_metadata(event)
    command_line = endpoint_command_line(event)

    if indicator == "encoded_command":
        return (
            "-encodedcommand" in command_line
            or "-enc " in command_line
            or (
                str(metadata.get("command_type") or "").lower()
                == "encoded_command"
                and str(metadata.get("encoding") or "").lower()
                == "base64"
            )
        )

    if indicator == "suspicious_parent":
        parent_process = str(
            metadata.get("parent_process") or ""
        ).lower()

        return (
            metadata.get("suspicious_parent") is True
            or parent_process in {
                "winword.exe",
                "excel.exe",
                "outlook.exe",
                "powerpnt.exe",
                "msaccess.exe",
            }
        )

    if indicator == "hidden_window":
        return has_hidden_window(event)

    return False


def endpoint_event_score(
    event: dict[str, Any],
) -> tuple[int, list[str]]:
    """Calculate the suspicious PowerShell score."""

    score = 40
    indicators: list[str] = []

    if endpoint_has_indicator(event, "encoded_command"):
        score += 25
        indicators.append("encoded_command")

    metadata = endpoint_metadata(event)

    if (
        str(metadata.get("command_type") or "").lower()
        == "encoded_command"
    ):
        score += 15

    if endpoint_has_indicator(event, "suspicious_parent"):
        score += 20
        indicators.append("suspicious_parent")

    if endpoint_has_indicator(event, "hidden_window"):
        score += 15
        indicators.append("hidden_window")

    return min(score, 100), indicators

def endpoint_correlated_network_activity(
    event: dict[str, Any],
    events: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Return a network event correlated to the same PowerShell process."""

    process_id = endpoint_metadata(event).get("process_id")

    if process_id is None:
        return None

    process_id = str(process_id)

    timestamp = event["_parsed_timestamp"]
    host = event.get("host")
    user = event.get("user")

    window_end = (
        timestamp
        + timedelta(minutes=ENDPOINT_001_CORRELATION_WINDOW_MINUTES)
    )

    for candidate in events:
        if candidate["event_type"] != "network_connection":
            continue

        if candidate.get("host") != host:
            continue

        if candidate.get("user") != user:
            continue

        candidate_process_id = endpoint_metadata(candidate).get("process_id")

        if candidate_process_id is None:
            continue

        if str(candidate_process_id) != process_id:
            continue

        if not (
            timestamp
            <= candidate["_parsed_timestamp"]
            <= window_end
        ):
            continue

        return candidate

    return None


def endpoint_correlated_child_process(
    event: dict[str, Any],
    events: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Return a child process associated with the PowerShell process."""

    process_id = endpoint_metadata(event).get("process_id")

    if process_id is None:
        return None

    process_id = str(process_id)

    timestamp = event["_parsed_timestamp"]
    host = event.get("host")
    user = event.get("user")

    window_end = (
        timestamp
        + timedelta(minutes=ENDPOINT_001_CORRELATION_WINDOW_MINUTES)
    )

    for candidate in events:
        if candidate.get("event_type") != "process_creation":
            continue

        if candidate.get("host") != host:
            continue

        if candidate.get("user") != user:
            continue

        metadata = endpoint_metadata(candidate)

        if str(metadata.get("parent_pid")) != process_id:
            continue

        candidate_timestamp = candidate["_parsed_timestamp"]

        if timestamp <= candidate_timestamp <= window_end:
            return candidate

    return None

def has_correlated_network_activity(
    events: list[dict[str, Any]],
    process_event: dict[str, Any],
) -> dict[str, Any] | None:
    return endpoint_correlated_network_activity(
        process_event,
        events,
    )


def has_correlated_child_process(
    events: list[dict[str, Any]],
    process_event: dict[str, Any],
) -> dict[str, Any] | None:
    return endpoint_correlated_child_process(
        process_event,
        events,
    )


def build_endpoint_001_alert(
    process_event: dict[str, Any],
    network_event: dict[str, Any] | None,
    child_process_event: dict[str, Any] | None,
) -> dict[str, Any]:
    """Build a DET-ENDPOINT-001 alert."""

    encoded = has_encoded_command(process_event)
    suspicious_parent = has_suspicious_parent(process_event)
    hidden = has_hidden_window(process_event)

    score = 40

    if encoded:
        score += 25

    metadata = endpoint_metadata(process_event)

    if (
        str(metadata.get("command_type") or "").lower()
        == "encoded_command"
    ):
        score += 15

    if suspicious_parent:
        score += 20

    if hidden:
        score += 15

    if network_event is not None:
        score += 20

    if child_process_event is not None:
        score += 10

    score = min(score, 100)

    severity = "high" if score >= 70 else "medium"
    confidence = "high" if score >= 70 else "medium"

    supporting_event_ids = [process_event["event_id"]]

    if network_event is not None:
        supporting_event_ids.append(network_event["event_id"])

    if child_process_event is not None:
        supporting_event_ids.append(
            child_process_event["event_id"]
        )

    indicators: list[str] = []

    if encoded:
        indicators.append("encoded_command")

    if suspicious_parent:
        indicators.append("suspicious_parent")

    if hidden:
        indicators.append("hidden_window")

    if network_event is not None:
        indicators.append("correlated_network_activity")

    if child_process_event is not None:
        indicators.append("correlated_child_process")

    return {
        "alert_id": (
            f"ALERT-{process_event['event_id']}-DET-ENDPOINT-001"
        ),
        "detection_id": DETECTION_ENDPOINT_001,
        "detection_name": DETECTION_ENDPOINT_001_NAME,
        "detection_version": DETECTION_ENDPOINT_001_VERSION,
        "status": "open",
        "severity": severity,
        "confidence": confidence,
        "timestamp": process_event["timestamp"],
        "event_id": process_event["event_id"],
        "evidence_classification": {
            "observed_evidence": indicators,
            "analyst_interpretation": (
                "The endpoint event contains multiple suspicious "
                "PowerShell characteristics. The observed telemetry "
                "supports investigation but does not independently "
                "prove malicious intent."
            ),
        },
        "event_type": "process_creation",
        "host": process_event["host"],
        "user": process_event["user"],
        "process": process_event["process"],
        "process_name": endpoint_process_name(process_event),
        "process_id": metadata.get("process_id"),
        "file_path": process_event["file_path"],
        "parent_process": metadata.get("parent_process"),
        "command_line": process_event["command_line"],
        "risk_score": score,
        "indicators": indicators,
        "correlation_window_minutes": (
            ENDPOINT_001_CORRELATION_WINDOW_MINUTES
        ),
        "network_event_id": (
            network_event["event_id"]
            if network_event
            else None
        ),
        "child_process_event_id": (
            child_process_event["event_id"]
            if child_process_event
            else None
        ),
        "supporting_event_ids": supporting_event_ids,
        "rationale": (
            "Observed PowerShell execution with an encoded command "
            "and additional correlated execution indicators: "
            + ", ".join(indicators)
            + ". This is suspicious endpoint telemetry and does not "
              "independently establish malicious intent or compromise."
        ),
        "mitre_attack": {
            "tactics": [
                "execution",
                "defense_evasion",
            ],
            "techniques": [
                {
                    "id": "T1059",
                    "name": "Command and Scripting Interpreter",
                },
                {
                    "id": "T1059.001",
                    "name": "PowerShell",
                },
            ],
        },
        "analyst_interpretation": (
            "The observed process lineage and correlated endpoint "
            "activity are consistent with suspicious PowerShell "
            "execution. Analyst review should determine whether the "
            "execution was authorized and whether the decoded command, "
            "network destination, and child process were expected."
        ),
        "recommended_action": (
            "Validate the executing user and host, preserve the "
            "supporting endpoint events, review the PowerShell command "
            "and process lineage, correlate the network destination, "
            "and escalate for containment consideration if the activity "
            "is unauthorized."
        ),
    }



def detect_endpoint_001(
    events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Run DET-ENDPOINT-001 against endpoint telemetry."""

    alerts: list[dict[str, Any]] = []

    for event in events:
        if not is_powershell_event(event):
            continue

        if not has_encoded_command(event):
            continue

        network_event = has_correlated_network_activity(
            events,
            event,
        )

        child_process_event = has_correlated_child_process(
            events,
            event,
        )

        suspicious_parent = has_suspicious_parent(event)
        hidden = has_hidden_window(event)

        if not (
            suspicious_parent
            or hidden
            or network_event is not None
            or child_process_event is not None
        ):
            continue

        alerts.append(
            build_endpoint_001_alert(
                process_event=event,
                network_event=network_event,
                child_process_event=child_process_event,
            )
        )

    return alerts



def auth_003_session_id(
    event: dict[str, Any],
) -> str | None:
    """Return the normalized session ID from authentication telemetry."""

    metadata = event.get("metadata")

    if not isinstance(metadata, dict):
        return None

    value = metadata.get("session_id")

    if value is None:
        return None

    value = str(value).strip()

    return value or None


def auth_003_is_password_authentication(
    event: dict[str, Any],
) -> bool:
    """Determine whether an event represents password SSH authentication."""

    if event.get("event_type") != "authentication":
        return False

    if event.get("protocol") not in {None, "ssh"}:
        return False

    metadata = event.get("metadata")

    if isinstance(metadata, dict):
        auth_method = str(
            metadata.get("auth_method") or ""
        ).lower()

        if auth_method and auth_method != "password":
            return False

    return True


def auth_003_is_failed_authentication(
    event: dict[str, Any],
) -> bool:
    """Return True for DET-AUTH-003 failed password authentication."""

    return (
        auth_003_is_password_authentication(event)
        and event.get("status") in VALID_FAILURE_STATUSES
        and event.get("action") in VALID_FAILURE_ACTIONS
    )


def auth_003_is_successful_authentication(
    event: dict[str, Any],
) -> bool:
    """Identify successful password authentication events."""

    return (
        auth_003_is_password_authentication(event)
        and event.get("status") in SUCCESS_STATUSES
        and event.get("action") in SUCCESS_ACTIONS
    )


def auth_003_has_privileged_indicator(
    event: dict[str, Any],
) -> str | None:
    """Return a recognized privileged activity indicator."""

    if event.get("event_type") != "command_execution":
        return None

    command_line = str(
        event.get("command_line") or ""
    ).strip().lower()

    if command_line == "sudo -l":
        return "sudo -l"

    if command_line == "id":
        return "id"

    return None


def build_auth_003_alert(
    successful_authentication: dict[str, Any],
    failed_events: list[dict[str, Any]],
    session_start: dict[str, Any],
    command_events: list[dict[str, Any]],
    privileged_indicators: list[str],
) -> dict[str, Any]:
    """Build a DET-AUTH-003 alert."""

    supporting_events = (
        failed_events
        + [successful_authentication, session_start]
        + command_events
    )

    supporting_event_ids = [
        event["event_id"]
        for event in supporting_events
    ]

    first_seen = min(
        event["_parsed_timestamp"]
        for event in supporting_events
    )

    last_seen = max(
        event["_parsed_timestamp"]
        for event in supporting_events
    )

    return {
        "alert_id": "ALERT-CASE-004-DET-AUTH-003",
        "detection_id": DETECTION_AUTH_003,
        "detection_name": DETECTION_AUTH_003_NAME,
        "detection_version": DETECTION_AUTH_003_VERSION,
        "status": "open",
        "severity": "high",
        "confidence": "high",
        "evidence_classification": "observed_evidence",
        "event_type": "authentication_sequence",
        "source_ip": successful_authentication["source_ip"],
        "host": successful_authentication["host"],
        "user": successful_authentication["user"],
        "failed_authentication_count": len(failed_events),
        "successful_authentication_event_id": (
            successful_authentication["event_id"]
        ),
        "session_start_event_id": session_start["event_id"],
        "post_authentication_command_count": len(command_events),
        "privileged_activity_indicators": privileged_indicators,
        "session_id": auth_003_session_id(
            successful_authentication
        ),
        "correlation_window_minutes": AUTH_003_WINDOW_MINUTES,
        "first_seen": first_seen.isoformat(),
        "last_seen": last_seen.isoformat(),
        "supporting_event_ids": supporting_event_ids,
        "rationale": (
            f"Observed {len(failed_events)} failed password "
            "authentication attempts against the same account and "
            "source IP, followed by successful authentication, a "
            "correlated session start, and "
            f"{len(command_events)} post-authentication command events. "
            "Privileged activity indicators observed: "
            + ", ".join(privileged_indicators)
            + "."
        ),
        "analyst_interpretation": (
            "The telemetry shows a suspicious authentication-to-session "
            "sequence involving a privileged account and subsequent "
            "enumeration activity. This is observed evidence of a "
            "suspicious sequence and does not independently prove "
            "account compromise or malicious intent."
        ),
        "recommended_action": (
            "Verify whether the authentication was authorized, "
            "confirm ownership of the source IP and account, review "
            "the complete session activity, correlate identity and "
            "endpoint telemetry, and escalate for containment "
            "consideration if unauthorized access is confirmed."
        ),
        "mitre_attack": {
            "tactics": [
                "credential_access",
                "persistence",
                "discovery",
                "privilege_escalation",
            ],
            "techniques": [
                {
                    "technique": "T1110",
                    "name": "Brute Force",
                },
                {
                    "technique": "T1078",
                    "name": "Valid Accounts",
                },
                {
                    "technique": "T1087",
                    "name": "Account Discovery",
                },
                {
                    "technique": "T1069.001",
                    "name": "Permission Groups Discovery: Local",
                },
                {
                    "technique": "T1059.004",
                    "name": "Unix Shell",
                },
            ],
        },
    }


def detect_auth_003(
    events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Run DET-AUTH-003 against authentication/session telemetry."""

    alerts: list[dict[str, Any]] = []

    for successful_authentication in events:
        if not auth_003_is_successful_authentication(
            successful_authentication
        ):
            continue

        source_ip = successful_authentication.get("source_ip")
        user = successful_authentication.get("user")
        timestamp = successful_authentication["_parsed_timestamp"]

        window_start = timestamp - timedelta(
            minutes=AUTH_003_WINDOW_MINUTES
        )
        window_end = timestamp + timedelta(
            minutes=AUTH_003_WINDOW_MINUTES
        )

        failed_events = [
            event
            for event in events
            if (
                auth_003_is_failed_authentication(event)
                and event.get("source_ip") == source_ip
                and event.get("user") == user
                and window_start
                <= event["_parsed_timestamp"]
                <= timestamp
            )
        ]

        if len(failed_events) < AUTH_003_MIN_FAILURES:
            continue

        session_id = auth_003_session_id(
            successful_authentication
        )

        if session_id is None:
            continue

        session_start = None

        for event in events:
            if event.get("event_type") != "session_start":
                continue

            if event.get("source_ip") != source_ip:
                continue

            if event.get("user") != user:
                continue

            if auth_003_session_id(event) != session_id:
                continue

            if not (
                timestamp
                <= event["_parsed_timestamp"]
                <= window_end
            ):
                continue

            session_start = event
            break

        if session_start is None:
            continue

        command_events = [
            event
            for event in events
            if (
                event.get("event_type") == "command_execution"
                and event.get("source_ip") == source_ip
                and event.get("user") == user
                and auth_003_session_id(event) == session_id
                and timestamp
                <= event["_parsed_timestamp"]
                <= window_end
            )
        ]

        if len(command_events) < AUTH_003_MIN_COMMANDS:
            continue

        privileged_indicators = []

        for event in command_events:
            indicator = auth_003_has_privileged_indicator(event)

            if (
                indicator is not None
                and indicator not in privileged_indicators
            ):
                privileged_indicators.append(indicator)

        if not privileged_indicators:
            continue

        alerts.append(
            build_auth_003_alert(
                successful_authentication=successful_authentication,
                failed_events=failed_events,
                session_start=session_start,
                command_events=command_events,
                privileged_indicators=privileged_indicators,
            )
        )

    return alerts


# ---------------------------------------------------------------------------
# DET-NET-001 helpers
# ---------------------------------------------------------------------------

def network_source_field(
    event: dict[str, Any],
    field: str,
) -> str:
    """Return a source field from network telemetry."""

    source = event.get("source", {})

    if not isinstance(source, dict):
        return ""

    value = source.get(field, "")

    if value is None:
        return ""

    return str(value)


def network_destination_field(
    event: dict[str, Any],
    field: str,
) -> Any:
    """Return a destination field from network telemetry."""

    destination = event.get("destination", {})

    if not isinstance(destination, dict):
        return None

    return destination.get(field)


def network_metadata(
    event: dict[str, Any],
) -> dict[str, Any]:
    """Return network metadata safely."""

    metadata = event.get("metadata", {})

    if isinstance(metadata, dict):
        return metadata

    return {}


def network_connection_events(
    events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return outbound successful network connections."""

    return [
        event
        for event in events
        if (
            event["event_type"] == "network_connection"
            and event["direction"] == "outbound"
            and event["status"] == "success"
        )
    ]


def network_group_key(
    event: dict[str, Any],
) -> tuple[str, str, str, str, int]:
    """Build the DET-NET-001 correlation key."""

    destination_ip = network_destination_field(
        event,
        "ip",
    )

    destination_port = network_destination_field(
        event,
        "port",
    )

    try:
        destination_port = int(destination_port)
    except (TypeError, ValueError):
        destination_port = 0

    return (
        network_source_field(event, "host"),
        network_source_field(event, "process_name"),
        network_source_field(event, "process_path"),
        str(destination_ip or ""),
        destination_port,
    )


def calculate_intervals(
    events: list[dict[str, Any]],
) -> list[float]:
    """Calculate intervals between ordered network connections."""

    ordered = sorted(
        events,
        key=lambda event: event["_parsed_timestamp"],
    )

    intervals: list[float] = []

    for previous, current in zip(
        ordered,
        ordered[1:],
    ):
        interval = (
            current["_parsed_timestamp"]
            - previous["_parsed_timestamp"]
        ).total_seconds()

        intervals.append(interval)

    return intervals


def calculate_beacon_regularity(
    intervals: list[float],
) -> tuple[float, float]:
    """
    Return regularity ratio and average interval.

    Regularity ratio is the percentage of observed intervals
    within the expected beacon interval tolerance.
    """

    if not intervals:
        return 0.0, 0.0

    matching = sum(
        1
        for interval in intervals
        if abs(
            interval - NET_001_EXPECTED_INTERVAL_SECONDS
        )
        <= NET_001_INTERVAL_TOLERANCE_SECONDS
    )

    regularity_ratio = matching / len(intervals)
    average_interval = sum(intervals) / len(intervals)

    return regularity_ratio, average_interval


def network_process_is_unsigned(
    event: dict[str, Any],
) -> bool:
    """Return True when process metadata identifies an unsigned binary."""

    metadata = network_metadata(event)

    return metadata.get("signed") is False


def network_process_is_user_writable(
    event: dict[str, Any],
) -> bool:
    """Return True when the process path is user-writable."""

    process_path = network_source_field(
        event,
        "process_path",
    ).lower()

    return (
        "\\users\\public\\" in process_path
        or "/tmp/" in process_path
        or "/var/tmp/" in process_path
    )


def network_process_name_is_suspicious(
    event: dict[str, Any],
) -> bool:
    """Return True for known suspicious process naming."""

    process_name = network_source_field(
        event,
        "process_name",
    ).lower()

    return process_name in {
        "svchost_update.exe",
    }


def network_uses_non_standard_port(
    event: dict[str, Any],
) -> bool:
    """Return True for the DET-NET-001 suspicious port."""

    destination_port = network_destination_field(
        event,
        "port",
    )

    try:
        destination_port = int(destination_port)
    except (TypeError, ValueError):
        return False

    return destination_port == 8443


def build_net_001_alert(
    beacon_events: list[dict[str, Any]],
    correlation_event: dict[str, Any] | None,
    regularity_ratio: float,
    average_interval: float,
    indicators: list[str],
    risk_score: int,
) -> dict[str, Any]:
    """Build a deterministic DET-NET-001 alert."""

    first_event = beacon_events[0]
    last_event = beacon_events[-1]

    severity = (
        "high"
        if risk_score >= 70
        else "medium"
    )

    supporting_ids = [
        event["event_id"]
        for event in beacon_events
    ]

    if correlation_event is not None:
        supporting_ids.append(
            correlation_event["event_id"]
        )

    return {
        "alert_id": (
            f"ALERT-CASE-005-{DETECTION_NET_001}"
        ),
        "detection_id": DETECTION_NET_001,
        "detection_name": DETECTION_NET_001_NAME,
        "detection_version": DETECTION_NET_001_VERSION,
        "severity": severity,
        "confidence": (
            "high"
            if risk_score >= 70
            else "medium"
        ),
        "status": "open",
        "timestamp": last_event["timestamp"],
        "host": network_source_field(
            first_event,
            "host",
        ),
        "source_ip": network_source_field(
            first_event,
            "ip",
        ),
        "process_name": network_source_field(
            first_event,
            "process_name",
        ),
        "process_path": network_source_field(
            first_event,
            "process_path",
        ),
        "destination_ip": network_destination_field(
            first_event,
            "ip",
        ),
        "destination_port": network_destination_field(
            first_event,
            "port",
        ),
        "destination_domain": network_destination_field(
            first_event,
            "domain",
        ),
        "connection_count": len(beacon_events),
        "first_connection": first_event["timestamp"],
        "last_connection": last_event["timestamp"],
        "average_interval_seconds": round(
            average_interval,
            2,
        ),
        "regularity_ratio": round(
            regularity_ratio,
            2,
        ),
        "risk_score": risk_score,
        "indicators": indicators,
        "correlation_event_id": (
            correlation_event["event_id"]
            if correlation_event is not None
            else None
        ),
        "supporting_event_ids": supporting_ids,
        "evidence_classification": {
            "observed_evidence": [
                f"{len(beacon_events)} repeated outbound connections",
                (
                    "approximately "
                    f"{round(average_interval, 2)}-second average interval"
                ),
                (
                    f"{round(regularity_ratio * 100, 1)}% "
                    "interval regularity"
                ),
                "suspicious process characteristics",
            ],
            "analyst_interpretation": (
                "The observed network pattern is consistent with "
                "automated C2 beaconing. Process and connection "
                "characteristics increase suspicion, but network "
                "beaconing alone does not establish compromise."
            ),
        },
        "mitre_attack": {
            "tactics": [
                "command_and_control",
            ],
            "techniques": [
                {
                    "id": "T1071",
                    "name": "Application Layer Protocol",
                },
                {
                    "id": "T1071.001",
                    "name": "Web Protocols",
                },
                {
                    "id": "T1573",
                    "name": "Encrypted Channel",
                },
            ],
        },
        "rationale": (
            "Repeated outbound connections from the same process "
            "to the same destination occurred at a regular interval "
            "and correlated with suspicious process characteristics."
        ),
    }


def detect_net_001(
    events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Detect suspicious C2 beaconing activity."""

    alerts: list[dict[str, Any]] = []

    connections = network_connection_events(events)

    grouped: defaultdict[
        tuple[str, str, str, str, int],
        list[dict[str, Any]],
    ] = defaultdict(list)

    for event in connections:
        grouped[
            network_group_key(event)
        ].append(event)

    for key, group in grouped.items():
        ordered = sorted(
            group,
            key=lambda event: event["_parsed_timestamp"],
        )

        if len(ordered) < NET_001_MIN_CONNECTIONS:
            continue

        for start_index, start_event in enumerate(ordered):
            window_end = (
                start_event["_parsed_timestamp"]
                + timedelta(minutes=NET_001_WINDOW_MINUTES)
            )

            window_events = [
                event
                for event in ordered[start_index:]
                if event["_parsed_timestamp"] <= window_end
            ]

            if len(window_events) < NET_001_MIN_CONNECTIONS:
                continue

            intervals = calculate_intervals(window_events)

            if not intervals:
                continue

            regularity_ratio, average_interval = (
                calculate_beacon_regularity(intervals)
            )

            if regularity_ratio < NET_001_MIN_REGULARITY_RATIO:
                continue

            first_event = window_events[0]

            indicators = [
                "repeated_connections",
                "regular_beacon_interval",
            ]

            risk_score = 20

            risk_score += 20
            risk_score += 20

            if network_uses_non_standard_port(first_event):
                indicators.append(
                    "non_standard_destination_port"
                )
                risk_score += 10

            if network_process_is_unsigned(first_event):
                indicators.append(
                    "unsigned_process"
                )
                risk_score += 15

            if network_process_is_user_writable(first_event):
                indicators.append(
                    "user_writable_path"
                )
                risk_score += 10

            if network_process_name_is_suspicious(first_event):
                indicators.append(
                    "suspicious_process_name"
                )
                risk_score += 10

            correlation_event = None

            for candidate in events:
                if candidate["event_type"] != (
                    "process_network_correlation"
                ):
                    continue

                if network_group_key(candidate) != key:
                    continue

                metadata = network_metadata(candidate)

                try:
                    connection_count = int(
                        metadata.get(
                            "connection_count",
                            0,
                        )
                    )
                except (TypeError, ValueError):
                    connection_count = 0

                if connection_count < NET_001_MIN_CONNECTIONS:
                    continue

                correlation_event = candidate
                break

            if correlation_event is not None:
                indicators.append(
                    "process_network_correlation"
                )
                risk_score += 15

            risk_score = min(
                risk_score,
                100,
            )

            if risk_score < 70:
                continue

            alerts.append(
                build_net_001_alert(
                    window_events,
                    correlation_event,
                    regularity_ratio,
                    average_interval,
                    indicators,
                    risk_score,
                )
            )

            break

    return alerts



# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------

def remove_internal_fields(
    event: dict[str, Any],
) -> dict[str, Any]:
    """Remove internal processing fields before serialization."""

    return {
        key: value
        for key, value in event.items()
        if not key.startswith("_")
    }


def write_alerts(
    alerts: list[dict[str, Any]],
    output_path: Path,
) -> None:
    """Write detection results as a deterministic JSON document."""

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    detection_id = (
        alerts[0]["detection_id"]
        if alerts
        else "NONE"
    )

    clean_alerts = [
        remove_internal_fields(alert)
        for alert in alerts
    ]

    document = {
        "schema_version": "1.0",
        "generated_by": "CYBERNOVA SOC Detection Engine",
        "detection_id": detection_id,
        "alert_count": len(clean_alerts),
        "alerts": clean_alerts,
    }

    with output_path.open(
        "w",
        encoding="utf-8",
    ) as handle:
        json.dump(
            document,
            handle,
            indent=2,
            sort_keys=False,
        )
        handle.write("\n")


# ---------------------------------------------------------------------------
# Detection dispatcher
# ---------------------------------------------------------------------------

def run_detection(
    detection_id: str,
    events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Dispatch telemetry to the requested detection."""

    if detection_id == DETECTION_AUTH_001:
        return detect_auth_001(events)

    if detection_id == DETECTION_AUTH_002:
        return detect_auth_002(events)

    if detection_id == DETECTION_AUTH_003:
        return detect_auth_003(events)

    if detection_id == DETECTION_ENDPOINT_001:
        return detect_endpoint_001(events)

    if detection_id == DETECTION_NET_001:
        return detect_net_001(events)

    raise ValueError(
        f"unsupported detection: {detection_id}"
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser(
        description=(
            "CYBERNOVA SOC Operations Lab Detection Engine"
        )
    )

    parser.add_argument(
        "--detection",
        required=True,
        choices=(
            DETECTION_AUTH_001,
            DETECTION_AUTH_002,
            DETECTION_AUTH_003,
            DETECTION_ENDPOINT_001,
            DETECTION_NET_001,
        ),
        help="Detection rule to execute.",
    )

    parser.add_argument(
        "--telemetry",
        "--input",
        dest="telemetry",
        required=True,
        type=Path,
        help="Path to normalized JSONL telemetry.",
    )

    parser.add_argument(
        "--output",
        type=Path,
        help="Optional path for JSON alert output.",
    )

    return parser.parse_args()


def main() -> int:
    """CLI entry point."""

    args = parse_args()

    try:
        events = load_jsonl(
            args.telemetry
        )

        alerts = run_detection(
            args.detection,
            events,
        )

    except (
        FileNotFoundError,
        OSError,
        TelemetryValidationError,
        ValueError,
    ) as exc:
        print(
            f"ERROR: {exc}",
            file=sys.stderr,
        )
        return 1

    if args.output:
        write_alerts(
            alerts=alerts,
            output_path=args.output,
        )

    print(
        f"Detection: {args.detection}"
    )
    print(
        f"Telemetry events: {len(events)}"
    )
    print(
        f"Alerts generated: {len(alerts)}"
    )

    for alert in alerts:
        print(
            f"Alert ID: {alert['alert_id']}"
        )
        print(
            f"Severity: {alert['severity']}"
        )
        print(
            f"Confidence: {alert['confidence']}"
        )

        if args.detection == DETECTION_NET_001:
            print(
                f"Host: {alert['host']}"
            )
            print(
                f"Process: {alert['process_name']}"
            )
            print(
                "Destination: "
                f"{alert['destination_ip']}:"
                f"{alert['destination_port']}"
            )
            print(
                "Connections: "
                f"{alert['connection_count']}"
            )
            print(
                "Average interval: "
                f"{alert['average_interval_seconds']} seconds"
            )
            print(
                "Risk score: "
                f"{alert['risk_score']}"
            )

        elif args.detection == DETECTION_AUTH_001:
            print(
                f"Source IP: {alert['source_ip']}"
            )
            print(
                f"User: {alert['user']}"
            )
            print(
                "Failed attempts: "
                f"{alert['failed_attempt_count']}"
            )
            print(
                "Successful authentication observed: "
                f"{alert['successful_authentication_observed']}"
            )

        elif args.detection == DETECTION_AUTH_002:
            print(
                f"Source IP: {alert['source_ip']}"
            )
            print(
                f"Host: {alert['host']}"
            )
            print(
                "Distinct users: "
                f"{alert['targeted_user_count']}"
            )
            print(
                "Failed attempts: "
                f"{alert['failed_attempt_count']}"
            )
            print(
                "Successful authentication observed: "
                f"{alert['successful_authentication_observed']}"
            )

        elif args.detection == DETECTION_AUTH_003:
            print(
                f"Source IP: {alert['source_ip']}"
            )
            print(
                f"User: {alert['user']}"
            )
            print(
                f"Host: {alert['host']}"
            )
            print(
                "Failed attempts: "
                f"{alert['failed_authentication_count']}"
            )
            print(
                "Post-authentication commands: "
                f"{alert['post_authentication_command_count']}"
            )

        elif args.detection == DETECTION_ENDPOINT_001:
            print(
                f"Host: {alert['host']}"
            )
            print(
                f"User: {alert['user']}"
            )
            print(
                f"Process: {alert['process_name']}"
            )
            print(
                "Risk score: "
                f"{alert['risk_score']}"
            )
            print(
                "Indicators: "
                + ", ".join(alert["indicators"])
            )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
