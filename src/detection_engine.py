#!/usr/bin/env python3
"""
CYBERNOVA SOC Operations Lab
Detection Engine

Implemented detections:
    DET-AUTH-001 - SSH Brute-Force Authentication Detection
    DET-AUTH-002 - Password Spraying Authentication Detection
    DET-AUTH-003 - Suspicious Post-Authentication Privileged Session
    DET-ENDPOINT-001 - Suspicious PowerShell Execution

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


class TelemetryValidationError(ValueError):
    """Raised when telemetry does not meet the expected schema."""


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

            event_id = event["event_id"]

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

    if event["event_type"] == "authentication":
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

    if event["source"] == "endpoint":
        missing = ENDPOINT_REQUIRED_FIELDS - set(event)

        if missing:
            missing_fields = ", ".join(sorted(missing))
            raise TelemetryValidationError(
                f"line {line_number}: missing endpoint fields: "
                f"{missing_fields}"
            )

        if event["event_type"] not in {
            "process_creation",
            "network_connection",
        }:
            raise TelemetryValidationError(
                f"line {line_number}: unsupported endpoint event_type: "
                f"{event['event_type']}"
            )

        if not isinstance(event["metadata"], dict):
            raise TelemetryValidationError(
                f"line {line_number}: endpoint metadata must be an object"
            )


def is_ssh_authentication_event(
    event: dict[str, Any],
) -> bool:
    """Return True when an event represents SSH authentication."""

    protocol = str(
        event.get("protocol") or ""
    ).lower()

    port = event.get("port")

    return (
        event.get("event_type") == "authentication"
        and (
            protocol == "ssh"
            or port == 22
        )
    )


def is_failure(event: dict[str, Any]) -> bool:
    """Identify failed SSH authentication events."""

    return (
        is_ssh_authentication_event(event)
        and str(
            event.get("status", "")
        ).lower() in VALID_FAILURE_STATUSES
        and str(
            event.get("action", "")
        ).lower() in VALID_FAILURE_ACTIONS
    )


def is_success(event: dict[str, Any]) -> bool:
    """Identify successful SSH authentication events."""

    return (
        is_ssh_authentication_event(event)
        and str(
            event.get("status", "")
        ).lower() in SUCCESS_STATUSES
        and str(
            event.get("action", "")
        ).lower() in SUCCESS_ACTIONS
    )


def is_password_authentication(
    event: dict[str, Any],
) -> bool:
    """Identify password-based authentication."""

    metadata = event.get("metadata")

    if not isinstance(metadata, dict):
        return False

    method = str(
        metadata.get("authentication_method") or ""
    ).lower()

    return method == "password"


# ---------------------------------------------------------------------------
# DET-AUTH-001
# ---------------------------------------------------------------------------


def find_threshold_window(
    failures: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]] | None, datetime | None]:
    """
    Find the first five-minute window containing at least five failures.

    Events are already sorted chronologically.
    """

    window = timedelta(
        minutes=AUTH_001_WINDOW_MINUTES
    )

    for index, first_event in enumerate(failures):
        first_time = first_event["_parsed_timestamp"]
        matching: list[dict[str, Any]] = []

        for candidate in failures[index:]:
            candidate_time = candidate["_parsed_timestamp"]

            if candidate_time - first_time <= window:
                matching.append(candidate)
            else:
                break

        if len(matching) >= AUTH_001_FAILURE_THRESHOLD:
            return matching, first_time

    return None, None


def find_success_after_threshold(
    events: list[dict[str, Any]],
    source_ip: str,
    user: str,
    threshold_time: datetime,
) -> dict[str, Any] | None:
    """Find a successful SSH authentication after the threshold."""

    for event in events:
        if (
            is_success(event)
            and event.get("source_ip") == source_ip
            and event.get("user") == user
            and event["_parsed_timestamp"] >= threshold_time
        ):
            return event

    return None


def build_auth_001_alert(
    source_ip: str,
    user: str,
    host: str,
    threshold_events: list[dict[str, Any]],
    success_event: dict[str, Any] | None,
) -> dict[str, Any]:
    """Build a DET-AUTH-001 alert."""

    first_event = threshold_events[0]
    last_event = threshold_events[-1]

    escalated = success_event is not None

    supporting_event_ids = [
        event["event_id"]
        for event in threshold_events
    ]

    if success_event is not None:
        supporting_event_ids.append(
            success_event["event_id"]
        )

    severity = "high" if escalated else "medium"

    if escalated:
        rationale = (
            f"Observed {len(threshold_events)} failed SSH "
            f"authentication attempts for user '{user}' from "
            f"{source_ip} within {AUTH_001_WINDOW_MINUTES} minutes, "
            "followed by a successful SSH authentication. The "
            "successful authentication is an observed event and "
            "does not independently prove account compromise."
        )
    else:
        rationale = (
            f"Observed {len(threshold_events)} failed SSH "
            f"authentication attempts for user '{user}' from "
            f"{source_ip} within {AUTH_001_WINDOW_MINUTES} minutes. "
            "No subsequent successful SSH authentication was "
            "observed in the supplied telemetry."
        )

    return {
        "alert_id": "ALERT-CASE-001-DET-AUTH-001",
        "detection_id": DETECTION_AUTH_001,
        "detection_name": DETECTION_AUTH_001_NAME,
        "detection_version": DETECTION_AUTH_001_VERSION,
        "status": "open",
        "severity": severity,
        "confidence": "high",
        "evidence_classification": "observed_evidence",
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
        "successful_authentication_observed": (
            success_event is not None
        ),
        "successful_authentication_event_id": (
            success_event["event_id"]
            if success_event
            else None
        ),
        "supporting_event_ids": supporting_event_ids,
        "rationale": rationale,
        "mitre_attack": {
            "tactic": "credential-access",
            "technique": "T1110",
            "subtechnique": "T1110.001",
        },
        "analyst_interpretation": (
            "The telemetry is consistent with an SSH brute-force "
            "authentication pattern. If the subsequent successful "
            "authentication is unexpected, additional identity, "
            "endpoint, and network evidence should be collected "
            "before determining whether the account was compromised."
        ),
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
    """Run DET-AUTH-001 against authentication telemetry."""

    grouped_failures: dict[
        tuple[str, str],
        list[dict[str, Any]],
    ] = defaultdict(list)

    for event in events:
        if is_failure(event):
            key = (
                str(event["source_ip"]),
                str(event["user"]),
            )
            grouped_failures[key].append(event)

    alerts: list[dict[str, Any]] = []

    for (
        source_ip,
        user,
    ), failures in sorted(grouped_failures.items()):

        threshold_events, threshold_time = (
            find_threshold_window(failures)
        )

        if (
            threshold_events is None
            or threshold_time is None
        ):
            continue

        host = str(
            threshold_events[0]["host"]
        )

        success_event = find_success_after_threshold(
            events=events,
            source_ip=source_ip,
            user=user,
            threshold_time=threshold_time,
        )

        alerts.append(
            build_auth_001_alert(
                source_ip=source_ip,
                user=user,
                host=host,
                threshold_events=threshold_events,
                success_event=success_event,
            )
        )

    return alerts


# ---------------------------------------------------------------------------
# DET-AUTH-002
# ---------------------------------------------------------------------------


def find_password_spray_window(
    failures: list[dict[str, Any]],
) -> tuple[
    list[dict[str, Any]] | None,
    datetime | None,
]:
    """
    Find the first five-minute window satisfying the password-spraying
    thresholds.

    Requirements:
        - at least 6 failed password authentications
        - at least 6 distinct users
    """

    window = timedelta(
        minutes=AUTH_002_WINDOW_MINUTES
    )

    for index, first_event in enumerate(failures):
        first_time = first_event["_parsed_timestamp"]
        matching: list[dict[str, Any]] = []

        for candidate in failures[index:]:
            candidate_time = candidate["_parsed_timestamp"]

            if candidate_time - first_time <= window:
                matching.append(candidate)
            else:
                break

        distinct_users = {
            str(event["user"])
            for event in matching
        }

        if (
            len(matching) >= AUTH_002_MIN_FAILURES
            and len(distinct_users)
            >= AUTH_002_MIN_DISTINCT_USERS
        ):
            return matching, first_time

    return None, None


def find_success_from_source(
    events: list[dict[str, Any]],
    source_ip: str,
    threshold_time: datetime,
) -> dict[str, Any] | None:
    """
    Find the first successful SSH authentication from the spraying
    source at or after the detected threshold.
    """

    for event in events:
        if (
            is_success(event)
            and event.get("source_ip") == source_ip
            and event["_parsed_timestamp"] >= threshold_time
        ):
            return event

    return None


def build_auth_002_alert(
    source_ip: str,
    host: str,
    threshold_events: list[dict[str, Any]],
    success_event: dict[str, Any] | None,
) -> dict[str, Any]:
    """Build a DET-AUTH-002 password-spraying alert."""

    first_event = threshold_events[0]
    last_event = threshold_events[-1]

    distinct_users = sorted(
        {
            str(event["user"])
            for event in threshold_events
        }
    )

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
    confidence = "high" if escalated else "medium"

    if escalated:
        rationale = (
            f"Observed {len(threshold_events)} failed password "
            f"SSH authentication attempts from {source_ip} "
            f"against {len(distinct_users)} distinct users within "
            f"{AUTH_002_WINDOW_MINUTES} minutes, followed by a "
            f"successful SSH authentication for user "
            f"'{success_event['user']}'. The success is observed "
            "telemetry and does not independently prove account "
            "compromise."
        )
    else:
        rationale = (
            f"Observed {len(threshold_events)} failed password "
            f"SSH authentication attempts from {source_ip} "
            f"against {len(distinct_users)} distinct users within "
            f"{AUTH_002_WINDOW_MINUTES} minutes. No successful "
            "SSH authentication from the same source was observed "
            "after the detection threshold in the supplied telemetry."
        )

    return {
        "alert_id": "ALERT-CASE-002-DET-AUTH-002",
        "detection_id": DETECTION_AUTH_002,
        "detection_name": DETECTION_AUTH_002_NAME,
        "detection_version": DETECTION_AUTH_002_VERSION,
        "status": "open",
        "severity": severity,
        "confidence": confidence,
        "evidence_classification": "observed_evidence",
        "event_type": "authentication",
        "protocol": "ssh",
        "host": host,
        "source_ip": source_ip,
        "targeted_user_count": len(distinct_users),
        "targeted_users": distinct_users,
        "failed_attempt_count": len(threshold_events),
        "authentication_method": "password",
        "threshold": {
            "minimum_failed_attempts": AUTH_002_MIN_FAILURES,
            "minimum_distinct_users": AUTH_002_MIN_DISTINCT_USERS,
            "window_minutes": AUTH_002_WINDOW_MINUTES,
        },
        "first_seen": first_event["timestamp"],
        "last_seen": last_event["timestamp"],
        "successful_authentication_observed": (
            success_event is not None
        ),
        "successful_authentication_event_id": (
            success_event["event_id"]
            if success_event
            else None
        ),
        "successful_authentication_user": (
            success_event["user"]
            if success_event
            else None
        ),
        "supporting_event_ids": supporting_event_ids,
        "rationale": rationale,
        "mitre_attack": {
            "tactic": "credential-access",
            "technique": "T1110",
            "subtechnique": "T1110.003",
            "name": "Password Spraying",
        },
        "analyst_interpretation": (
            "The telemetry is consistent with a password-spraying "
            "authentication pattern because one source attempted "
            "password authentication against multiple distinct "
            "accounts within a short time window. The observed "
            "successful authentication increases investigation "
            "priority but does not independently establish account "
            "compromise."
        ),
        "recommended_action": (
            "Validate whether the source and authentication activity "
            "were authorized. Review identity, endpoint, and network "
            "telemetry for the targeted account, preserve the "
            "supporting events, and investigate the successful "
            "authentication for user "
            f"'{success_event['user'] if success_event else 'N/A'}'."
        ),
    }


def detect_auth_002(
    events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Run DET-AUTH-002 against authentication telemetry."""

    grouped_failures: dict[
        str,
        list[dict[str, Any]],
    ] = defaultdict(list)

    for event in events:
        if (
            is_failure(event)
            and is_password_authentication(event)
        ):
            source_ip = str(
                event["source_ip"]
            )
            grouped_failures[source_ip].append(event)

    alerts: list[dict[str, Any]] = []

    for source_ip, failures in sorted(
        grouped_failures.items()
    ):
        threshold_events, threshold_time = (
            find_password_spray_window(failures)
        )

        if (
            threshold_events is None
            or threshold_time is None
        ):
            continue

        host = str(
            threshold_events[0]["host"]
        )

        success_event = find_success_from_source(
            events=events,
            source_ip=source_ip,
            threshold_time=threshold_time,
        )

        alerts.append(
            build_auth_002_alert(
                source_ip=source_ip,
                host=host,
                threshold_events=threshold_events,
                success_event=success_event,
            )
        )

    return alerts


# ---------------------------------------------------------------------------
# DET-ENDPOINT-001
# ---------------------------------------------------------------------------


def endpoint_process_name(event: dict[str, Any]) -> str:
    """Return a normalized endpoint process name."""

    return str(event.get("process") or "").lower()


def endpoint_command_line(event: dict[str, Any]) -> str:
    """Return a normalized endpoint command line."""

    return str(event.get("command_line") or "").lower()


def endpoint_metadata(event: dict[str, Any]) -> dict[str, Any]:
    """Return endpoint metadata when it is a dictionary."""

    metadata = event.get("metadata")
    return metadata if isinstance(metadata, dict) else {}


def is_powershell_event(event: dict[str, Any]) -> bool:
    """Identify PowerShell process creation events."""

    return (
        event.get("source") == "endpoint"
        and event.get("event_type") == "process_creation"
        and endpoint_process_name(event)
        in {"powershell.exe", "powershell_ise.exe"}
    )


def has_encoded_command(event: dict[str, Any]) -> bool:
    """Identify encoded PowerShell command indicators."""

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
    """Identify suspicious Office parent processes."""

    metadata = endpoint_metadata(event)
    parent = str(
        metadata.get("parent_process") or ""
    ).lower()

    return parent in {
        "winword.exe",
        "excel.exe",
        "outlook.exe",
        "msaccess.exe",
        "powerpnt.exe",
    }


def has_hidden_window(event: dict[str, Any]) -> bool:
    """Identify hidden PowerShell execution."""

    command_line = endpoint_command_line(event)

    return (
        "-windowstyle hidden" in command_line
        or "-w hidden" in command_line
        or str(
            endpoint_metadata(event).get("window_style") or ""
        ).lower() == "hidden"
    )


def get_process_id(event: dict[str, Any]) -> str | None:
    """Return the endpoint process ID as a normalized string."""

    value = endpoint_metadata(event).get("process_id")

    if value is None:
        return None

    return str(value)


def has_correlated_network_activity(
    events: list[dict[str, Any]],
    process_event: dict[str, Any],
) -> dict[str, Any] | None:
    """Find network activity associated with the PowerShell process."""

    process_id = get_process_id(process_event)

    if process_id is None:
        return None

    start = process_event["_parsed_timestamp"]
    end = start + timedelta(
        minutes=ENDPOINT_001_CORRELATION_WINDOW_MINUTES
    )

    for event in events:
        if event.get("event_type") != "network_connection":
            continue

        if event.get("host") != process_event.get("host"):
            continue

        if event.get("user") != process_event.get("user"):
            continue

        if get_process_id(event) != process_id:
            continue

        timestamp = event["_parsed_timestamp"]

        if start <= timestamp <= end:
            return event

    return None


def has_correlated_child_process(
    events: list[dict[str, Any]],
    process_event: dict[str, Any],
) -> dict[str, Any] | None:
    """Find a child process associated with the PowerShell process."""

    process_id = get_process_id(process_event)

    if process_id is None:
        return None

    start = process_event["_parsed_timestamp"]
    end = start + timedelta(
        minutes=ENDPOINT_001_CORRELATION_WINDOW_MINUTES
    )

    for event in events:
        if event.get("event_type") != "process_creation":
            continue

        if event.get("host") != process_event.get("host"):
            continue

        if event.get("user") != process_event.get("user"):
            continue

        metadata = endpoint_metadata(event)

        if str(metadata.get("parent_pid")) != process_id:
            continue

        timestamp = event["_parsed_timestamp"]

        if start <= timestamp <= end:
            return event

    return None


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
        "evidence_classification": "observed_evidence",
        "event_type": "process_creation",
        "host": process_event["host"],
        "user": process_event["user"],
        "process": process_event["process"],
        "process_id": metadata.get("process_id"),
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
            "tactic": "execution",
            "technique": "T1059",
            "subtechnique": "T1059.001",
            "name": "PowerShell",
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



# ---------------------------------------------------------------------------
# DET-AUTH-003: Suspicious Post-Authentication Privileged Session
# ---------------------------------------------------------------------------


def auth_003_session_id(event: dict[str, Any]) -> str | None:
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
    """Identify failed password authentication events."""

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

    document = {
        "schema_version": "1.0",
        "generated_by": "CYBERNOVA SOC Detection Engine",
        "detection_id": detection_id,
        "alert_count": len(alerts),
        "alerts": alerts,
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
# CLI
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser(
        description=(
            "Run a CYBERNOVA authentication detection "
            "against JSONL telemetry."
        )
    )

    parser.add_argument(
        "--detection",
        choices=(
            DETECTION_AUTH_001,
            DETECTION_AUTH_002,
            DETECTION_AUTH_003,
            DETECTION_ENDPOINT_001,
        ),
        required=True,
        help="Detection ID to execute.",
    )

    parser.add_argument(
        "--input",
        required=True,
        type=Path,
        help="Path to normalized telemetry JSONL.",
    )

    parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="Path for generated alert JSON.",
    )

    return parser.parse_args()


def run_detection(
    detection_id: str,
    events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Dispatch telemetry to the selected detection."""

    if detection_id == DETECTION_AUTH_001:
        return detect_auth_001(events)

    if detection_id == DETECTION_AUTH_002:
        return detect_auth_002(events)

    if detection_id == DETECTION_AUTH_003:
        return detect_auth_003(events)

    if detection_id == DETECTION_ENDPOINT_001:
        return detect_endpoint_001(events)

    raise ValueError(
        f"unsupported detection: {detection_id}"
    )


def main() -> int:
    """Application entry point."""

    args = parse_args()

    try:
        events = load_jsonl(args.input)

        alerts = run_detection(
            detection_id=args.detection,
            events=events,
        )

        write_alerts(
            alerts=alerts,
            output_path=args.output,
        )

    except (
        FileNotFoundError,
        TelemetryValidationError,
        OSError,
        ValueError,
    ) as exc:
        print(
            f"ERROR: {exc}",
            file=sys.stderr,
        )
        return 1

    print(
        "===== CYBERNOVA DETECTION ENGINE ====="
    )
    print(
        f"Detection: {args.detection}"
    )
    print(
        f"Telemetry events loaded: {len(events)}"
    )
    print(
        f"Alerts generated: {len(alerts)}"
    )
    print(
        f"Output: {args.output}"
    )

    for alert in alerts:
        print()
        print(
            f"Alert ID: {alert['alert_id']}"
        )
        print(
            f"Severity: {alert['severity']}"
        )
        if "source_ip" in alert:
            print(
                f"Source IP: {alert['source_ip']}"
            )

        if "host" in alert:
            print(
                f"Host: {alert['host']}"
            )

        if "user" in alert:
            print(
                f"User: {alert['user']}"
            )

        if "targeted_user_count" in alert:
            print(
                "Distinct users: "
                f"{alert['targeted_user_count']}"
            )

        if "failed_attempt_count" in alert:
            print(
                "Failed attempts: "
                f"{alert['failed_attempt_count']}"
            )

        if "successful_authentication_observed" in alert:
            print(
                "Successful authentication observed: "
                f"{alert['successful_authentication_observed']}"
            )

        if "risk_score" in alert:
            print(
                f"Risk score: {alert['risk_score']}"
            )

        if "indicators" in alert:
            print(
                "Indicators: "
                + ", ".join(alert["indicators"])
            )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
