#!/usr/bin/env python3
"""
CYBERNOVA SOC Operations Lab
Detection Engine

Implemented detections:
    DET-AUTH-001 - SSH Brute-Force Authentication Detection
    DET-AUTH-002 - Password Spraying Authentication Detection

Purpose:
    Read normalized authentication telemetry, validate the input,
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


REQUIRED_FIELDS = {
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

            missing = REQUIRED_FIELDS - set(event)

            if missing:
                missing_fields = ", ".join(sorted(missing))
                raise TelemetryValidationError(
                    f"line {line_number}: missing required fields: "
                    f"{missing_fields}"
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
    """Validate fields required for authentication detection."""

    if event["event_type"] != "authentication":
        return

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
        ),
        required=True,
        help="Detection ID to execute.",
    )

    parser.add_argument(
        "--input",
        required=True,
        type=Path,
        help="Path to normalized authentication JSONL telemetry.",
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
        print(
            f"Source IP: {alert['source_ip']}"
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

        print(
            "Failed attempts: "
            f"{alert['failed_attempt_count']}"
        )

        print(
            "Successful authentication observed: "
            f"{alert['successful_authentication_observed']}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
