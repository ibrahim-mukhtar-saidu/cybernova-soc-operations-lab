"""Correlation logic for the CYBERNOVA SOC CASE-010 workflow."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any


CORRELATION_ID = "DET-CORR-001"
CORRELATION_NAME = "Multi-Stage Attack Correlation"
CORRELATION_VERSION = "1.0"
CORRELATION_WINDOW_MINUTES = 30

REQUIRED_STAGES = (
    "DET-AUTH-001",
    "DET-AUTH-003",
    "DET-LINUX-001",
)

STAGE_NAMES = {
    "DET-AUTH-001": "credential_access",
    "DET-AUTH-003": "post_authentication_activity",
    "DET-LINUX-001": "persistence",
}


def _parse_timestamp(value: str) -> datetime:
    """Parse an ISO-8601 timestamp into an aware datetime."""

    normalized = value.replace("Z", "+00:00")
    timestamp = datetime.fromisoformat(normalized)

    if timestamp.tzinfo is None:
        raise ValueError("correlation timestamp must include timezone information")

    return timestamp


def _alert_timestamp(alert: dict[str, Any]) -> str:
    """Return the deterministic stage timestamp used for correlation."""

    timestamp = alert.get("timestamp")

    if isinstance(timestamp, str) and timestamp:
        return timestamp

    last_seen = alert.get("last_seen")

    if isinstance(last_seen, str) and last_seen:
        return last_seen

    first_seen = alert.get("first_seen")

    if isinstance(first_seen, str) and first_seen:
        return first_seen

    raise ValueError(
        "correlation alerts require timestamp, last_seen, or first_seen"
    )


def _supporting_event_ids(alert: dict[str, Any]) -> list[str]:
    """Return deterministic supporting event IDs from an alert."""

    event_ids = alert.get("supporting_event_ids", [])

    if not isinstance(event_ids, list):
        raise ValueError("supporting_event_ids must be a list")

    return sorted(
        {
            event_id
            for event_id in event_ids
            if isinstance(event_id, str) and event_id
        }
    )


def correlate_multi_stage_attack(
    alerts: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Correlate the three required CASE-010 detection stages."""

    candidates: dict[tuple[str, str], dict[str, list[dict[str, Any]]]] = {}

    for alert in alerts:
        detection_id = alert.get("detection_id")

        if detection_id not in REQUIRED_STAGES:
            continue

        if alert.get("status") != "open":
            continue

        if alert.get("confidence") != "high":
            continue

        host = alert.get("host")
        user = alert.get("user")
        try:
            timestamp = _alert_timestamp(alert)
        except ValueError as exc:
            raise ValueError(
                "correlation alerts require non-empty host, user, "
                "and timestamp, last_seen, or first_seen"
            ) from exc

        if not all(
            isinstance(value, str) and value
            for value in (host, user)
        ):
            raise ValueError(
                "correlation alerts require non-empty host and user"
            )

        _parse_timestamp(timestamp)

        key = (host, user)
        candidates.setdefault(key, {}).setdefault(detection_id, []).append(alert)

    correlations: list[dict[str, Any]] = []

    for (host, user), stages in candidates.items():
        if any(stage not in stages for stage in REQUIRED_STAGES):
            continue

        ordered_options = [
            sorted(stages[stage], key=lambda alert: _parse_timestamp(_alert_timestamp(alert)))
            for stage in REQUIRED_STAGES
        ]

        for auth_alert in ordered_options[0]:
            for session_alert in ordered_options[1]:
                for persistence_alert in ordered_options[2]:
                    selected = [
                        auth_alert,
                        session_alert,
                        persistence_alert,
                    ]

                    timestamps = [
                        _parse_timestamp(_alert_timestamp(alert))
                        for alert in selected
                    ]

                    if timestamps != sorted(timestamps):
                        continue

                    if timestamps[-1] - timestamps[0] > timedelta(
                        minutes=CORRELATION_WINDOW_MINUTES
                    ):
                        continue

                    source_ips = {
                        alert["source_ip"]
                        for alert in selected
                        if isinstance(alert.get("source_ip"), str)
                        and alert["source_ip"]
                    }

                    if len(source_ips) > 1:
                        continue

                    supporting_alert_ids = [
                        alert["alert_id"]
                        for alert in selected
                    ]

                    supporting_event_ids = sorted(
                        {
                            event_id
                            for alert in selected
                            for event_id in _supporting_event_ids(alert)
                        }
                    )

                    source_ip = next(iter(source_ips), None)

                    correlation_alert = {
                        "alert_id": "ALERT-CASE-010-DET-CORR-001",
                        "detection_id": CORRELATION_ID,
                        "detection_name": CORRELATION_NAME,
                        "detection_version": CORRELATION_VERSION,
                        "status": "open",
                        "severity": "critical",
                        "confidence": "high",
                        "first_seen": selected[0]["timestamp"],
                        "last_seen": selected[-1]["timestamp"],
                        "host": host,
                        "user": user,
                        "source_ip": source_ip,
                        "stage_count": len(selected),
                        "stages": [
                            {
                                "detection_id": alert["detection_id"],
                                "stage": STAGE_NAMES[alert["detection_id"]],
                                "alert_id": alert["alert_id"],
                                "timestamp": _alert_timestamp(alert),
                            }
                            for alert in selected
                        ],
                        "supporting_alert_ids": supporting_alert_ids,
                        "supporting_event_ids": supporting_event_ids,
                        "mitre_attack": {
                            "tactics": [
                                "credential_access",
                                "discovery",
                                "persistence",
                            ],
                            "techniques": [
                                "T1110",
                                "T1078",
                                "T1087",
                                "T1069.001",
                                "T1053.003",
                            ],
                        },
                        "analyst_interpretation": (
                            "Observed correlated authentication attack, "
                            "post-authentication privileged activity, and "
                            "Linux cron persistence alerts on the same lab "
                            "host and user within the configured correlation "
                            "window. The correlated evidence supports "
                            "investigation of a multi-stage attack sequence "
                            "but does not independently prove compromise."
                        ),
                    }

                    correlations.append(correlation_alert)

    return correlations
