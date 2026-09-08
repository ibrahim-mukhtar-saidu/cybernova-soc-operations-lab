import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT / "src" / "detection_engine.py"

CASE001_TELEMETRY = (
    ROOT / "telemetry/authentication/CASE-001-authentication-events.jsonl"
)

CASE002_TELEMETRY = (
    ROOT / "telemetry/authentication/CASE-002-authentication-events.jsonl"
)


def run_detection(detection_id, telemetry_path, output_path):
    result = subprocess.run(
        [
            sys.executable,
            str(ENGINE),
            "--detection",
            detection_id,
            "--input",
            str(telemetry_path),
            "--output",
            str(output_path),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, (
        f"Detection failed.\n"
        f"STDOUT:\n{result.stdout}\n"
        f"STDERR:\n{result.stderr}"
    )

    return json.loads(output_path.read_text(encoding="utf-8"))


def test_auth_001_brute_force_detection(tmp_path):
    output = tmp_path / "auth001.json"

    document = run_detection(
        "DET-AUTH-001",
        CASE001_TELEMETRY,
        output,
    )

    assert document["detection_id"] == "DET-AUTH-001"
    assert document["alert_count"] == 1

    alert = document["alerts"][0]

    assert alert["alert_id"] == "ALERT-CASE-001-DET-AUTH-001"
    assert alert["source_ip"] == "198.51.100.25"
    assert alert["user"] == "root"
    assert alert["failed_attempt_count"] == 8
    assert alert["successful_authentication_observed"] is True
    assert alert["successful_authentication_event_id"] == "EVT-001012"


def test_auth_002_password_spraying_detection(tmp_path):
    output = tmp_path / "auth002.json"

    document = run_detection(
        "DET-AUTH-002",
        CASE002_TELEMETRY,
        output,
    )

    assert document["detection_id"] == "DET-AUTH-002"
    assert document["alert_count"] == 1

    alert = document["alerts"][0]

    assert alert["alert_id"] == "ALERT-CASE-002-DET-AUTH-002"
    assert alert["source_ip"] == "198.51.100.40"
    assert alert["failed_attempt_count"] == 13
    assert alert["targeted_user_count"] == 7
    assert alert["authentication_method"] == "password"


def test_auth_002_success_escalates_alert(tmp_path):
    output = tmp_path / "auth002-escalation.json"

    document = run_detection(
        "DET-AUTH-002",
        CASE002_TELEMETRY,
        output,
    )

    alert = document["alerts"][0]

    assert alert["successful_authentication_observed"] is True
    assert alert["successful_authentication_event_id"] == "EVT-002008"
    assert alert["successful_authentication_user"] == "alice"
    assert alert["severity"] == "high"
    assert alert["confidence"] == "high"


def test_auth_002_targeted_users_are_correlated(tmp_path):
    output = tmp_path / "auth002-users.json"

    document = run_detection(
        "DET-AUTH-002",
        CASE002_TELEMETRY,
        output,
    )

    alert = document["alerts"][0]

    expected_users = [
        "alice",
        "bob",
        "carol",
        "david",
        "erin",
        "frank",
        "grace",
    ]

    assert alert["targeted_users"] == expected_users
    assert alert["targeted_user_count"] == len(expected_users)


def test_auth_002_supporting_events_exist_in_telemetry(tmp_path):
    output = tmp_path / "auth002-evidence.json"

    document = run_detection(
        "DET-AUTH-002",
        CASE002_TELEMETRY,
        output,
    )

    alert = document["alerts"][0]

    telemetry_events = [
        json.loads(line)
        for line in CASE002_TELEMETRY.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    telemetry_ids = {
        event["event_id"]
        for event in telemetry_events
    }

    assert alert["supporting_event_ids"]
    assert set(alert["supporting_event_ids"]).issubset(
        telemetry_ids
    )

    assert (
        alert["successful_authentication_event_id"]
        in telemetry_ids
    )


def test_auth_002_noise_does_not_trigger(tmp_path):
    output = tmp_path / "auth002-noise.json"
    noise_path = tmp_path / "noise.jsonl"

    events = [
        json.loads(line)
        for line in CASE002_TELEMETRY.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    noise = [
        event
        for event in events
        if event["source_ip"] != "198.51.100.40"
    ]

    noise_path.write_text(
        "\n".join(json.dumps(event) for event in noise) + "\n",
        encoding="utf-8",
    )

    document = run_detection(
        "DET-AUTH-002",
        noise_path,
        output,
    )

    assert document["alert_count"] == 0
    assert document["alerts"] == []


def test_auth_002_requires_distinct_users(tmp_path):
    output = tmp_path / "auth002-threshold.json"
    reduced_path = tmp_path / "reduced.jsonl"

    events = [
        json.loads(line)
        for line in CASE002_TELEMETRY.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    reduced = [
        event
        for event in events
        if event["source_ip"] != "198.51.100.40"
        or event["user"] in {"alice", "bob", "carol", "david", "erin"}
    ]

    reduced_path.write_text(
        "\n".join(json.dumps(event) for event in reduced) + "\n",
        encoding="utf-8",
    )

    document = run_detection(
        "DET-AUTH-002",
        reduced_path,
        output,
    )

    assert document["alert_count"] == 0


def test_invalid_telemetry_is_rejected(tmp_path):
    output = tmp_path / "invalid.json"
    invalid_path = tmp_path / "invalid.jsonl"

    invalid_path.write_text(
        json.dumps(
            {
                "event_id": "INVALID-001",
                "timestamp": "2026-09-08T10:00:00Z",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            str(ENGINE),
            "--detection",
            "DET-AUTH-002",
            "--input",
            str(invalid_path),
            "--output",
            str(output),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
