"""Tests of the traffic log `TrafficLog` (spec T6, FR-20): schema, path, `commit`, escaping and reader."""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from obd_bridge import traffic_log
from obd_bridge.errors import LogFormatError, ReadOnlyViolation
from obd_bridge.policy import ReadOnlyPolicy
from obd_bridge.stn.driver import StnDriver
from obd_bridge.traffic_log import TrafficLog, escape, read_events, unescape
from obd_bridge.transport.null import NullTransport
from obd_bridge.uds.client import ReadOnlyUdsClient
from obd_bridge.uds.connection import ElmUdsConnection
from obd_bridge.vag.catalog import EcuCatalog

_EVENT_FIELDS = {"v", "sid", "seq", "tm", "tw", "ev", "layer", "ecu", "data", "guard", "meta"}
_TZ = timezone(timedelta(hours=1))


def _fake_clock(values: list[float]) -> Callable[[], float]:
    """Monotonic clock returning consecutive values (the last one repeated)."""
    state = list(values)

    def clock() -> float:
        return state.pop(0) if len(state) > 1 else state[0]

    return clock


def _fixed_now(moment: datetime) -> Callable[[], datetime]:
    return lambda: moment


def _write_lines(path: Path, events: list[dict | str]) -> Path:
    lines = [e if isinstance(e, str) else json.dumps(e) for e in events]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _event(seq: int, ev: str = "tx", layer: str = "adapter") -> dict:
    return {
        "v": 1,
        "sid": "20261120T101500-probe",
        "seq": seq,
        "tm": 0.0,
        "tw": "2026-11-20T10:15:00.000+01:00",
        "ev": ev,
        "layer": layer,
        "ecu": None,
        "data": "",
        "guard": None,
        "meta": {},
    }


def test_event_schema_and_seq(project_dir: Path) -> None:
    moment = datetime(2026, 11, 20, 10, 15, 0, 123000, tzinfo=_TZ)
    log = TrafficLog.create(
        "probe-dry-run",
        root=project_dir,
        clock=_fake_clock([100.0, 100.0, 100.2504, 100.5]),
        now=_fixed_now(moment),
    )
    log.session_start({"mode": "dry-run", "commit": "abc"})
    guard = {"decision": "allowed", "rule": "LINE/allowlist", "reason": "line on the allowlist"}
    log.emit("tx", "adapter", "STPX H:7E0, D:22F190, R:1", ecu="19", guard=guard)

    # Flush after every line: the file is readable before the log is closed.
    lines = log.path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    first, second = (json.loads(line) for line in lines)

    assert set(first) == _EVENT_FIELDS
    assert set(second) == _EVENT_FIELDS
    assert [first["seq"], second["seq"]] == [0, 1]
    assert first["v"] == 1 and first["sid"] == log.session_id
    assert first["ev"] == "session_start" and first["layer"] == "app"
    assert first["meta"]["commit"] == "abc"
    assert second["tm"] == 0.25
    assert second["tw"] == "2026-11-20T10:15:00.123+01:00"
    assert (second["ecu"], second["guard"], second["data"]) == ("19", guard, "STPX H:7E0, D:22F190, R:1")
    # Compact form: separators without spaces.
    assert ", " not in lines[0] and ": " not in lines[0]

    log.emit("guard", "adapter", "ATMA", guard={"decision": "rejected", "rule": "LINE/allowlist", "reason": "x"})
    log.session_end({"atcs": None, "run_exit_code": 0})
    log.close()

    events = read_events(log.path)
    assert [e["seq"] for e in events] == [0, 1, 2, 3]
    end = events[-1]
    assert end["ev"] == "session_end"
    assert end["meta"]["lines_tx"] == 1
    assert end["meta"]["stpx_count"] == 1
    assert end["meta"]["guard_rejections"] == 1
    assert end["meta"]["run_exit_code"] == 0
    assert "duration_s" in end["meta"]
    with pytest.raises(ValueError):
        log.emit("marker", "app")


def test_session_path_and_collision(project_dir: Path) -> None:
    moment = datetime(2026, 11, 20, 9, 5, 7, tzinfo=_TZ)
    logs = [
        TrafficLog.create("probe", root=project_dir, now=_fixed_now(moment)) for _ in range(3)
    ]
    try:
        expected_dir = project_dir / "data" / "sessions" / "2026-11-20"
        assert [log.session_id for log in logs] == [
            "20261120T090507-probe",
            "20261120T090507-probe-2",
            "20261120T090507-probe-3",
        ]
        assert [log.path for log in logs] == [
            expected_dir / f"{log.session_id}.jsonl" for log in logs
        ]
        logs[0].session_start({"commit": None})
    finally:
        for log in logs:
            log.close()

    # No overwrite: another log does not go into existing files.
    before = logs[0].path.read_bytes()
    extra = TrafficLog.create("probe", root=project_dir, now=_fixed_now(moment))
    extra.close()
    assert extra.path.name == "20261120T090507-probe-4.jsonl"
    assert logs[0].path.read_bytes() == before

    with pytest.raises(ValueError):
        TrafficLog.create("../probe", root=project_dir)


def test_commit_null_without_git(project_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Temporary directory outside the repository: no commit.
    assert traffic_log.detect_commit(project_dir) is None

    log = TrafficLog.create("probe-dry-run", root=project_dir)
    log.session_start({"mode": "dry-run"})
    log.close()
    assert read_events(log.path)[0]["meta"]["commit"] is None

    def missing_git(*args: object, **kwargs: object) -> object:
        raise FileNotFoundError("git")

    def slow_git(*args: object, **kwargs: object) -> object:
        raise subprocess.TimeoutExpired(cmd="git", timeout=2)

    def failing_git(*args: object, **kwargs: object) -> object:
        return subprocess.CompletedProcess(args=args, returncode=128, stdout="", stderr="fatal")

    def ok_git(*args: object, **kwargs: object) -> object:
        assert kwargs.get("timeout") == 2
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="a" * 40 + "\n", stderr="")

    for fake in (missing_git, slow_git, failing_git):
        monkeypatch.setattr(traffic_log.subprocess, "run", fake)
        assert traffic_log.detect_commit(project_dir) is None
    monkeypatch.setattr(traffic_log.subprocess, "run", ok_git)
    assert traffic_log.detect_commit(project_dir) == "a" * 40


def test_escape_roundtrip() -> None:
    every = bytes(range(256))
    for value in range(256):
        single = bytes([value])
        assert unescape(escape(single)) == single
    assert unescape(escape(every)) == every
    assert escape(every).isascii()

    assert escape(b"ATZ\r") == "ATZ\\r"
    assert escape(b"\n") == "\\n"
    assert escape(b"\\") == "\\\\"
    assert escape(b"\x00\x1b\x7f\xff") == "\\x00\\x1B\\x7F\\xFF"
    assert escape(b"7E8 03 62 F1 90>") == "7E8 03 62 F1 90>"

    for broken in ("\\x4", "\\q", "abc\\", "\\xZZ", "\u017c"):
        with pytest.raises(LogFormatError):
            unescape(broken)


@pytest.mark.parametrize(
    ("events", "line_no"),
    [
        pytest.param([_event(0, "session_start", "app"), "{this is not json"], 2, id="json"),
        pytest.param([_event(0, "tx")], 1, id="missing-session-start"),
        pytest.param([_event(1, "session_start", "app")], 1, id="seq-from-zero"),
        pytest.param(
            [_event(0, "session_start", "app"), _event(1), _event(3)], 3, id="seq-gap"
        ),
        pytest.param([_event(0, "session_start", "app"), "[1, 2]"], 2, id="not-object"),
    ],
)
def test_read_events_errors(tmp_path: Path, events: list[dict | str], line_no: int) -> None:
    path = _write_lines(tmp_path / "s.jsonl", events)
    with pytest.raises(LogFormatError) as excinfo:
        read_events(path)
    assert excinfo.value.exit_code == 64
    assert f"line {line_no}" in str(excinfo.value)

    valid = _write_lines(
        tmp_path / "ok.jsonl", [_event(0, "session_start", "app"), _event(1), _event(2)]
    )
    assert [e["seq"] for e in read_events(valid)] == [0, 1, 2]


class _GatewayTransport(NullTransport):
    """`NullTransport` with the reply of gateway 19 to `22F187` (3 ISO-TP frames)."""

    STPX_REPLIES = {
        "STPX H:710,D:22F187,R:1,T:1500": "77A100E62F187344730\r77A2139303734363841\r77A2220000000000000",
    }

    @staticmethod
    def _reply_for(command: str) -> str:
        reply = _GatewayTransport.STPX_REPLIES.get(command)
        return reply if reply is not None else NullTransport._reply_for(command)


def test_client_events_in_driver_log(project_dir: Path) -> None:
    """`uds` and `guard` events of the `uds` layer from `ReadOnlyUdsClient` go to the driver log."""
    catalog = EcuCatalog.load(project_dir / "defs" / "ecu-catalog.yaml")
    log = TrafficLog.create("probe-dry-run", root=project_dir)
    log.session_start({"commit": None})
    driver = StnDriver(
        _GatewayTransport(), ReadOnlyPolicy(catalog), log, clock=lambda: 0.0, sleep=lambda _: None
    )
    driver.open()
    driver.warm_start()
    driver.set_format()
    driver.identify(None)
    driver.open_protocol()
    driver.select_target(catalog.get("19"))
    connection = ElmUdsConnection(driver)
    client = ReadOnlyUdsClient(connection, ReadOnlyPolicy(catalog))
    assert connection.driver.log is log

    assert client.read_did(0xF187) == b"4G0907468A "
    with pytest.raises(ReadOnlyViolation):
        client.read_dtc_snapshot(0x012345, 0xFF)
    log.close()

    events = read_events(log.path)
    assert [e["seq"] for e in events] == list(range(len(events)))
    uds = [e for e in events if e["ev"] == "uds"]
    assert [(e["layer"], e["meta"]["direction"]) for e in uds] == [("uds", "req"), ("uds", "resp")]
    assert uds[0]["data"] == "22F187"
    assert uds[0]["guard"] == {"decision": "allowed", "rule": "UDS/0x22", "reason": None}
    assert uds[1]["data"] == "62F1873447303930373436384120"
    assert uds[1]["meta"]["outcome"] == "positive"
    assert {e["ecu"] for e in uds} == {"19"}

    # Order: req, then the driver STPX line, then resp.
    stpx = [e for e in events if e["ev"] == "tx" and e["layer"] == "adapter" and e["data"].startswith("STPX")]
    assert [e["data"] for e in stpx] == ["STPX H:710,D:22F187,R:1,T:1500"]
    assert uds[0]["seq"] < stpx[0]["seq"] < uds[1]["seq"]

    # Rejection in `_checked`: one `guard` event of the `uds` layer, no STPX line.
    guards = [e for e in events if e["ev"] == "guard"]
    assert [(e["layer"], e["data"]) for e in guards] == [("uds", "1904012345FF")]
    assert guards[0]["guard"]["decision"] == "rejected"
    assert guards[0]["guard"]["rule"] == "UDS/record-ff"
    assert guards[0]["ecu"] == "19"


def test_guard_must_be_mapping(project_dir: Path) -> None:
    """`guard` as an object (e.g. `GuardDecision` without the `decision` field) raises `TypeError` without writing a line."""
    from obd_bridge.policy import GuardDecision

    log = TrafficLog.create("probe", root=project_dir)
    log.session_start({"commit": None})
    with pytest.raises(TypeError):
        log.emit("tx", "adapter", "ATI", guard=GuardDecision(allowed=True, rule="LINE/allowlist", reason=None))  # type: ignore[arg-type]
    log.emit("tx", "adapter", "ATI", guard=None)
    log.close()
    events = read_events(log.path)
    assert [e["seq"] for e in events] == [0, 1]
    assert events[1]["guard"] is None
