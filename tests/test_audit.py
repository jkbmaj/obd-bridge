"""Tests of the session audit `audit_session` (spec T10, FR-27, audit M6).

The clean log is created in the test from a real `StnDriver` on `NullTransport`.
Logs with violations are the fixtures `tests/fixtures/sessions/*.jsonl` (valid
schema T6, continuous `seq`) or copies of the clean log modified in `tmp_path`.
The `forged_*` fixtures contain forged `state` events (they declare transitions
consistent with the probe), so the audit must detect sequences C1, C2 and M1
only from `tx`/`rx` pairs of the `transport` layer.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from conftest import MOCK_CATALOG
from obd_bridge.audit import (
    JSON_SCHEMA,
    RULE_ADAPTER_CONFIG,
    RULE_ADAPTER_RESET,
    RULE_CHARSET,
    RULE_FRAMING,
    RULE_LAYER_MISMATCH,
    RULE_STATE_TRANSITION,
    AuditResult,
    audit_session,
    render_json,
    render_text,
)
from obd_bridge.errors import LogFormatError
from obd_bridge.policy import ReadOnlyPolicy
from obd_bridge.stn.driver import StnDriver
from obd_bridge.traffic_log import TrafficLog, read_events
from obd_bridge.transport.null import NullTransport
from obd_bridge.vag.catalog import EcuCatalog

REPO_ROOT: Path = Path(__file__).resolve().parent.parent
CATALOG: EcuCatalog = EcuCatalog.load(MOCK_CATALOG)
SESSIONS_DIR: Path = REPO_ROOT / "tests" / "fixtures" / "sessions"


class FakeClock:
    """Monotonic clock without waiting; `sleep` advances the time."""

    def __init__(self) -> None:
        self.now = 50.0

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clean_log(project_dir: Path) -> Path:
    """Session log from `StnDriver` on `NullTransport`: initialization, protocol, target 19, STPX, close."""
    log = TrafficLog.create("probe-dry-run", root=project_dir)
    log.session_start({"commit": None, "mode": "dry-run"})
    clock = FakeClock()
    driver = StnDriver(NullTransport(), ReadOnlyPolicy(CATALOG), log, clock=clock, sleep=clock.sleep)
    driver.open()
    driver.initialize(None)
    driver.open_protocol()
    driver.select_target(CATALOG.get("19"))
    driver.transact(b"\x22\xf1\x87")
    driver.close()
    log.session_end({"run_exit_code": 0})
    log.close()
    return log.path


def write_events(path: Path, events: list[dict[str, Any]]) -> Path:
    """Writes events as JSONL with a reassigned, continuous `seq`."""
    lines = []
    for seq, event in enumerate(events):
        lines.append(json.dumps({**event, "seq": seq}, ensure_ascii=False, separators=(",", ":")))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def transport_tx_index(events: list[dict[str, Any]], escaped: str) -> int:
    """Index of the `transport` layer `tx` event with data `escaped`."""
    return next(
        i
        for i, e in enumerate(events)
        if e["ev"] == "tx" and e["layer"] == "transport" and e["data"] == escaped
    )


def rules(result: AuditResult) -> set[str]:
    return {violation.rule for violation in result.violations}


def test_clean_log_passes(clean_log: Path) -> None:
    events = read_events(clean_log)
    result = audit_session(clean_log, CATALOG)

    assert result.violations == ()
    assert result.exit_code == 0
    assert result.warnings == ()
    assert result.mode == "dry-run"
    assert result.checked_tx == sum(1 for e in events if e["ev"] == "tx" and e["layer"] == "transport")
    assert result.checked_tx == 20  # 7 initialization, 7 protocol, 4 target, STPX, STPC
    assert result.guard_rejections == 0

    document = json.loads(render_json(result))
    assert document["schema"] == JSON_SCHEMA == "obdb.audit/1"
    assert set(document) == {
        "schema", "path", "mode", "checked_tx", "violations", "guard_rejections", "warnings",
    }
    assert document["violations"] == []
    assert "no violations" in render_text(result)


def test_disallowed_tx_line() -> None:
    path = SESSIONS_DIR / "atsp6_injected.jsonl"
    events = read_events(path)
    seq = events[transport_tx_index(events, "ATSP6\\r")]["seq"]

    result = audit_session(path, CATALOG)

    matching = [v for v in result.violations if v.seq == seq]
    assert [(v.line, v.rule) for v in matching] == [("ATSP6", "LINE/no-match")]
    assert matching[0].reason
    assert result.exit_code == 2
    document = json.loads(render_json(result))
    assert {
        "seq": seq, "line": "ATSP6", "rule": "LINE/no-match", "reason": matching[0].reason, "caused_by_seq": None
    } in document["violations"]
    assert "LINE/no-match" in render_text(result)


def test_stpx_in_protocol_open() -> None:
    result = audit_session(SESSIONS_DIR / "stpx_in_protocol_open.jsonl", CATALOG)

    stpx = [v for v in result.violations if (v.line or "").startswith("STPX ")]
    assert [v.rule for v in stpx] == ["LINE/state"]
    assert result.exit_code == 2


def _drop_adapter_tx(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    index = transport_tx_index(events, "STDI\\r")
    return events[: index - 1] + events[index:]


def _reject_adapter_tx(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    index = transport_tx_index(events, "STDI\\r")
    events[index - 1] = {**events[index - 1], "guard": {"decision": "rejected", "rule": "x", "reason": "x"}}
    return events


def _set_transport_data(data: str) -> Callable[[list[dict[str, Any]]], list[dict[str, Any]]]:
    def change(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        index = transport_tx_index(events, "STDI\\r")
        events[index] = {**events[index], "data": data}
        return events

    return change


@pytest.mark.parametrize(
    ("mutation", "expected_rule"),
    [
        pytest.param(_drop_adapter_tx, RULE_LAYER_MISMATCH, id="missing-adapter-tx"),
        pytest.param(_reject_adapter_tx, RULE_LAYER_MISMATCH, id="adapter-tx-rejected"),
        pytest.param(_set_transport_data("ATI\\r"), RULE_LAYER_MISMATCH, id="different-line"),
        pytest.param(_set_transport_data("STDI"), RULE_FRAMING, id="missing-cr"),
        pytest.param(_set_transport_data("STDI\\r\\r"), RULE_FRAMING, id="extra-cr"),
        pytest.param(_set_transport_data("STDI\\nATI\\r"), RULE_FRAMING, id="lf"),
        pytest.param(_set_transport_data("STDI\\xC4\\r"), RULE_CHARSET, id="non-ascii"),
    ],
)
def test_layer_mismatch_and_framing(
    clean_log: Path,
    tmp_path: Path,
    mutation: Callable[[list[dict[str, Any]]], list[dict[str, Any]]],
    expected_rule: str,
) -> None:
    events = mutation(read_events(clean_log))
    path = write_events(tmp_path / "mutated.jsonl", events)

    result = audit_session(path, CATALOG)

    assert expected_rule in rules(result)
    assert result.exit_code == 2


def test_broken_log(tmp_path: Path, clean_log: Path) -> None:
    broken_json = tmp_path / "broken.jsonl"
    broken_json.write_text(clean_log.read_text(encoding="utf-8") + "{invalid\n", encoding="utf-8")
    paths = [broken_json, tmp_path / "missing.jsonl", SESSIONS_DIR / "broken_seq.jsonl"]

    for path in paths:
        with pytest.raises(LogFormatError) as info:
            audit_session(path, CATALOG)
        assert info.value.exit_code == 64

    # Fixed messages, without the OS text (strerror, decoder reason).
    with pytest.raises(LogFormatError) as missing:
        audit_session(tmp_path / "missing.jsonl", CATALOG)
    assert str(missing.value).endswith(": file does not exist")
    assert "No such file" not in str(missing.value)
    with pytest.raises(LogFormatError) as directory:
        audit_session(tmp_path, CATALOG)
    assert "directory" in str(directory.value) and "Is a directory" not in str(directory.value)
    binary = tmp_path / "binary.jsonl"
    binary.write_bytes(b"\xff\xfe{}\n")
    with pytest.raises(LogFormatError) as undecodable:
        audit_session(binary, CATALOG)
    assert "UTF-8" in str(undecodable.value) and "invalid start byte" not in str(undecodable.value)


@pytest.mark.parametrize(
    ("fixture", "line_rule", "line_prefix", "model_rules"),
    [
        pytest.param(
            "forged_c1.jsonl",
            "LINE/no-match",
            "ATFCSD021101",
            {RULE_ADAPTER_CONFIG, RULE_STATE_TRANSITION},
            id="C1",
        ),
        pytest.param(
            "forged_c2.jsonl",
            "LINE/no-match",
            "ATCAF0",
            {RULE_ADAPTER_CONFIG, RULE_STATE_TRANSITION},
            id="C2",
        ),
        pytest.param(
            "forged_m1.jsonl",
            "LINE/state",
            "STCFCPC",
            {RULE_ADAPTER_CONFIG, RULE_STATE_TRANSITION},
            id="M1",
        ),
    ],
)
def test_forged_sequences(fixture: str, line_rule: str, line_prefix: str, model_rules: set[str]) -> None:
    path = SESSIONS_DIR / fixture
    events = read_events(path)
    # Forged state events declare only transitions consistent with the probe.
    states = [e["meta"] for e in events if e["ev"] == "state"]
    assert {"prev_state": "PROTOCOL_OPEN", "state": "TARGET_SELECTED", "prev_target": "19", "target": "19"} in [
        {k: m[k] for k in ("prev_state", "state", "prev_target", "target")} for m in states
    ]

    result = audit_session(path, CATALOG)

    assert any(v.rule == line_rule and v.line == line_prefix for v in result.violations)
    assert model_rules <= rules(result)
    stpx = [v for v in result.violations if (v.line or "").startswith("STPX ")]
    assert stpx and all(v.rule == RULE_ADAPTER_CONFIG for v in stpx)
    assert not any(v.rule == "LINE/adapter-config" for v in result.violations)
    assert result.exit_code == 2
    # Cascade: model violations after the line that changed the model are secondary to that line.
    cause = next(v.seq for v in result.violations if v.rule == line_rule and v.line == line_prefix)
    assert all(v.caused_by_seq == cause for v in stpx)
    assert all(v.caused_by_seq is None for v in result.violations if v.seq <= cause)
    assert render_text(result).count("    and ") == 1


def test_target_without_header() -> None:
    path = SESSIONS_DIR / "target_without_header.jsonl"
    events = read_events(path)
    to_target = next(
        e["seq"] for e in events if e["ev"] == "state" and e["meta"]["state"] == "TARGET_SELECTED"
    )

    result = audit_session(path, CATALOG)

    transition = [v for v in result.violations if v.seq == to_target]
    assert [v.rule for v in transition] == [RULE_STATE_TRANSITION]
    assert "77A" in transition[0].reason or "710" in transition[0].reason
    assert any("session_end" in warning for warning in result.warnings)
    assert result.exit_code == 2
    assert "session_end" in render_text(result)


# ---------------------------------------------------------------------------
# Package C: the audit replays adapter reset detection

BANNER_RX = "\\r\\rELM327 v1.3a\\r\\r>"


def _stpx_pair(events: list[dict[str, Any]]) -> tuple[int, int]:
    """Indexes of the adapter layer `tx` for `STPX` and the transport layer `rx` with its reply."""
    tx = next(i for i, e in enumerate(events) if _adapter_tx(e) and e["data"].startswith("STPX"))
    rx = next(i for i in range(tx + 2, len(events)) if _is(events[i], "rx", "transport"))
    return tx, rx


def _is(event: dict[str, Any], ev: str, layer: str) -> bool:
    return event["ev"] == ev and event["layer"] == layer


def _adapter_tx(event: dict[str, Any]) -> bool:
    return _is(event, "tx", "adapter")


def _with_banner_then_stpx(events: list[dict[str, Any]], *, repeat: bool) -> list[dict[str, Any]]:
    """Banner in the reply to `STPX`; with `repeat` another `STPX` after the banner (driver regression)."""
    tx, rx = _stpx_pair(events)
    changed = [dict(e) for e in events]
    changed[rx] = {**changed[rx], "data": BANNER_RX}
    if repeat:
        repeated = [dict(changed[tx]), dict(changed[tx + 1]), {**changed[rx], "data": "NO DATA\\r\\r>"}]
        changed[rx + 1 : rx + 1] = repeated
    return changed


def _stale_before(events: list[dict[str, Any]], line: str, data: str) -> list[dict[str, Any]]:
    """An `rx` event with `meta.stale` right before the adapter layer `tx` with line `line`."""
    index = next(i for i, e in enumerate(events) if _adapter_tx(e) and e["data"] == line)
    meta = {"stale": True, "timeout": True}
    stale = {**events[index + 2], "ev": "rx", "layer": "transport", "data": data, "meta": meta}
    stale.pop("guard", None)
    return [*events[:index], stale, *events[index:]]


def test_audit_reset_banner_then_only_stpc(clean_log: Path, tmp_path: Path) -> None:
    """C4: a banner in the reply followed only by `STPC` (driver behaviour) yields 0 violations."""
    events = _with_banner_then_stpx(read_events(clean_log), repeat=False)
    result = audit_session(write_events(tmp_path / "reset_ok.jsonl", events), CATALOG)
    assert result.violations == () and result.exit_code == 0


def test_audit_reset_banner_then_stpx(clean_log: Path, tmp_path: Path) -> None:
    """C4: a line other than `STPC` after reset signs yields `AUDIT/adapter-reset` and code 2."""
    events = _with_banner_then_stpx(read_events(clean_log), repeat=True)
    path = write_events(tmp_path / "reset_regression.jsonl", events)
    stored = read_events(path)
    transport_tx = [e for e in stored if _is(e, "tx", "transport")]
    second_stpx = [e["seq"] for e in transport_tx if e["data"].startswith("STPX")][1]

    result = audit_session(path, CATALOG)

    assert result.exit_code == 2
    reset = [v for v in result.violations if v.rule == RULE_ADAPTER_RESET]
    assert [v.seq for v in reset] == [second_stpx]
    assert reset[0].caused_by_seq is None and "ELM327" in reset[0].reason
    # The model after the reset is empty, so the same STPX also violates the model condition.
    config = [v for v in result.violations if v.rule == RULE_ADAPTER_CONFIG]
    assert [v.seq for v in config] == [second_stpx]
    stpc = [e["seq"] for e in transport_tx if e["data"] == "STPC\\r"]
    assert not any(v.seq in stpc for v in result.violations)
    assert RULE_ADAPTER_RESET in render_text(result)


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("STPX H:710,D:22F187,R:1,T:1500", {RULE_ADAPTER_RESET, RULE_ADAPTER_CONFIG}),
        ("ATWS", set()),
        ("STPC", set()),
    ],
)
def test_audit_stale_input(clean_log: Path, tmp_path: Path, line: str, expected: set[str]) -> None:
    """C4: `meta.stale` before a line other than `ATWS` in RAW and `STPC` opens the reset lockout."""
    events = read_events(clean_log)
    if line.startswith("STPX"):
        line = next(e["data"] for e in events if _adapter_tx(e) and e["data"].startswith("STPX"))
    events = _stale_before(events, line, "77A0462F18741AAAAAA\\r")
    result = audit_session(write_events(tmp_path / "stale.jsonl", events), CATALOG)
    assert {v.rule for v in result.violations if v.caused_by_seq is None} == expected
    assert result.exit_code == (2 if expected else 0)
