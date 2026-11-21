"""Tests of the `obdb probe --execute` probe (runner, preflight, report; spec T9, T6, T8, FR-22, FR-25).

The tests do not use `SerialTransport` or `/dev/*`. The car is simulated by
`CarSimTransport`: it answers adapter lines from a table, and `STPX` lines
with ISO-TP frames using the response CAN ID from the ECU catalog. The clock,
the wait function and the local time are injected, so the run is
deterministic. Files are created only in `project_dir` (a temporary
directory set as the current one).
"""

from __future__ import annotations

import dataclasses
import io
import signal
from collections.abc import Callable, Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

import obd_bridge.probe.plan as plan_module
import obd_bridge.probe.report as report_module
import obd_bridge.probe.runner as runner_module
import obd_bridge.stn.driver as driver_module
from conftest import MOCK_CATALOG
from obd_bridge.audit import AuditViolation, audit_session
from obd_bridge.errors import TransportError, TransportTimeout
from obd_bridge.probe.preflight import PreflightAborted, confirm
from obd_bridge.probe.runner import (
    ItemResult,
    ProbeMode,
    ProbeSession,
    classify_step,
    execute_probe,
    nearest_rank,
    nrc78_mode,
    run_probe_session,
)
from obd_bridge.stn.profile import AdapterProfile
from obd_bridge.traffic_log import read_events
from obd_bridge.vag.catalog import EcuCatalog
from obd_bridge.yamlio import load_yaml

CATALOG: EcuCatalog = EcuCatalog.load(MOCK_CATALOG)
EXECUTED_ALL: list[int] = [*range(1, 9), *range(10, 23), 24, 25, 26, 27]
STAGE_BCD: list[int] = [*range(10, 23), 24, 25]

# ---------------------------------------------------------------------------
# Car simulator


ADAPTER_REPLIES: dict[str, str] = {
    "ATWS": "ELM327 v1.3a",
    "ATI": "ELM327 v1.3a",
    "AT@1": "SCANTOOL.NET LLC",
    "STI": "STN2120 v4.5.0",
    "STDI": "STN2120 r1.0",
    "ATRV": "12.6V",
    "STVR": "12.60",
    "ATPPS": "03:19 F  0C:68 N\r2A:04 F",
    "ATDPN": "A6",
    "STPR": "33",
    "STPRS": "ISO 15765-4 (CAN 11/500)",
    "ATCS": "T:00 R:00",
    "STFCP": "?",
}
"""Adapter responses without echo; lines outside the table get `OK`."""

INSTALLED = bytes([0x01, 0x02, 0x03, 0x17, 0x19, 0x34, 0x5F, 0x09]) + bytes(72)
DTC = bytes.fromhex("012345")

DEFAULT_UDS: dict[tuple[str, str], Any] = {
    ("710", "22F187"): bytes.fromhex("62F187") + b"4G0907468D ",
    ("710", "222A2A"): bytes.fromhex("622A2A") + INSTALLED,
    ("710", "220634"): bytes.fromhex("7F2222"),
    ("710", "1902FF"): bytes.fromhex("5902FF") + DTC + b"\x2f",
    ("710", "1903"): bytes.fromhex("5903") + DTC + b"\x01" + DTC + b"\xff",
    ("7E1", "190A"): [bytes.fromhex("7F1978"), bytes.fromhex("590AFF")],
}
"""UDS responses `(tx, request hex)`; the rest from `default_positive`."""


def default_positive(request: str) -> bytes | str:
    """Positive response for a request outside the table."""
    data = bytes.fromhex(request)
    if data[0] == 0x22:
        return bytes([0x62]) + data[1:] + b"\x01\x02\x03"
    if data[0] == 0x19:
        sub = data[1]
        if sub == 0x01:
            return bytes.fromhex("5901FF010000")
        if sub == 0x04:
            return bytes.fromhex("5904") + data[2:6] + b"\x01\x02"
        if sub == 0x03:
            return bytes.fromhex("5903")
        return bytes([0x59, sub, 0xFF])
    return "NO DATA"


def isotp_frames(rx_id: int, message: bytes) -> list[str]:
    """ISO-TP frames in the `ATH1`/`ATS0` format (SF, or FF and CF with padding)."""
    prefix = f"{rx_id:03X}"
    if len(message) <= 7:
        body = bytes([len(message)]) + message
        return [prefix + body.ljust(8, b"\xaa").hex().upper()]
    frames = [prefix + (bytes([0x10 | (len(message) >> 8), len(message) & 0xFF]) + message[:6]).hex().upper()]
    rest, seq = message[6:], 1
    while rest:
        chunk, rest = rest[:7], rest[7:]
        frames.append(prefix + (bytes([0x20 | seq]) + chunk).ljust(8, b"\xaa").hex().upper())
        seq = (seq + 1) % 16
    return frames


class FakeClock:
    """Monotonic clock advanced by calls, `sleep` and the simulator."""

    def __init__(self) -> None:
        self.t = 100.0
        self.slept: list[float] = []

    def __call__(self) -> float:
        self.t += 0.0001
        return self.t

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.t += seconds

    def advance(self, seconds: float) -> None:
        self.t += seconds


def fixed_now() -> datetime:
    """Fixed local time with time zone (session 2026-11-20 08:15:00.123 +01:00)."""
    return datetime(2026, 11, 20, 8, 15, 0, 123000, tzinfo=timezone(timedelta(hours=1)))


class CarSimTransport:
    """Transport simulating an STN2120 adapter connected to the car (no echo, `ATH1`, `ATS0`).

    Parameters:
        catalog: ECU catalog (response CAN ID for `H:` from the `STPX` line).
        clock: clock advanced by 34.5 ms on each response to `STPX`.
        adapter: adapter response overrides (line: text).
        uds: UDS response overrides (`(tx, request)`: bytes, list of messages or text).
        interrupt_on: line at which the first read raises `KeyboardInterrupt`.
        interrupts: number of consecutive `interrupt_on` reads with `KeyboardInterrupt`
            (2: also the read drain, i.e. a second Ctrl-C).
        stale_after_window: bytes arriving after the banner window (after the first
            `reset_input`); reported by `pending_input`, returned by `read_until`.
        timeout_on: line at which the read raises `TransportTimeout`.
        reads_for: line with a list of consecutive reads `(data, timeout)` that
            replace the response (e.g. `7F xx 78` in consecutive windows and the drain).
        rpm: engine 01 speed at start (response to `22 F40C` to 7E0); 0 means engine off.
        rpm_on: engine speed changes when a line is written; the key is a line (first occurrence)
            or a pair (line, occurrence number from 1).
        atrv_running: response to `ATRV` at an engine speed of at least 400 (alternator charging).
        uds_on: UDS responses for a pair (`STPX` line, occurrence number from 1); they take
            precedence over `uds` (e.g. a different response in a step repeat).

    `interrupt_on` also accepts a pair (line, write occurrence number).
    """

    url: str = "carsim://a6-c7"
    can_set_baudrate: bool = False

    def __init__(
        self,
        catalog: EcuCatalog,
        clock: FakeClock | None = None,
        *,
        adapter: Mapping[str, str] | None = None,
        uds: Mapping[tuple[str, str], Any] | None = None,
        interrupt_on: str | tuple[str, int] | None = None,
        interrupts: int = 1,
        timeout_on: str | None = None,
        stale_after_window: bytes | None = None,
        reads_for: Mapping[str, list[tuple[str, bool]]] | None = None,
        rpm: float = 0.0,
        rpm_on: Mapping[str | tuple[str, int], float] | None = None,
        atrv_running: str = "14.1V",
        uds_on: Mapping[tuple[str, int], Any] | None = None,
    ) -> None:
        self.catalog = catalog
        self.rpm = rpm
        self.rpm_on = {(key, 1) if isinstance(key, str) else key: value for key, value in (rpm_on or {}).items()}
        self.atrv_running = atrv_running
        self.uds_on = dict(uds_on or {})
        self.rpm_log: list[tuple[str, float]] = []
        self._counts: dict[str, int] = {}
        self._interrupt_armed = False
        self.clock = clock
        self.adapter = {**ADAPTER_REPLIES, **(adapter or {})}
        self.uds = {**DEFAULT_UDS, **(uds or {})}
        self.interrupt_on = interrupt_on
        self.timeout_on = timeout_on
        self.reads_for = {line: list(reads) for line, reads in (reads_for or {}).items()}
        self._scripted: list[tuple[str, bool]] = []
        self.lines: list[str] = []
        self.reads: list[str | None] = []
        self.opened = False
        self.closed = False
        self._current: str | None = None
        self._pending: bytes | None = None
        self._interrupts_left = interrupts
        self._stale_after_window = stale_after_window
        self._stale: bytes | None = None
        self._resets = 0

    def open(self) -> None:
        self.opened = True

    def close(self) -> None:
        self.closed = True

    def reset_input(self) -> None:
        self._resets += 1
        # The first flush ends the banner window; late bytes arrive right after it.
        self._stale = self._stale_after_window if self._resets == 1 else None

    def pending_input(self) -> int:
        return len(self._stale) if self._stale else 0

    def set_baudrate(self, baud: int) -> None:
        raise TransportError(f"CarSimTransport does not support changing the baud rate to {baud}")

    def write(self, data: bytes) -> None:
        line = bytes(data).decode("ascii").removesuffix("\r")
        assert "\r" not in line and "\n" not in line, line
        self.lines.append(line)
        self._current = line
        count = self._counts.get(line, 0) + 1
        self._counts[line] = count
        if (line, count) in self.rpm_on:
            self.rpm = self.rpm_on[(line, count)]
        if isinstance(self.interrupt_on, tuple):
            self._interrupt_armed = self.interrupt_on == (line, count)
        else:
            self._interrupt_armed = line == self.interrupt_on
        self._scripted = self.reads_for.pop(line, [])
        self._pending = self._reply(line, count).encode("ascii") + b"\r\r>"

    def read_until(self, marker: bytes, timeout_s: float) -> bytes:
        if self._stale:
            data, self._stale = self._stale, None
            self.reads.append("<stale>")
            return data
        self.reads.append(self._current)
        if self._scripted:
            data, timed_out = self._scripted.pop(0)
            if not self._scripted:
                self._pending = None
            if timed_out:
                raise TransportTimeout(partial=data.encode("ascii"))
            return data.encode("ascii")
        if self._pending is None:
            raise TransportTimeout(partial=b"")
        if self._current == self.timeout_on:
            self._pending = None
            raise TransportTimeout(partial=b"")
        if self._interrupt_armed and self._interrupts_left > 0:
            self._interrupts_left -= 1
            raise KeyboardInterrupt
        data, self._pending = self._pending, None
        return data

    def _reply(self, line: str, count: int = 1) -> str:
        if not line.startswith("STPX "):
            if line == "ATRV" and self.rpm >= 400:
                return self.atrv_running
            return self.adapter.get(line, "OK")
        fields = dict(part.split(":", 1) for part in line[5:].split(","))
        tx, request = fields["H"], fields["D"]
        pair = self.catalog.pair_of(int(tx, 16))
        assert pair is not None, tx
        if self.clock is not None:
            self.clock.advance(0.0345)
        reply = self.uds_on.get((line, count), self.uds.get((tx, request)))
        if reply is None and (tx, request) == ("7E0", "22F40C"):
            self.rpm_log.append((line, self.rpm))
            reply = bytes.fromhex("62F40C") + int(self.rpm * 4).to_bytes(2, "big")
        if reply is None:
            reply = default_positive(request)
        if isinstance(reply, str):
            return reply
        messages = reply if isinstance(reply, list) else [reply]
        return "\r".join(frame for message in messages for frame in isotp_frames(pair[1], message))


# ---------------------------------------------------------------------------
# Helpers


def run_live(transport: CarSimTransport, clock: FakeClock, **kwargs: Any) -> ProbeSession:
    return run_probe_session(
        ProbeMode.LIVE,
        transport,
        CATALOG,
        preflight="interactive",
        argv=["probe", "--execute"],
        clock=clock,
        sleep=clock.sleep,
        now=fixed_now,
        **kwargs,
    )


def markers(session: ProbeSession) -> dict[int, list[dict[str, Any]]]:
    out: dict[int, list[dict[str, Any]]] = {}
    for event in read_events(session.jsonl_path):
        if event["ev"] == "marker" and event["meta"].get("kind") == "probe_step":
            out.setdefault(event["meta"]["step"], []).append(event["meta"])
    return out


def results(session: ProbeSession) -> dict[int, str]:
    return {step.step: step.result for step in session.result.steps}


def probe_doc(session: ProbeSession) -> dict[str, Any]:
    assert session.probe_path is not None
    document = load_yaml(session.probe_path)
    assert isinstance(document, dict)
    return document


class FakeStdin:
    """Operator input: `readline` returns text or raises an exception."""

    def __init__(self, answer: str | type[BaseException], tty: bool = True) -> None:
        self.answer = answer
        self.tty = tty

    def isatty(self) -> bool:
        return self.tty

    def readline(self) -> str:
        if isinstance(self.answer, type):
            raise self.answer()
        return self.answer


# ---------------------------------------------------------------------------
# Tests


@pytest.mark.parametrize(
    ("answer", "tty", "yes", "expected"),
    [
        ("y\n", True, False, "interactive"),
        ("Y\n", True, False, "interactive"),
        ("yes\n", True, False, "interactive"),
        ("YES\n", True, False, "interactive"),
        ("N\n", True, False, None),
        ("\n", True, False, None),
        ("", True, False, None),
        (EOFError, True, False, None),
        (KeyboardInterrupt, True, False, None),
        ("y\n", False, False, None),
        ("", False, True, "yes-flag"),
    ],
)
def test_preflight_answers(
    project_dir: Path, answer: Any, tty: bool, yes: bool, expected: str | None
) -> None:
    stderr = io.StringIO()
    stdin = FakeStdin(answer, tty)
    url = "/dev/cu.usbserial-TEST0001"
    if expected is not None:
        assert confirm(stdin, stderr, yes, url) == expected
        text = stderr.getvalue()
        assert "Checklist before the live probe:" in text
        assert f"to port {url}." in text
        if yes:
            assert "Confirmed with the --yes flag." in text
        return

    factory_calls: list[str] = []

    def factory(target_url: str) -> CarSimTransport:
        factory_calls.append(target_url)
        raise AssertionError("the transport factory must not be called after a refusal")

    with pytest.raises(PreflightAborted) as info:
        execute_probe(CATALOG, factory, url=url, yes=yes, stdin=stdin, stderr=stderr)
    assert info.value.exit_code == 1
    assert factory_calls == []
    assert not (project_dir / "data").exists()
    if not tty:
        assert "No interactive terminal: confirm the checklist with the --yes flag." in str(info.value)
    else:
        assert "Probe aborted by the operator." in str(info.value)


def test_execute_happy_path(project_dir: Path) -> None:
    clock = FakeClock()
    transport = CarSimTransport(CATALOG, clock)
    session = run_live(transport, clock, note="test", odometer_km=123456)

    assert session.exit_code == 0 and session.run_exit_code == 0
    assert session.result.outcome == "completed" and session.result.stop is None
    found = markers(session)
    assert sorted(found) == EXECUTED_ALL
    for number in EXECUTED_ALL:
        phases = [meta["phase"] for meta in found[number]]
        assert phases == ["start", "end"], number
        assert found[number][1]["result"] == results(session)[number]
    assert all(result != "skipped" for result in results(session).values())
    assert results(session)[8] == "ok" and results(session)[11] == "ok"

    events = read_events(session.jsonl_path)
    assert events[0]["meta"]["preflight"] == "interactive"
    assert events[0]["meta"]["mode"] == "live" and events[0]["meta"]["odometer_km"] == 123456
    assert events[-1]["ev"] == "session_end"
    assert events[-1]["meta"]["run_exit_code"] == 0
    assert events[-1]["meta"]["atcs"] == "T:00 R:00"
    snapshot_lines = [line for line in transport.lines if "D:1904" in line]
    assert snapshot_lines == ["STPX H:710,D:190401234501,R:1,T:1500"]
    assert transport.lines[-1] == "STPC" and transport.closed

    assert session.probe_path is not None
    assert session.probe_path.name == f"{session.session_id}.yaml"
    assert "-probe-probe" not in session.probe_path.name
    doc = probe_doc(session)
    assert doc["schema"] == "obdb.probe/1" and doc["mode"] == "live"
    assert doc["exit_code"] == 0 and doc["run_exit_code"] == 0 and doc["outcome"] == "completed"
    assert isinstance(doc["started_at"], str)
    assert datetime.fromisoformat(doc["started_at"]).utcoffset() == timedelta(hours=1)
    assert doc["session_log"] == str(session.jsonl_path)
    assert doc["adapter"]["sti"] == "STN2120 v4.5.0" and doc["adapter"]["voltage_v"] == 12.6
    assert doc["adapter"]["pp"] == {"03": "19", "0C": "68", "2A": "04"}
    assert doc["commands"]["STFCP"] == "unsupported" and doc["commands"]["STCFCPA"] == "ok"
    assert doc["commands"]["STCAFCP"] == "untested"
    assert doc["fc_strategy"] == "st_pairs" and doc["nrc78_mode"] == "same_command"
    timing = doc["timing"]["stpx_22f187_ms"]
    assert timing["n"] == 100 and timing["baud"] == 38400 and timing["p95"] >= timing["p50"] > 0
    assert doc["installation"]["addresses"][:3] == ["01", "02", "03"]
    assert "17" in doc["installation"]["addresses"]
    assert doc["audit"] == {"checked_tx": session.audit.checked_tx, "violations": 0, "guard_rejections": 0}
    assert [entry["step"] for entry in doc["checklist"]] == EXECUTED_ALL
    step12 = next(entry for entry in doc["checklist"] if entry["step"] == 12)
    assert step12["ecu"] == "19" and step12["items"][0]["response"].startswith("62F187")

    profile = AdapterProfile.load_latest("STN2120 v4.5.0", "STN2120 r1.0", project_dir / "data" / "probes")
    assert profile is not None and profile.fc_strategy == "st_pairs"


@pytest.mark.parametrize(
    ("atrv", "fragment"),
    [("12.1V", "Voltage 12.1 V below the threshold 12.4 V"), ("???", "Unreadable ATRV voltage")],
)
def test_low_voltage_warns_and_continues(project_dir: Path, atrv: str, fragment: str) -> None:
    """The 12.4 V threshold temporarily only warns: the probe runs through all steps."""
    clock = FakeClock()
    transport = CarSimTransport(CATALOG, clock, adapter={"ATRV": atrv})
    session = run_live(transport, clock)

    assert session.exit_code == 0 and session.result.outcome == "completed"
    assert session.result.stop is None
    assert [entry["step"] for entry in probe_doc(session)["checklist"]] == EXECUTED_ALL
    assert any(line.startswith("STPX") for line in transport.lines)
    warning = probe_doc(session)["adapter"]["voltage_warning"]
    assert warning is not None and fragment in warning
    assert f"Warning, voltage: {warning}" in report_module.render_run_text(session)


def test_normal_voltage_has_no_warning(project_dir: Path) -> None:
    clock = FakeClock()
    session = run_live(CarSimTransport(CATALOG, clock), clock)

    assert probe_doc(session)["adapter"]["voltage_warning"] is None
    assert "Warning, voltage" not in report_module.render_run_text(session)


def _blocked_payload(monkeypatch: pytest.MonkeyPatch, where: str) -> None:
    """Replaces the function building the step 13 line so that F189 becomes a 0x2E write."""
    write = bytes.fromhex("2EF18900")
    if where == "plan":
        original = plan_module.read_did

        def patched_read_did(did: str) -> bytes:
            return write if did == "F189" else original(did)

        monkeypatch.setattr(plan_module, "read_did", patched_read_did)
    else:
        original_line = driver_module.stpx_line

        def patched_stpx_line(target: Any, payload: bytes, timeout_ms: int | None = None) -> str:
            if bytes(payload) == bytes.fromhex("22F189") and target.vag_address == "19":
                payload = write
            return original_line(target, payload, timeout_ms)

        monkeypatch.setattr(driver_module, "stpx_line", patched_stpx_line)


@pytest.mark.parametrize("where", ["plan", "driver"])
def test_guard_violation_stop(project_dir: Path, monkeypatch: pytest.MonkeyPatch, where: str) -> None:
    _blocked_payload(monkeypatch, where)
    clock = FakeClock()
    transport = CarSimTransport(CATALOG, clock)
    session = run_live(transport, clock)

    assert session.run_exit_code == 2 and session.exit_code == 2
    assert session.result.stop is not None and session.result.stop.step == 13
    assert not any("2EF189" in line for line in transport.lines)
    guard_events = [e for e in read_events(session.jsonl_path) if e["ev"] == "guard"]
    assert len(guard_events) == 1
    assert guard_events[0]["layer"] == ("uds" if where == "plan" else "adapter")
    by_step = results(session)
    assert by_step[13] == "error"
    assert all(by_step[n] == "skipped" for n in [*range(14, 23), 24, 25])
    assert by_step[26] == "ok" and transport.lines[-1] == "STPC"
    assert session.audit.violations == () and session.audit.guard_rejections == 1
    assert probe_doc(session)["exit_code"] == 2


def test_question_mark_on_stpx(project_dir: Path) -> None:
    clock = FakeClock()
    transport = CarSimTransport(CATALOG, clock, uds={("710", "22F187"): "?"})
    session = run_live(transport, clock)

    assert session.exit_code == 3 and session.result.stop is not None
    assert session.result.stop.step == 12
    by_step = results(session)
    assert by_step[12] == "unsupported"
    assert all(by_step[n] == "skipped" for n in [*range(13, 23), 24, 25])
    assert by_step[26] == "ok" and by_step[27] == "ok"
    assert transport.lines[-1] == "STPC"
    # Package D: before step 12 only the engine 01 speed sample, then one gateway STPX.
    assert [line for line in transport.lines if line.startswith("STPX")] == [RPM_LINE, GW_F187]


@pytest.mark.parametrize("kind", ["timeout", "interrupt"])
def test_interruptions(project_dir: Path, kind: str) -> None:
    clock = FakeClock()
    line = "STPX H:710,D:22F189,R:1,T:1500"
    options: dict[str, Any] = {"timeout_on": line} if kind == "timeout" else {"interrupt_on": line}
    transport = CarSimTransport(CATALOG, clock, **options)
    session = run_live(transport, clock)

    by_step = results(session)
    assert session.result.stop is not None and session.result.stop.step == 13
    assert all(by_step[n] == "skipped" for n in [*range(14, 23), 24, 25])
    assert transport.closed
    if kind == "timeout":
        assert session.exit_code == 3 and session.result.outcome == "stopped"
        assert "STPC" not in transport.lines
        assert transport.lines[-1] == line
        assert by_step[26] == "skipped"
    else:
        assert session.exit_code == 4 and session.result.outcome == "aborted"
        assert transport.reads.count(line) == 2  # interrupted read and the drain up to `>`
        # Stage E after draining the current command: step 26 (ATRV, ATCS), then STPC.
        assert transport.lines[-4:] == [line, "ATRV", "ATCS", "STPC"]
        assert by_step[26] == "ok" and by_step[27] == "ok"
        assert session.result.atcs == "T:00 R:00"
    doc = probe_doc(session)
    assert doc["exit_code"] == session.exit_code and doc["outcome"] == session.result.outcome
    assert read_events(session.jsonl_path)[-1]["ev"] == "session_end"


def test_audit_violation_final_code(project_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    writes: list[Path] = []
    original_write = report_module.write_atomic

    def fake_audit(path: Path, catalog: EcuCatalog) -> Any:
        events = read_events(path)
        assert events[-1]["ev"] == "session_end" and events[-1]["meta"]["run_exit_code"] == 0
        assert not (project_dir / "data" / "probes").exists()
        calls.append("audit")
        real = audit_session(path, catalog)
        violation = AuditViolation(seq=1, line="ATSP6", rule="AUDIT/test", reason="injected violation")
        return dataclasses.replace(real, violations=(violation,))

    def spy_write(path: Any, text: str) -> None:
        calls.append("write")
        writes.append(Path(path))
        original_write(path, text)

    monkeypatch.setattr(runner_module, "audit_session", fake_audit)
    monkeypatch.setattr(report_module, "write_atomic", spy_write)
    clock = FakeClock()
    session = run_live(CarSimTransport(CATALOG, clock), clock)

    assert calls == ["audit", "write"]
    assert session.run_exit_code == 0 and session.exit_code == 2
    doc = probe_doc(session)
    assert doc["run_exit_code"] == 0 and doc["exit_code"] == 2 and doc["outcome"] == "completed"
    assert doc["audit"]["violations"] == 1
    assert writes == [session.probe_path]
    assert session.probe_path is not None
    assert list(session.probe_path.parent.iterdir()) == [session.probe_path]
    with pytest.raises(FileExistsError):
        original_write(session.probe_path, "overwrite")
    assert load_yaml(session.probe_path)["exit_code"] == 2


def _item(result: str, pending: int = 0) -> ItemResult:
    return ItemResult(line="STPX H:7E1,D:22F187,R:1", result=result, pending_count=pending)


@pytest.mark.parametrize(
    ("kind", "argument", "expected"),
    [
        ("step", (3, []), "skipped"),
        ("step", (13, ["skipped", "skipped"]), "skipped"),
        ("step", (13, ["ok", "error", "nrc"]), "error"),
        ("step", (3, ["ok", "unsupported"]), "unsupported"),
        ("step", (10, ["ok", "unsupported"]), "unsupported"),
        ("step", (12, ["unsupported"]), "unsupported"),
        ("step", (8, ["ok", "unsupported"]), "ok"),
        ("step", (13, ["ok", "unsupported"]), "ok"),
        ("step", (14, ["ok", "nrc"]), "ok"),
        ("step", (18, ["no_data", "pending_unresolved", "nrc"]), "pending_unresolved"),
        ("step", (18, ["no_data", "nrc"]), "nrc"),
        ("step", (19, ["no_data", "no_data", "skipped"]), "no_data"),
        ("nrc78", [_item("ok"), _item("nrc")], "unknown"),
        ("nrc78", [_item("ok", pending=1), _item("ok")], "same_command"),
        ("nrc78", [_item("ok", pending=2), _item("pending_unresolved", pending=3)], "needs_r2"),
        ("rank", ([float(n) for n in range(1, 101)], 95), 95.0),
        ("rank", ([30.0, 10.0, 20.0], 95), 30.0),
        ("rank", ([30.0, 10.0, 20.0, 40.0], 50), 20.0),
        ("rank", ([5.0], 95), 5.0),
    ],
)
def test_step_classification(kind: str, argument: Any, expected: Any) -> None:
    function: Callable[..., Any]
    if kind == "step":
        number, items = argument
        assert classify_step(number, items) == expected
    elif kind == "nrc78":
        function = nrc78_mode
        assert function(argument) == expected
    else:
        values, percent = argument
        assert nearest_rank(values, percent) == expected


def test_probe_ignores_stored_profile(project_dir: Path) -> None:
    """FR-22: the probe always starts without a profile; a stored `elm_fallback` profile does not change the FC lines."""
    clock = FakeClock()
    first = run_live(CarSimTransport(CATALOG, clock), clock)
    assert first.exit_code == 0 and first.probe_path is not None
    stored = first.probe_path.read_text(encoding="utf-8").replace(
        "fc_strategy: st_pairs", "fc_strategy: elm_fallback", 1
    )
    assert "fc_strategy: elm_fallback" in stored
    first.probe_path.unlink()
    first.probe_path.write_text(stored, encoding="utf-8")
    profile = AdapterProfile.load_latest("STN2120 v4.5.0", "STN2120 r1.0", project_dir / "data" / "probes")
    assert profile is not None and profile.fc_strategy == "elm_fallback"

    clock = FakeClock()
    transport = CarSimTransport(CATALOG, clock)
    second = run_probe_session(
        ProbeMode.LIVE,
        transport,
        CATALOG,
        preflight="interactive",
        argv=["probe", "--execute"],
        clock=clock,
        sleep=clock.sleep,
        now=lambda: fixed_now() + timedelta(hours=1),
    )
    assert second.exit_code == 0
    assert probe_doc(second)["fc_strategy"] == "st_pairs"
    gateway = CATALOG.get("19")
    pair_line = f"STCFCPA{gateway.tx_id:03X},{gateway.rx_id:03X}"
    assert pair_line in transport.lines
    assert not any(line.startswith("ATFCSH") or line == "ATFCSM1" for line in transport.lines)


# ---------------------------------------------------------------------------
# Fixes after verification (robustness on real hardware)

GW_DTC_LINE = "STPX H:710,D:1902FF,R:1,T:1500"
PENDING_78 = "77A037F1978AAAAAAAA\r"


def test_nrc78_series_extends_deadline(project_dir: Path) -> None:
    clock = FakeClock()
    final = "\r".join(isotp_frames(0x77A, DEFAULT_UDS[("710", "1902FF")])) + "\r\r>"
    transport = CarSimTransport(
        CATALOG, clock, reads_for={GW_DTC_LINE: [(PENDING_78, True), (PENDING_78, True), (final, False)]}
    )
    session = run_live(transport, clock)

    assert session.exit_code == 0 and session.result.outcome == "completed"
    # Step 16 and step 25; three read windows of step 16 without resending the request.
    assert transport.lines.count(GW_DTC_LINE) == 2
    assert transport.reads.count(GW_DTC_LINE) == 4
    step16 = next(entry for entry in probe_doc(session)["checklist"] if entry["step"] == 16)
    assert step16["result"] == "ok" and step16["items"][0]["pending_count"] == 2
    assert results(session)[17] != "skipped"


def test_stpx_timeout_keeps_partial_result(project_dir: Path) -> None:
    clock = FakeClock()
    transport = CarSimTransport(
        CATALOG,
        clock,
        reads_for={GW_DTC_LINE: [(PENDING_78, True), ("", True), ("NO DATA\r\r>", False)]},
    )
    session = run_live(transport, clock)

    assert session.exit_code == 3 and session.result.outcome == "stopped"
    assert session.result.stop is not None and session.result.stop.step == 16
    assert "time limit" in session.result.stop.reason
    by_step = results(session)
    assert all(by_step[n] == "skipped" for n in [*range(17, 23), 24, 25])
    # Read drain successful: stage E with step 26 and STPC.
    assert by_step[26] == "ok" and transport.lines[-3:] == ["ATRV", "ATCS", "STPC"]
    doc = probe_doc(session)
    item = next(entry for entry in doc["checklist"] if entry["step"] == 16)["items"][0]
    assert item["result"] == "error" and item["pending_count"] == 1
    assert item["lines"][0] == PENDING_78.strip() and item["lines"][-1] == "NO DATA"
    assert doc["nrc78_mode"] == "same_command"
    assert session.audit.violations == ()


def test_no_data_on_first_bus_contact(project_dir: Path) -> None:
    clock = FakeClock()
    transport = CarSimTransport(CATALOG, clock, uds={("710", "22F187"): "NO DATA"})
    session = run_live(transport, clock)

    assert session.exit_code == 4 and session.result.outcome == "stopped"
    stop = session.result.stop
    assert stop is not None and stop.step == 12
    assert "the car does not respond" in stop.reason.lower() and "ignition" in stop.reason
    by_step = results(session)
    assert by_step[12] == "no_data"
    assert all(by_step[n] == "skipped" for n in [*range(13, 23), 24, 25])
    assert by_step[26] == "ok" and transport.lines[-1] == "STPC"
    assert [line for line in transport.lines if line.startswith("STPX")] == [RPM_LINE, GW_F187]
    assert probe_doc(session)["stop"]["exit_code"] == 4


def test_adapter_reset_stops_session(project_dir: Path) -> None:
    clock = FakeClock()
    reset_line = "STPX H:710,D:22F189,R:1,T:1500"
    transport = CarSimTransport(CATALOG, clock, uds={("710", "22F189"): "\r\rELM327 v1.3a"})
    session = run_live(transport, clock)

    assert session.exit_code == 3 and session.result.outcome == "stopped"
    stop = session.result.stop
    assert stop is not None and stop.step == 13 and "Adapter reset" in stop.reason
    index = transport.lines.index(reset_line)
    assert transport.lines[index + 1 :] == ["STPC"]  # after a reset only the close
    by_step = results(session)
    assert by_step[13] == "error" and by_step[26] == "skipped"
    errors = [e for e in read_events(session.jsonl_path) if e["ev"] == "error"]
    assert any(e["meta"].get("rule") == "driver/adapter-reset" for e in errors)
    assert session.audit.violations == ()


def test_stpc_result_from_reply(project_dir: Path) -> None:
    clock = FakeClock()
    transport = CarSimTransport(CATALOG, clock, adapter={"STPC": "?"})
    session = run_live(transport, clock)

    step27 = next(entry for entry in probe_doc(session)["checklist"] if entry["step"] == 27)
    assert step27["result"] == "unsupported"
    assert step27["items"][0]["line"] == "STPC" and step27["items"][0]["response"] == "?"


def test_interrupt_in_progress_output(project_dir: Path) -> None:
    clock = FakeClock()
    armed = [True]

    def on_step(step: Any) -> None:
        if step.step == 25 and armed[0]:
            armed[0] = False
            raise KeyboardInterrupt

    session = run_live(CarSimTransport(CATALOG, clock), clock, on_step=on_step)

    assert session.exit_code == 4 and session.result.outcome == "aborted"
    assert session.result.stop is not None and session.result.stop.step == 25
    by_step = results(session)
    assert by_step[25] == "ok" and by_step[26] == "ok" and by_step[27] == "ok"
    assert probe_doc(session)["outcome"] == "aborted"
    assert read_events(session.jsonl_path)[-1]["ev"] == "session_end"


def test_interrupt_during_audit_keeps_files(project_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def interrupted_audit(path: Path, catalog: EcuCatalog) -> Any:
        signal.raise_signal(signal.SIGINT)  # Ctrl-C during the audit
        return audit_session(path, catalog)

    monkeypatch.setattr(runner_module, "audit_session", interrupted_audit)
    clock = FakeClock()
    session = run_live(CarSimTransport(CATALOG, clock), clock)

    assert session.exit_code == 0
    assert session.probe_path is not None and session.probe_path.is_file()
    assert probe_doc(session)["audit"]["violations"] == 0
    assert signal.getsignal(signal.SIGINT) is signal.default_int_handler



# ---------------------------------------------------------------------------
# Package C


def test_late_banner_before_atws_continues(project_dir: Path) -> None:
    """C3: a late banner before `ATWS` in RAW is logged and discarded; the probe continues."""
    clock = FakeClock()
    transport = CarSimTransport(CATALOG, clock, stale_after_window=b"\r\rELM327 v1.3a\r\r>")
    session = run_live(transport, clock)

    assert session.exit_code == 0 and session.result.outcome == "completed"
    assert transport.reads[:2] == [None, "<stale>"]
    found = read_events(session.jsonl_path)
    stale = [e for e in found if e["ev"] == "rx" and (e.get("meta") or {}).get("stale") is True]
    assert len(stale) == 1 and "ELM327" in stale[0]["data"]
    assert session.audit.violations == ()


def test_second_interrupt_skips_second_drain(project_dir: Path) -> None:
    """C5: a second Ctrl-C during the drain closes the port without draining again and without STPC."""
    clock = FakeClock()
    line = "STPX H:710,D:22F189,R:1,T:1500"
    transport = CarSimTransport(CATALOG, clock, interrupt_on=line, interrupts=2)
    session = run_live(transport, clock)

    assert session.exit_code == 4 and session.result.outcome == "aborted"
    assert transport.reads.count(line) == 2  # interrupted read and interrupted drain, no third one
    assert transport.lines[-1] == line and "STPC" not in transport.lines
    assert transport.closed
    by_step = results(session)
    assert by_step[26] == "skipped"
    errors = [e for e in read_events(session.jsonl_path) if e["ev"] == "error"]
    second = [e for e in errors if "while draining" in e["data"]]
    assert len(second) == 1 and second[0]["meta"]["type"] == "KeyboardInterrupt"
    assert read_events(session.jsonl_path)[-1]["ev"] == "session_end"


class _ResetInSegmentation(CarSimTransport):
    """Banner in the response to the step 22 `STPX` (after `STCSEGR1`)."""

    def write(self, data: bytes) -> None:
        super().write(data)
        if self._current == "STCSEGR1":
            self._armed = True
        elif self._current is not None and self._current.startswith("STPX") and getattr(self, "_armed", False):
            self._armed = False
            self._pending = b"\r\rELM327 v1.3a\r\r>"


def test_reset_in_segmentation_step_no_stcsegr0(project_dir: Path) -> None:
    """C6: after a reset in step 22 the runner does not try `STCSEGR0`; the only line is `STPC`."""
    clock = FakeClock()
    transport = _ResetInSegmentation(CATALOG, clock)
    session = run_live(transport, clock)

    assert session.exit_code == 3 and session.result.stop is not None
    assert session.result.stop.step == 22
    index = transport.lines.index("STCSEGR1")
    assert transport.lines[index + 2 :] == ["STPC"]
    step22 = next(entry for entry in probe_doc(session)["checklist"] if entry["step"] == 22)
    assert [item["line"] for item in step22["items"]][-1].startswith("STPX")
    assert not any(item["line"] == "STCSEGR0" for item in step22["items"])
    errors = [e for e in read_events(session.jsonl_path) if e["ev"] == "error"]
    assert not any("STCSEGR0" in e["data"] for e in errors)


@pytest.mark.parametrize("where", ["raw", "target"])
def test_reset_stop_reason_mentions_stpc_only_when_open(project_dir: Path, where: str) -> None:
    """C7: the stop reason after a reset does not claim that STPC closed the session when the protocol was not open."""
    clock = FakeClock()
    if where == "raw":
        transport = CarSimTransport(CATALOG, clock, adapter={"ATE0": "\r\rELM327 v1.3a"})
    else:
        transport = CarSimTransport(CATALOG, clock, uds={("710", "22F189"): "\r\rELM327 v1.3a"})
    session = run_live(transport, clock)

    stop = session.result.stop
    assert session.exit_code == 3 and stop is not None and "Adapter reset" in stop.reason
    assert "closed by STPC" not in stop.reason
    if where == "raw":
        assert stop.step == 3 and "STPC" not in transport.lines
        assert "without STPC" in stop.reason
    else:
        assert transport.lines[-1] == "STPC"
        assert "only STPC" in stop.reason


def test_deferred_interrupt_reported(project_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """C8: Ctrl-C deferred during the audit is counted in `ProbeSession.deferred_interrupts`."""
    def interrupted_audit(path: Path, catalog: EcuCatalog) -> Any:
        signal.raise_signal(signal.SIGINT)
        return audit_session(path, catalog)

    monkeypatch.setattr(runner_module, "audit_session", interrupted_audit)
    clock = FakeClock()
    session = run_live(CarSimTransport(CATALOG, clock), clock)
    assert session.exit_code == 0 and session.deferred_interrupts == 1

    clock = FakeClock()
    monkeypatch.setattr(runner_module, "audit_session", audit_session)
    quiet = run_probe_session(
        ProbeMode.LIVE,
        CarSimTransport(CATALOG, clock),
        CATALOG,
        preflight="interactive",
        clock=clock,
        sleep=clock.sleep,
        now=lambda: fixed_now() + timedelta(hours=1),
    )
    assert quiet.deferred_interrupts == 0


# ---------------------------------------------------------------------------
# Package D: engine state, start-stop and voltage at each module

RPM_LINE = "STPX H:7E0,D:22F40C,R:1"
GW_F187 = "STPX H:710,D:22F187,R:1,T:1500"
TCU_F191 = "STPX H:7E1,D:22F191,R:1"
ECM_F186 = "STPX H:7E0,D:22F186,R:1"
SAMPLE_STEPS: list[int] = [*range(12, 23), 24, 25, 26]
"""Steps with an engine state sample: before each module step and once in stage E (step 26)."""


def checklist(session: ProbeSession) -> list[dict[str, Any]]:
    return probe_doc(session)["checklist"]


def engine_doc(session: ProbeSession) -> dict[str, Any]:
    return probe_doc(session)["engine"]


def warning_kinds(session: ProbeSession) -> list[str]:
    return [entry["kind"] for entry in probe_doc(session)["warnings"]]


def test_engine_off_whole_probe(project_dir: Path) -> None:
    """D1: engine off throughout: samples before the modules and in stage E, no repeats and no warnings."""
    clock = FakeClock()
    transport = CarSimTransport(CATALOG, clock)
    session = run_live(transport, clock)

    assert session.exit_code == 0 and session.result.outcome == "completed"
    entries = checklist(session)
    assert [entry["step"] for entry in entries] == EXECUTED_ALL
    assert all(entry["repeat_of"] is None and entry["engine_event"] is None for entry in entries)
    engine = engine_doc(session)
    assert [sample["step"] for sample in engine["samples"]] == SAMPLE_STEPS
    assert {sample["state"] for sample in engine["samples"]} == {"off"}
    assert all(sample["rpm"] == 0.0 and sample["voltage_v"] == 12.6 for sample in engine["samples"])
    assert engine["repeated"] == [] and engine["missing_running"] == []
    assert probe_doc(session)["warnings"] == []
    assert "Warning" not in report_module.render_run_text(session)
    assert transport.lines.count(RPM_LINE) == len(SAMPLE_STEPS)

    # The first sample right after opening the protocol and the gateway FC pair (step 11), before step 12.
    first = transport.lines.index(RPM_LINE)
    assert transport.lines[first - 5 : first + 1] == [
        "ATRV", "ATSH7E0", "ATCRA7E8", "STCFCPA7E0,7E8", "STFFCA7E8,7FF", RPM_LINE,
    ]
    assert transport.lines[first - 6] == "STFFCA77A,7FF"
    assert transport.lines[first + 1 : first + 4] == ["ATSH710", "ATCRA77A", "STPX H:710,D:22F187,R:1,T:1500"]

    sample_markers = [
        event["meta"] for event in read_events(session.jsonl_path)
        if event["ev"] == "marker" and event["meta"].get("kind") == "engine_sample"
    ]
    assert [meta["step"] for meta in sample_markers if meta["phase"] == "end"] == SAMPLE_STEPS
    assert {meta["result"] for meta in sample_markers if meta["phase"] == "end"} == {"off"}
    assert session.audit.violations == () and session.audit.guard_rejections == 0


def test_engine_running_whole_probe(project_dir: Path) -> None:
    """D2: engine running throughout with 14.1 V charging: state running, no repeats and no warnings."""
    clock = FakeClock()
    transport = CarSimTransport(CATALOG, clock, rpm=780.0)
    session = run_live(transport, clock)

    assert session.exit_code == 0 and session.result.outcome == "completed"
    assert [entry["step"] for entry in checklist(session)] == EXECUTED_ALL
    engine = engine_doc(session)
    assert {sample["state"] for sample in engine["samples"]} == {"running"}
    assert all(sample["rpm"] == 780.0 and sample["voltage_v"] == 14.1 for sample in engine["samples"])
    assert probe_doc(session)["warnings"] == []
    assert probe_doc(session)["adapter"]["voltage_warning"] is None


def test_engine_start_during_module_repeats_once(project_dir: Path) -> None:
    """D3: engine start during step 17: result marked, one repeat with the engine running."""
    clock = FakeClock()
    transport = CarSimTransport(CATALOG, clock, rpm_on={TCU_F191: 780.0})
    session = run_live(transport, clock)

    assert session.exit_code == 0 and session.result.outcome == "completed"
    entries = checklist(session)
    order = [entry["step"] for entry in entries]
    assert order == [*range(1, 9), *range(10, 18), 17, *range(18, 23), 24, 25, 26, 27]
    original, repeat = entries[order.index(17)], entries[order.index(17) + 1]
    assert original["engine_event"] == "engine state change: off -> running"
    assert original["repeat_of"] is None and original["result"] == "ok"
    assert repeat["repeat_of"] == 17 and repeat["engine_event"] is None and repeat["result"] == "ok"
    assert [item["line"] for item in repeat["items"]][:2] == ["ATSH7E1", "ATCRA7E9"]
    assert transport.lines.count(TCU_F191) == 2
    engine = engine_doc(session)
    assert engine["repeated"] == [17] and engine["missing_running"] == []
    after = [sample for sample in engine["samples"] if sample["after_repeat"] == 17]
    assert len(after) == 1 and after[0]["state"] == "running" and after[0]["step"] == 18
    assert warning_kinds(session) == ["engine_event"]
    progress = [report_module.format_progress(step) for step in session.result.steps]
    assert "Step 17 (C, repeat): ok" in progress
    assert "Warning, engine: Step 17: engine state change: off -> running" in report_module.render_run_text(session)
    assert session.audit.violations == () and session.audit.guard_rejections == 0


def test_engine_stop_and_restart_repeats(project_dir: Path) -> None:
    """D4: start-stop: engine stops in step 17, starts in step 18; both entries repeated after step 18."""
    clock = FakeClock()
    transport = CarSimTransport(CATALOG, clock, rpm=780.0, rpm_on={TCU_F191: 0.0, ECM_F186: 780.0})
    session = run_live(transport, clock)

    assert session.exit_code == 0 and session.result.outcome == "completed"
    entries = checklist(session)
    order = [entry["step"] for entry in entries]
    assert order == [*range(1, 9), *range(10, 19), 17, 18, *range(19, 23), 24, 25, 26, 27]
    events = {(entry["step"], entry["repeat_of"]): entry["engine_event"] for entry in entries if entry["step"] in (17, 18)}
    assert events == {
        (17, None): "engine state change: running -> off",
        (18, None): "engine state change: off -> running",
        (17, 17): None,
        (18, 18): None,
    }
    engine = engine_doc(session)
    assert engine["repeated"] == [17, 18] and engine["missing_running"] == []
    assert warning_kinds(session) == ["engine_event", "engine_event"]


def test_engine_stop_without_restart_warns(project_dir: Path) -> None:
    """D5: engine stops in step 17 without a restart: no repeat, warning about a missing measurement."""
    clock = FakeClock()
    transport = CarSimTransport(CATALOG, clock, rpm=780.0, rpm_on={TCU_F191: 0.0})
    session = run_live(transport, clock)

    assert session.exit_code == 0 and session.result.outcome == "completed"
    entries = checklist(session)
    assert [entry["step"] for entry in entries] == EXECUTED_ALL
    step17 = next(entry for entry in entries if entry["step"] == 17)
    assert step17["engine_event"] == "engine state change: running -> off"
    assert all(entry["engine_event"] is None for entry in entries if entry["step"] != 17)
    assert transport.lines.count(TCU_F191) == 1
    engine = engine_doc(session)
    assert engine["repeated"] == [] and engine["missing_running"] == [17]
    assert warning_kinds(session) == ["engine_event", "engine_no_running"]
    text = report_module.render_run_text(session)
    assert "Warning, engine: Step 17: no module measurement with the engine running" in text


def test_engine_change_in_repeat_no_second_repeat(project_dir: Path) -> None:
    """D2.4: state change in a repeat: repeat marked, no second repeat, warning about a missing measurement."""
    clock = FakeClock()
    transport = CarSimTransport(CATALOG, clock, rpm_on={(TCU_F191, 1): 780.0, (TCU_F191, 2): 0.0})
    session = run_live(transport, clock)

    assert session.exit_code == 0
    entries = [entry for entry in checklist(session) if entry["step"] == 17]
    assert [(entry["repeat_of"], entry["engine_event"]) for entry in entries] == [
        (None, "engine state change: off -> running"),
        (17, "engine state change: running -> off"),
    ]
    assert transport.lines.count(TCU_F191) == 2
    engine = engine_doc(session)
    assert engine["repeated"] == [17] and engine["missing_running"] == [17]
    assert warning_kinds(session) == ["engine_event", "engine_no_running"]


def test_interrupt_in_repeat_like_normal_step(project_dir: Path) -> None:
    """D2.5: Ctrl-C in a repeat: command drained, stage E without a sample, code 4."""
    clock = FakeClock()
    transport = CarSimTransport(CATALOG, clock, rpm_on={TCU_F191: 780.0}, interrupt_on=(TCU_F191, 2))
    session = run_live(transport, clock)

    assert session.exit_code == 4 and session.result.outcome == "aborted"
    stop = session.result.stop
    assert stop is not None and stop.step == 17
    entries = checklist(session)
    repeat = [entry for entry in entries if entry["repeat_of"] == 17]
    assert len(repeat) == 1 and repeat[0]["result"] == "error"
    later = {entry["step"]: entry["result"] for entry in entries if entry["repeat_of"] is None}
    assert all(later[n] == "skipped" for n in [*range(18, 23), 24, 25])
    assert transport.lines[-4:] == [TCU_F191, "ATRV", "ATCS", "STPC"]
    assert engine_doc(session)["missing_running"] == [17]
    assert read_events(session.jsonl_path)[-1]["ev"] == "session_end"


def test_low_charging_voltage_warns_once(project_dir: Path) -> None:
    """D6: engine running, voltage 12.9 V: one 13.2 V warning (alternator), probe complete."""
    clock = FakeClock()
    warnings: list[str] = []
    transport = CarSimTransport(CATALOG, clock, rpm=780.0, atrv_running="12.9V")
    session = run_live(transport, clock, on_warning=lambda warning: warnings.append(report_module.format_warning(warning)))

    assert session.exit_code == 0 and session.result.outcome == "completed"
    assert probe_doc(session)["adapter"]["voltage_warning"] is None  # 12.9 V in step 5 is not below 12.4 V
    assert warning_kinds(session) == ["charging_low"]
    (message,) = [entry["message"] for entry in probe_doc(session)["warnings"]]
    assert "12.9 V" in message and "13.2 V" in message and "the alternator may not be charging" in message
    assert warnings == [f"Warning, voltage: {message}"]
    assert report_module.render_run_text(session).count("the alternator may not be charging") == 1


def test_low_voltage_engine_off_warns_once(project_dir: Path) -> None:
    """D6: voltage 12.1 V with the engine off: warning from step 5, the samples do not repeat it."""
    clock = FakeClock()
    warnings: list[str] = []
    transport = CarSimTransport(CATALOG, clock, adapter={"ATRV": "12.1V"})
    session = run_live(transport, clock, on_warning=lambda warning: warnings.append(report_module.format_warning(warning)))

    assert session.exit_code == 0
    assert warning_kinds(session) == ["voltage_low"]
    assert probe_doc(session)["warnings"][0]["step"] == 5
    assert warnings == [f"Warning, voltage: {probe_doc(session)['adapter']['voltage_warning']}"]


@pytest.mark.parametrize("reply", ["NO DATA", bytes.fromhex("7F2231")], ids=["no_data", "nrc"])
def test_engine_rpm_without_answer_is_unknown(project_dir: Path, reply: Any) -> None:
    """D7, I1: no engine speed read in any sample: state unknown, no stop and no repeats,
    one `engine_unavailable` warning (stderr once, summary, probe file)."""
    clock = FakeClock()
    printed: list[str] = []
    transport = CarSimTransport(CATALOG, clock, uds={("7E0", "22F40C"): reply})
    session = run_live(transport, clock, on_warning=lambda warning: printed.append(report_module.format_warning(warning)))

    assert session.exit_code == 0 and session.result.outcome == "completed"
    assert [entry["step"] for entry in checklist(session)] == EXECUTED_ALL
    engine = engine_doc(session)
    assert {sample["state"] for sample in engine["samples"]} == {"unknown"}
    assert all(sample["rpm"] is None for sample in engine["samples"])
    assert engine["repeated"] == [] and engine["missing_running"] == []
    assert warning_kinds(session) == ["engine_unavailable"]
    (warning,) = probe_doc(session)["warnings"]
    assert warning["step"] == 26
    assert "Engine state detection inactive" in warning["message"]
    assert "does not report engine speed" in warning["message"]
    assert printed == [f"Warning, engine: {warning['message']}"]
    assert report_module.render_run_text(session).count("Engine state detection inactive") == 1
    assert transport.lines.count(RPM_LINE) == len(SAMPLE_STEPS)


@pytest.mark.parametrize(
    ("rpm", "state"),
    [(0.0, "off"), (0.25, "cranking"), (399.75, "cranking"), (400.0, "running"), (780.0, "running")],
)
def test_engine_state_thresholds(rpm: float, state: str) -> None:
    from obd_bridge.probe.engine import decode_rpm, engine_state

    raw = int(rpm * 4).to_bytes(2, "big")
    assert decode_rpm(raw) == rpm
    assert engine_state(decode_rpm(raw)) == state
    assert decode_rpm(None) is None and decode_rpm(b"\x01") is None
    assert engine_state(None) == "unknown"


def test_checklist_engine_item() -> None:
    """D4: checklist item 3 allows an engine started before the probe; item 5 gives both thresholds."""
    from obd_bridge.probe.preflight import checklist_text

    lines = checklist_text("socket://127.0.0.1:1").splitlines()
    assert lines[3] == (
        "  3. Ignition on; engine off or started before the probe "
        "(do not start the engine during the probe)."
    )
    assert lines[5].startswith("  5. ") and "12.4 V" in lines[5] and "13.2 V" in lines[5]
    assert "it does not stop" in lines[5]


def test_timeout_in_sample_stops_like_step(project_dir: Path) -> None:
    """D1: an engine speed read timeout in the sample before step 12 behaves as in a step: stop with code 3, step 12 `error`."""
    clock = FakeClock()
    transport = CarSimTransport(CATALOG, clock, timeout_on=RPM_LINE)
    session = run_live(transport, clock)

    assert session.exit_code == 3 and session.result.outcome == "stopped"
    stop = session.result.stop
    assert stop is not None and stop.step == 12 and "time limit" in stop.reason
    entries = checklist(session)
    step12 = next(entry for entry in entries if entry["step"] == 12)
    assert step12["result"] == "error" and step12["items"][-1]["line"] == RPM_LINE
    assert all(entry["result"] == "skipped" for entry in entries if entry["step"] in [*range(13, 23), 24, 25])
    # The adapter did not return to the prompt: no further lines, step 26 skipped, no STPC.
    assert transport.lines[-1] == RPM_LINE and "STPC" not in transport.lines
    assert len(engine_doc(session)["samples"]) == 1 and engine_doc(session)["samples"][0]["state"] == "unknown"
    assert session.audit.violations == ()


# ---------------------------------------------------------------------------
# Package D: fixes after code review (W1, W2, I1 to I4)

GW_2A2A = "STPX H:710,D:222A2A,R:1,T:1500"
TCU_F187 = "STPX H:7E1,D:22F187,R:1"
TCU_190A = "STPX H:7E1,D:190A,R:1"
ENGINE_FC_PAIR = "STCFCPA7E0,7E8"
ENGINE_FC_FILTER = "STFFCA7E8,7FF"
INTERRUPTED = "Interrupted by the operator (Ctrl-C)."


def raise_interrupt(warning: Any) -> None:
    raise KeyboardInterrupt


def test_engine_start_in_step12_repeat_without_first_contact_stop(project_dir: Path) -> None:
    """D2: engine start in step 12: one repeat; NO DATA in the repeat is not a first-contact condition (code 0)."""
    clock = FakeClock()
    transport = CarSimTransport(CATALOG, clock, rpm_on={GW_F187: 780.0}, uds_on={(GW_F187, 2): "NO DATA"})
    session = run_live(transport, clock)

    assert session.exit_code == 0 and session.result.outcome == "completed" and session.result.stop is None
    entries = checklist(session)
    order = [entry["step"] for entry in entries]
    assert order == [*range(1, 9), 10, 11, 12, 12, *range(13, 23), 24, 25, 26, 27]
    original, repeat = entries[order.index(12)], entries[order.index(12) + 1]
    assert original["result"] == "ok" and original["engine_event"] == "engine state change: off -> running"
    assert repeat["repeat_of"] == 12 and repeat["result"] == "no_data"
    assert transport.lines.count(GW_F187) == 2
    assert engine_doc(session)["repeated"] == [12] and engine_doc(session)["missing_running"] == []
    assert session.audit.violations == () and session.audit.guard_rejections == 0


def test_interrupt_in_final_sample_records_step26_error(project_dir: Path) -> None:
    """W2: Ctrl-C in the stage E sample: error item in step 26, aborted, code 4, read drain and STPC."""
    clock = FakeClock()
    transport = CarSimTransport(CATALOG, clock, interrupt_on=(RPM_LINE, len(SAMPLE_STEPS)))
    session = run_live(transport, clock)

    assert session.exit_code == 4 and session.result.outcome == "aborted"
    stop = session.result.stop
    assert stop is not None and stop.step == 26 and stop.reason == INTERRUPTED
    entries = checklist(session)
    assert [entry["step"] for entry in entries] == EXECUTED_ALL
    step26 = next(entry for entry in entries if entry["step"] == 26)
    assert step26["result"] == "error"
    assert step26["items"][0]["line"] == RPM_LINE and step26["items"][0]["error"] == INTERRUPTED
    assert [item["line"] for item in step26["items"][1:]] == ["ATRV", "ATCS"]
    assert all(entry["result"] == "ok" for entry in entries if entry["step"] in STAGE_BCD)
    assert transport.lines[-4:] == [RPM_LINE, "ATRV", "ATCS", "STPC"]
    assert session.audit.violations == ()


def test_interrupt_in_on_warning_step5_records_error(project_dir: Path) -> None:
    """W2: Ctrl-C in `on_warning` in step 5: error item in step 5, aborted, code 4."""
    clock = FakeClock()
    transport = CarSimTransport(CATALOG, clock, adapter={"ATRV": "12.1V"})
    session = run_live(transport, clock, on_warning=raise_interrupt)

    assert session.exit_code == 4 and session.result.outcome == "aborted"
    stop = session.result.stop
    assert stop is not None and stop.step == 5 and stop.reason == INTERRUPTED
    entries = {entry["step"]: entry for entry in checklist(session)}
    assert entries[5]["result"] == "error"
    assert [item["line"] for item in entries[5]["items"]] == ["ATRV", "STVR", ""]
    assert entries[5]["items"][-1]["error"] == INTERRUPTED
    assert all(entries[n]["result"] == "skipped" for n in [6, 7, 8, *STAGE_BCD])
    assert warning_kinds(session) == ["voltage_low"]


def test_interrupt_in_on_warning_engine_event_records_error(project_dir: Path) -> None:
    """W2: Ctrl-C in `on_warning` on a state change (sample before step 18): step 18 error, not skipped."""
    clock = FakeClock()

    def interrupt_engine(warning: Any) -> None:
        if warning.kind == "engine_event":
            raise KeyboardInterrupt

    transport = CarSimTransport(CATALOG, clock, rpm_on={TCU_F191: 780.0})
    session = run_live(transport, clock, on_warning=interrupt_engine)

    assert session.exit_code == 4 and session.result.outcome == "aborted"
    stop = session.result.stop
    assert stop is not None and stop.step == 18
    entries = {(entry["step"], entry["repeat_of"]): entry for entry in checklist(session)}
    assert entries[(18, None)]["result"] == "error"
    assert entries[(18, None)]["items"][-1]["error"] == INTERRUPTED
    assert (17, 17) not in entries
    assert all(entries[(n, None)]["result"] == "skipped" for n in [*range(19, 23), 24, 25])


@pytest.mark.parametrize("drained", [True, False], ids=["drained", "no_drain"])
def test_rpm_timeout_in_sample(project_dir: Path, drained: bool) -> None:
    """I2: engine speed read timeout: after a successful drain state unknown and the probe continues; without a drain stop with code 3."""
    clock = FakeClock()
    drain = ("NO DATA\r\r>", False) if drained else ("", True)
    transport = CarSimTransport(CATALOG, clock, reads_for={RPM_LINE: [("", True), drain]})
    session = run_live(transport, clock)

    samples = engine_doc(session)["samples"]
    assert samples[0]["step"] == 12 and samples[0]["state"] == "unknown" and samples[0]["rpm"] is None
    assert any(event["ev"] == "error" for event in read_events(session.jsonl_path))
    if drained:
        assert session.exit_code == 0 and session.result.outcome == "completed"
        assert [entry["step"] for entry in checklist(session)] == EXECUTED_ALL
        assert results(session)[12] == "ok"
        assert [sample["state"] for sample in samples[1:]] == ["off"] * (len(SAMPLE_STEPS) - 1)
        # After the sample with a timeout: gateway reselected in the sample, then F187 of step 12.
        first = transport.lines.index(RPM_LINE)
        assert transport.lines[first + 1 : first + 4] == ["ATSH710", "ATCRA77A", GW_F187]
        assert warning_kinds(session) == []
        assert transport.lines[-1] == "STPC"
    else:
        assert session.exit_code == 3 and session.result.outcome == "stopped"
        stop = session.result.stop
        assert stop is not None and stop.step == 12 and "time limit" in stop.reason
        assert results(session)[12] == "error" and len(samples) == 1
        assert transport.lines[-1] == RPM_LINE and "STPC" not in transport.lines
    assert session.audit.violations == () and session.audit.guard_rejections == 0


@pytest.mark.parametrize(
    ("adapter", "failed_line"),
    [({ENGINE_FC_PAIR: "?"}, ENGINE_FC_PAIR), ({ENGINE_FC_FILTER: "STOPPED"}, ENGINE_FC_FILTER)],
    ids=["pair_unsupported", "filter_error"],
)
def test_engine_fc_failure_single_attempt(project_dir: Path, adapter: dict[str, str], failed_line: str) -> None:
    """I3: failed engine FC configuration in the first sample: no further attempts in samples,
    following samples ATRV only, state unknown, one `engine_unavailable` warning."""
    clock = FakeClock()
    printed: list[str] = []
    transport = CarSimTransport(CATALOG, clock, adapter=adapter)
    session = run_live(transport, clock, on_warning=lambda warning: printed.append(report_module.format_warning(warning)))

    assert session.exit_code == 0 and session.result.outcome == "completed"
    lines = transport.lines
    # One attempt in the sample (before step 12) and the own attempt of step 18, as before package D.
    assert ECM_F186 not in lines
    assert lines.count(ENGINE_FC_PAIR) == 2 and lines.count("ATSH7E0") == 2
    first = lines.index(ENGINE_FC_PAIR)
    assert lines[first - 3 : first] == ["ATRV", "ATSH7E0", "ATCRA7E8"]
    if failed_line == ENGINE_FC_FILTER:
        assert lines[first + 1] == ENGINE_FC_FILTER
    assert RPM_LINE not in lines
    # The sample with an error ends by reselecting the gateway; the following samples are ATRV only.
    assert lines[lines.index(failed_line) + 1 : lines.index(failed_line) + 4] == ["ATSH710", "ATCRA77A", GW_F187]
    gw_ident = "STPX H:710,D:22F189,R:1,T:1500"
    assert lines[lines.index(gw_ident) - 2 : lines.index(gw_ident)] == [GW_F187, "ATRV"]
    samples = engine_doc(session)["samples"]
    assert [sample["step"] for sample in samples] == SAMPLE_STEPS
    assert {sample["state"] for sample in samples} == {"unknown"}
    assert all(sample["voltage_v"] == 12.6 for sample in samples)
    by_step = results(session)
    assert by_step[18] == "error"
    assert all(by_step[n] == "ok" for n in [*range(12, 18), *range(19, 23), 24, 25, 26])
    assert warning_kinds(session) == ["engine_unavailable"]
    (warning,) = probe_doc(session)["warnings"]
    assert warning["step"] == 12 and failed_line in warning["message"]
    assert "Engine state detection inactive" in warning["message"]
    assert printed == [f"Warning, engine: {warning['message']}"]
    assert session.audit.violations == () and session.audit.guard_rejections == 0


def test_repeat_does_not_override_installation(project_dir: Path) -> None:
    """W1: repeat of step 15 with a different 2A2A list: `installation` from the original, repeat data only in its entry."""
    clock = FakeClock()
    other = bytes([0x01, 0x44]) + bytes(78)
    transport = CarSimTransport(
        CATALOG, clock, rpm_on={GW_2A2A: 780.0}, uds_on={(GW_2A2A, 2): bytes.fromhex("622A2A") + other}
    )
    session = run_live(transport, clock)

    assert session.exit_code == 0
    doc = probe_doc(session)
    assert doc["installation"]["addresses"] == ["01", "02", "03", "17", "19", "34", "5F", "09"]
    assert "44" not in doc["installation"]["not_in_catalog"]
    repeat = next(entry for entry in doc["checklist"] if entry["repeat_of"] == 15)
    assert repeat["items"][0]["response"] == ("622A2A" + other.hex()).upper()


def test_repeat_does_not_override_stcsegr1_lines(project_dir: Path) -> None:
    """W1: repeat of step 22 with a different response: `stcsegr1_lines` from the original."""
    clock = FakeClock()
    transport = CarSimTransport(
        CATALOG,
        clock,
        rpm_on={(TCU_F187, 2): 780.0},
        uds_on={(TCU_F187, 3): bytes.fromhex("62F187") + b"REPEAT"},
    )
    session = run_live(transport, clock)

    assert session.exit_code == 0
    doc = probe_doc(session)
    assert engine_doc(session)["repeated"] == [22]
    original = next(entry for entry in doc["checklist"] if entry["step"] == 22 and entry["repeat_of"] is None)
    repeat = next(entry for entry in doc["checklist"] if entry["repeat_of"] == 22)
    original_lines = next(item["lines"] for item in original["items"] if item["line"] == TCU_F187)
    repeat_lines = next(item["lines"] for item in repeat["items"] if item["line"] == TCU_F187)
    assert original_lines != repeat_lines
    assert doc["stcsegr1_lines"] == original_lines
    # `timing` still only from the original of step 24 (100 reads).
    assert doc["timing"]["stpx_22f187_ms"]["n"] == 100


def test_repeat_does_not_change_nrc78_mode(project_dir: Path) -> None:
    """W1: 7F 19 78 only in the repeat of step 25 (in the stage E sample): `nrc78_mode` from the original."""
    clock = FakeClock()
    pending = [bytes.fromhex("7F1978"), bytes.fromhex("590AFF")]
    transport = CarSimTransport(
        CATALOG,
        clock,
        uds={("7E1", "190A"): bytes.fromhex("590AFF")},
        rpm_on={(TCU_190A, 2): 780.0},  # occurrence 1: step 17, occurrence 2: step 25
        uds_on={(TCU_190A, 3): pending},
    )
    session = run_live(transport, clock)

    assert session.exit_code == 0
    doc = probe_doc(session)
    assert engine_doc(session)["repeated"] == [25]
    repeat = next(entry for entry in doc["checklist"] if entry["repeat_of"] == 25)
    # The repeat in the stage E sample starts by selecting the transmission (the target after the sample is engine 01).
    assert [item["line"] for item in repeat["items"]][:3] == ["ATSH7E1", "ATCRA7E9", TCU_190A]
    assert next(item for item in repeat["items"] if item["line"] == TCU_190A)["pending_count"] == 1
    assert doc["nrc78_mode"] == "unknown"
    after = [sample for sample in engine_doc(session)["samples"] if sample["after_repeat"] == 25]
    assert len(after) == 1 and after[0]["step"] == 26


def test_replay_live_session_with_repeat(project_dir: Path) -> None:
    """D2: replay of a live session with a repeat: the same lines on the wire, all events consumed."""
    from obd_bridge.transport.replay import ReplayTransport

    clock = FakeClock()
    transport = CarSimTransport(CATALOG, clock, rpm_on={TCU_F191: 780.0})
    session = run_live(transport, clock)
    assert engine_doc(session)["repeated"] == [17]

    replay = ReplayTransport(session.jsonl_path)
    clock2 = FakeClock()
    replayed = run_probe_session(
        ProbeMode.LIVE,
        replay,
        CATALOG,
        preflight="interactive",
        argv=["probe"],
        clock=clock2,
        sleep=clock2.sleep,
        now=lambda: fixed_now() + timedelta(hours=2),
    )

    def wire(path: Path) -> list[Any]:
        return [event.get("data") for event in read_events(path) if event["ev"] == "tx" and event["layer"] == "transport"]

    assert wire(replayed.jsonl_path) == wire(session.jsonl_path)
    assert replay.remaining == 0
    assert replayed.exit_code == 0 and replayed.result.engine["repeated"] == [17]
    assert [step.repeat_of for step in replayed.result.steps] == [step.repeat_of for step in session.result.steps]


def test_silent_bus_reason_names_step12() -> None:
    """I4: the silent bus stop reason names the first request of step 12 (the first STPX is the engine speed read)."""
    assert "the first request of step 12" in runner_module._SILENT_BUS
    assert "F187" in runner_module._SILENT_BUS


def test_silent_bus_without_engine_unavailable(project_dir: Path) -> None:
    """I1: silent bus (NO DATA also for the engine speed read): stop with code 4 without an `engine_unavailable` warning."""
    clock = FakeClock()
    transport = CarSimTransport(CATALOG, clock, uds={("710", "22F187"): "NO DATA", ("7E0", "22F40C"): "NO DATA"})
    session = run_live(transport, clock)

    assert session.exit_code == 4 and session.result.stop is not None and session.result.stop.step == 12
    assert [sample["state"] for sample in engine_doc(session)["samples"]] == ["unknown"]
    assert probe_doc(session)["warnings"] == []


def test_engine_rpm_nrc_with_stop_still_warns(project_dir: Path) -> None:
    """I1: an NRC to the engine speed read is a bus response; warning also after a stop (Ctrl-C in step 14)."""
    clock = FakeClock()
    transport = CarSimTransport(
        CATALOG, clock, uds={("7E0", "22F40C"): bytes.fromhex("7F2231")}, interrupt_on="STPX H:710,D:220600,R:1,T:1500"
    )
    session = run_live(transport, clock)

    assert session.exit_code == 4 and session.result.outcome == "aborted"
    assert warning_kinds(session) == ["engine_unavailable"]
    assert probe_doc(session)["warnings"][0]["step"] == 14


def test_interrupt_in_on_warning_engine_fc_failure(project_dir: Path) -> None:
    """W2, I3: Ctrl-C in `on_warning` on a failed engine FC configuration: no further sample lines, step 12 error."""
    clock = FakeClock()
    transport = CarSimTransport(CATALOG, clock, adapter={ENGINE_FC_PAIR: "?"})
    session = run_live(transport, clock, on_warning=raise_interrupt)

    assert session.exit_code == 4 and session.result.outcome == "aborted"
    stop = session.result.stop
    assert stop is not None and stop.step == 12
    step12 = next(entry for entry in checklist(session) if entry["step"] == 12)
    assert step12["result"] == "error"
    assert [item["line"] for item in step12["items"]] == [ENGINE_FC_PAIR, ""]
    assert step12["items"][-1]["error"] == INTERRUPTED
    first = transport.lines.index(ENGINE_FC_PAIR)
    assert transport.lines[first + 1 :] == ["ATRV", "ATCS", "STPC"]
