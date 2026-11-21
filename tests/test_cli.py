"""Tests of the `obdb` CLI layer (spec T11, T9, T10; FR-23, FR-28).

The tests call `obd_bridge.cli.main(argv)` in process and check the exit
code and the streams. No test uses `SerialTransport`: the `--execute` path
runs only with a replaced factory `cli.open_transport`
(the fixture `_block_dev_serial` from `conftest.py` additionally blocks `/dev/*`).
"""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any

import pytest
import typer

from obd_bridge import cli
from obd_bridge.errors import ObdBridgeError
from obd_bridge.transport.null import NullTransport

DETECTED_URL = "/dev/cu.usbserial-TEST0001"
"""Synthetic port returned by the replaced adapter detection."""


class _StopForTest(ObdBridgeError):
    """obd-bridge error with code 4 to check the `exit_code` mapping in `main()`."""

    exit_code = 4


def _run(argv: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str, str]:
    """Run `main(argv)` and return the exit code, stdout and stderr."""
    code = cli.main(argv)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


class _FakeTtyStdin(io.StringIO):
    """Input stream pretending to be a terminal (preflight requires a TTY without `--yes`)."""

    def isatty(self) -> bool:
        return True


class _GatewayNullTransport(NullTransport):
    """`NullTransport` with a gateway response to F187 in step 12.

    The live probe stops with code 4 when the first contact with the bus
    gives `NO DATA`; the gateway response allows checking the full CLI run.
    """

    STPX_REPLIES = {
        "STPX H:710,D:22F187,R:1,T:1500": "77A100E62F187344730\r77A2139303734363841\r77A2220000000000000",
    }

    @staticmethod
    def _reply_for(command: str) -> str:
        reply = _GatewayNullTransport.STPX_REPLIES.get(command)
        return reply if reply is not None else NullTransport._reply_for(command)


@pytest.fixture
def factory_calls(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Replace `cli.open_transport` with a `NullTransport` factory with a gateway response and record the call URLs."""
    calls: list[str] = []

    def fake_open_transport(url: str) -> NullTransport:
        calls.append(url)
        return _GatewayNullTransport()

    monkeypatch.setattr(cli, "open_transport", fake_open_transport)
    monkeypatch.setattr(cli, "detect_transport_url", lambda ctx: DETECTED_URL)
    return calls


@pytest.mark.parametrize(
    "argv",
    [
        ["probe", "--dry-run", "--execute"],
        ["probe", "--yes"],
        ["probe", "--dry-run", "--yes"],
        ["probe", "--transport", "loop://"],
        ["probe", "--dry-run", "--transport", "loop://"],
        ["probe", "--note", "test"],
        ["probe", "--odometer-km", "1000"],
        ["probe", "--dry-run", "--odometer-km", "-1"],
        ["probe", "--dry-run", "--odometer-km", "2000001"],
        ["probe", "--dry-run", "--odometer-km", "abc"],
        ["probe", "--unknown"],
        ["unknown-command"],
        ["audit"],
    ],
    ids=lambda argv: " ".join(argv),
)
def test_usage_errors(
    argv: list[str],
    project_dir: Path,
    factory_calls: list[str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Option conflicts and invalid values give code 64 with the usage error prefix, no files and no port."""
    code, out, err = _run(argv, capsys)
    assert code == 64
    assert err.startswith("Usage error:")
    assert "Help: obdb" in err and "--help" in err
    assert out == ""
    assert factory_calls == []
    assert not (project_dir / "data").exists()


def test_usage_error_class_matches_typer(capsys: pytest.CaptureFixture[str]) -> None:
    """The class caught in `main()` is the one the typer parser raises for an unknown option (code 64, not 3)."""
    command = typer.main.get_command(cli.app)
    with pytest.raises(cli.UsageError) as caught:
        cli._invoke(command, ["probe", "--unknown"])
    assert not isinstance(caught.value, cli.NoArgsIsHelpError)
    assert type(caught.value).__module__.startswith("typer._click")
    with pytest.raises(cli.NoArgsIsHelpError):
        cli._invoke(command, [])

    assert cli.main(["probe", "--unknown"]) == 64
    assert "Usage error:" in capsys.readouterr().err


def test_help_and_no_args(project_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """`--help` and `obdb` without arguments give code 0 and help on stdout."""
    code, out, err = _run(["--help"], capsys)
    assert code == 0
    assert "probe" in out and "audit" in out
    assert err == ""

    code, out, err = _run([], capsys)
    assert code == 0
    assert "probe" in out and "audit" in out
    assert err == ""

    code, out, _ = _run(["probe", "--help"], capsys)
    assert code == 0
    for option in ("--dry-run", "--execute", "--yes", "--transport", "--json", "--note", "--odometer-km"):
        assert option in out
    assert "single connected adapter" in out

    code, out, _ = _run(["audit", "--help"], capsys)
    assert code == 0
    assert "SESSION_JSONL" in out
    assert not (project_dir / "data").exists()


@pytest.mark.parametrize(
    ("raised", "expected_code", "expected_message"),
    [
        (KeyboardInterrupt(), 4, "Interrupted (Ctrl-C)."),
        (EOFError(), 1, "No input data."),
        (_StopForTest("Test stop condition."), 4, "Test stop condition."),
        (RuntimeError("test failure"), 3, "Internal error: RuntimeError: test failure"),
    ],
    ids=["keyboard-interrupt", "eof", "obd-bridge-error", "unexpected"],
)
def test_abort_mapping(
    raised: BaseException,
    expected_code: int,
    expected_message: str,
    project_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Exceptions from outside the runner: `Abort` from `KeyboardInterrupt` (4) and `EOFError` (1), `ObdBridgeError`, internal error (3)."""

    def failing_load() -> Any:
        raise raised

    monkeypatch.setattr(cli, "_load_catalog", failing_load)
    code, _, err = _run(["probe"], capsys)
    assert code == expected_code
    assert expected_message in err


def test_preflight_eof_and_audit_missing(
    project_dir: Path,
    factory_calls: list[str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """EOF in preflight gives code 1 without files and without the factory; audit of a missing file gives 64."""
    monkeypatch.setattr("sys.stdin", _FakeTtyStdin(""))
    code, out, err = _run(["probe", "--execute"], capsys)
    assert code == 1
    assert "Checklist before the live probe:" in err
    assert "Probe aborted by the operator." in err
    assert out == ""
    assert factory_calls == []
    assert not (project_dir / "data").exists()

    code, out, err = _run(["audit", "missing-session.jsonl"], capsys)
    assert code == 64
    assert "missing-session.jsonl" in err
    assert out == ""


def test_plan_without_flags_creates_nothing(project_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Plan without flags: table or `obdb.probe-plan/1`, code 0, no files and no `serial`."""
    code, out, _ = _run(["probe"], capsys)
    assert code == 0
    assert "Stage" in out and "Commands" in out and "STPX" in out

    code, out, _ = _run(["probe", "--json"], capsys)
    assert code == 0
    document = json.loads(out)
    assert document["schema"] == "obdb.probe-plan/1"
    assert document["mode"] == "plan"
    assert document["totals"]["steps"] == len(document["steps"])
    assert sorted(path.name for path in project_dir.iterdir()) == ["defs"]


def test_execute_with_fake_factory(
    project_dir: Path,
    factory_calls: list[str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """`--execute --yes` with a replaced factory: default URL, progress on stderr, probe file, JSON."""
    code, out, err = _run(["probe", "--execute", "--yes", "--json", "--note", "test", "--odometer-km", "12345"], capsys)
    assert factory_calls == [DETECTED_URL]
    assert code == 0
    assert "Confirmed with the --yes flag." in err
    assert "Step 1 (A): ok" in err
    document = json.loads(out)
    assert document["schema"] == "obdb.probe-run/1"
    assert document["exit_code"] == 0
    assert Path(document["probe_path"]).is_file()
    assert Path(document["jsonl_path"]).is_file()

    code, out, _ = _run(["probe", "--execute", "--yes", "--transport", "loop://"], capsys)
    assert factory_calls == [DETECTED_URL, "loop://"]
    assert code == 0
    assert "Probe outcome: completed" in out


def test_audit_cli_codes_on_modified_dry_run(project_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """`obdb audit`: a dry-run log gives 0, a copy with `ATSP6` in `tx` gives 2, a corrupted JSONL gives 64 (T10)."""
    assert cli.main(["probe", "--dry-run", "--json"]) == 0
    original = Path(json.loads(capsys.readouterr().out)["jsonl_path"])
    code, out, _ = _run(["audit", str(original)], capsys)
    assert code == 0 and "Violations: 0" in out

    events = [json.loads(raw) for raw in original.read_text(encoding="utf-8").splitlines()]
    index = next(
        i for i, event in enumerate(events)
        if event["ev"] == "tx" and event["layer"] == "transport" and event["data"].startswith("STPX ")
    )
    assert events[index - 1]["ev"] == "tx" and events[index - 1]["layer"] == "adapter"
    events[index]["data"] = "ATSP6\\r"
    events[index - 1]["data"] = "ATSP6"
    modified = project_dir / "modified.jsonl"
    modified.write_text(
        "".join(json.dumps(event, ensure_ascii=False) + "\n" for event in events), encoding="utf-8"
    )

    code, out, _ = _run(["audit", str(modified)], capsys)
    assert code == 2
    assert "ATSP6" in out and "violations detected (code 2)" in out
    code, out, _ = _run(["audit", "--json", str(modified)], capsys)
    assert code == 2
    violations = json.loads(out)["violations"]
    assert any(
        v["seq"] == events[index]["seq"] and v["line"] == "ATSP6" and v["rule"] == "LINE/no-match"
        for v in violations
    )

    broken = project_dir / "corrupted.jsonl"
    broken.write_text(original.read_text(encoding="utf-8").splitlines()[0] + "\n{invalid json\n", encoding="utf-8")
    code, out, err = _run(["audit", str(broken)], capsys)
    assert code == 64
    assert out == "" and "corrupted.jsonl" in err


def test_audit_cascade_on_modified_dry_run(project_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """One `ATSP6` line in a copy of the dry-run log: the text shows the primary violation and one summary line."""
    assert cli.main(["probe", "--dry-run", "--json"]) == 0
    original = Path(json.loads(capsys.readouterr().out)["jsonl_path"])
    events = [json.loads(raw) for raw in original.read_text(encoding="utf-8").splitlines()]
    index = next(
        i for i, event in enumerate(events)
        if event["ev"] == "tx" and event["layer"] == "transport" and event["data"].startswith("STPX ")
    )
    events[index]["data"] = "ATSP6\\r"
    events[index - 1]["data"] = "ATSP6"
    cause = events[index]["seq"]
    modified = project_dir / "cascade.jsonl"
    modified.write_text(
        "".join(json.dumps(event, ensure_ascii=False) + "\n" for event in events), encoding="utf-8"
    )

    code, out, _ = _run(["audit", "--json", str(modified)], capsys)
    assert code == 2
    violations = json.loads(out)["violations"]
    assert len(violations) > 100
    primary = [v for v in violations if v["caused_by_seq"] is None]
    assert [(v["seq"], v["line"], v["rule"]) for v in primary] == [(cause, "ATSP6", "LINE/no-match")]
    secondary = [v for v in violations if v["caused_by_seq"] is not None]
    assert {v["caused_by_seq"] for v in secondary} == {cause}
    assert {v["rule"] for v in secondary} == {"AUDIT/adapter-config", "AUDIT/state-transition"}
    assert all(v["seq"] > cause for v in secondary)

    code, out, _ = _run(["audit", str(modified)], capsys)
    assert code == 2
    listed = [line for line in out.splitlines() if line.startswith("  seq ")]
    assert listed == [f"  seq {cause} [LINE/no-match] ATSP6: {primary[0]['reason']}"]
    summary = [line for line in out.splitlines() if line.startswith("    and ")]
    assert len(summary) == 1
    # The count depends on the plan length; it is above 100, so the phrase is plural.
    assert summary[0].startswith(f"    and {len(secondary)} secondary violations ")
    assert f"caused by violation seq {cause}" in summary[0]
    assert f"Violations: {len(violations)} (primary: 1, secondary: {len(secondary)})" in out
    assert "violations detected (code 2)" in out


def test_deferred_interrupt_notice_on_stderr(
    project_dir: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """C8: Ctrl-C during the audit gives one message on stderr; code and result unchanged."""
    import signal

    import obd_bridge.probe.runner as runner_module
    from obd_bridge.audit import audit_session

    def interrupted_audit(path: Path, catalog: Any) -> Any:
        signal.raise_signal(signal.SIGINT)
        signal.raise_signal(signal.SIGINT)
        return audit_session(path, catalog)

    monkeypatch.setattr(runner_module, "audit_session", interrupted_audit)
    code, out, err = _run(["probe", "--dry-run"], capsys)
    assert code == 0 and "Dry-run summary:" in out
    assert err.count(runner_module.DEFERRED_INTERRUPT_NOTICE) == 1

    monkeypatch.setattr(runner_module, "audit_session", audit_session)
    code, _, err = _run(["probe", "--dry-run"], capsys)
    assert code == 0 and runner_module.DEFERRED_INTERRUPT_NOTICE not in err


class _RunningEngineNullTransport(_GatewayNullTransport):
    """Package D: engine running (780 rpm) at 12.9 V, that is below the charging threshold of 13.2 V."""

    @staticmethod
    def _reply_for(command: str) -> str:
        if command == "STPX H:7E0,D:22F40C,R:1":
            return "7E80562F40C0C30AAAA"
        if command == "ATRV":
            return "12.9V"
        return _GatewayNullTransport._reply_for(command)


class _LowVoltageNullTransport(_GatewayNullTransport):
    """Package D: engine off (state unknown, NO DATA for RPM) at 12.1 V."""

    @staticmethod
    def _reply_for(command: str) -> str:
        if command == "ATRV":
            return "12.1V"
        return _GatewayNullTransport._reply_for(command)


@pytest.mark.parametrize(
    ("transport", "fragment"),
    [
        (_RunningEngineNullTransport, "the alternator may not be charging"),
        (_LowVoltageNullTransport, "below the threshold 12.4 V"),
    ],
    ids=["charging", "engine_off"],
)
def test_voltage_warning_line_on_stderr_once(
    project_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    transport: type[NullTransport],
    fragment: str,
) -> None:
    """Package D: voltage warning as one line on stderr at detection time, without repetition; also in the summary."""
    monkeypatch.setattr(cli, "open_transport", lambda url: transport())
    code, out, err = _run(["probe", "--execute", "--yes", "--transport", "loop://"], capsys)
    assert code == 0
    warning_lines = [line for line in err.splitlines() if fragment in line]
    assert len(warning_lines) == 1
    assert warning_lines[0].startswith("Warning, voltage: ")
    # The warning line appears during the step progress, not after it.
    lines = err.splitlines()
    assert lines.index(warning_lines[0]) < lines.index("Step 27 (E): ok")
    assert out.count(fragment) == 1 and "Probe outcome: completed" in out


# ---------------------------------------------------------------------------
# Adapter detection for --execute without --transport


@pytest.mark.parametrize(
    ("ports", "expected_code", "fragment"),
    [
        ([], 3, "No USB adapter with an FTDI chip found; connect the adapter or pass --transport."),
        (
            ["/dev/cu.usbserial-TEST0001", "/dev/cu.usbserial-TEST0002"],
            64,
            "several USB adapters with an FTDI chip found (/dev/cu.usbserial-TEST0001, "
            "/dev/cu.usbserial-TEST0002); choose one with --transport.",
        ),
    ],
    ids=["none", "several"],
)
def test_execute_without_single_adapter_stops_before_checklist(
    ports: list[str],
    expected_code: int,
    fragment: str,
    project_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """No adapter (3) or several adapters (64): no checklist, no transport, no files."""
    from obd_bridge.transport import serial_transport

    opened: list[str] = []
    monkeypatch.setattr(serial_transport, "find_adapter_ports", lambda: list(ports))
    monkeypatch.setattr(cli, "open_transport", lambda url: opened.append(url))
    code, out, err = _run(["probe", "--execute", "--yes"], capsys)
    assert code == expected_code
    assert fragment in err
    assert "Checklist before the live probe:" not in err
    assert out == "" and opened == []
    assert not (project_dir / "data").exists()


def test_execute_uses_single_detected_adapter(
    project_dir: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Exactly one FTDI adapter: its port goes to the checklist and to the transport factory."""
    from obd_bridge.transport import serial_transport

    calls: list[str] = []

    def fake_open_transport(url: str) -> NullTransport:
        calls.append(url)
        return _GatewayNullTransport()

    monkeypatch.setattr(serial_transport, "find_adapter_ports", lambda: ["/dev/cu.usbserial-TEST0003"])
    monkeypatch.setattr(cli, "open_transport", fake_open_transport)
    code, _, err = _run(["probe", "--execute", "--yes"], capsys)
    assert code == 0
    assert calls == ["/dev/cu.usbserial-TEST0003"]
    assert "to port /dev/cu.usbserial-TEST0003." in err


def test_explicit_transport_skips_detection(
    project_dir: Path, factory_calls: list[str], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """With --transport the adapter detection is never called."""

    def refused(ctx: Any) -> str:
        raise AssertionError("detection must not run with --transport")

    monkeypatch.setattr(cli, "detect_transport_url", refused)
    code, _, _ = _run(["probe", "--execute", "--yes", "--transport", "loop://"], capsys)
    assert code == 0
    assert factory_calls == ["loop://"]
