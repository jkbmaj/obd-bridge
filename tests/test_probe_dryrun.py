"""Tests of `obdb probe --dry-run` through the CLI (spec T9 dry-run, T11; FR-24, FR-05, audit m10).

Dry-run uses only `NullTransport`. Files are created in `project_dir`
(a temporary directory set as the current one). The subprocess test runs
a clean interpreter without `conftest.py` to confirm that the dry-run path
does not import pyserial.
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from obd_bridge import cli
from obd_bridge.audit import audit_session
from obd_bridge.probe.runner import ProbeMode, run_probe_session
from obd_bridge.traffic_log import read_events
from obd_bridge.transport.replay import ReplayTransport
from obd_bridge.vag.catalog import EcuCatalog


def _session_logs(root: Path) -> list[Path]:
    """All session JSONL files in `root/data/sessions/`."""
    return sorted((root / "data" / "sessions").rglob("*.jsonl"))


def _transport_tx(path: Path) -> list[str]:
    """`tx` bytes of the `transport` layer from the log (field `data` after escaping)."""
    return [
        event["data"]
        for event in read_events(path)
        if event["ev"] == "tx" and event["layer"] == "transport"
    ]


def test_dry_run_single_jsonl(project_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Dry-run: code 0, one JSONL with `mode: dry-run`, no `data/probes/`, 0 rejections, clean audit."""
    code = cli.main(["probe", "--dry-run"])
    out = capsys.readouterr().out
    assert code == 0
    assert "Dry-run summary:" in out

    logs = _session_logs(project_dir)
    assert len(logs) == 1
    assert logs[0].stem.endswith("probe-dry-run")
    events = read_events(logs[0])
    start = events[0]
    assert start["ev"] == "session_start"
    assert start["meta"]["mode"] == "dry-run"
    assert start["meta"]["transport_url"] == "null://"
    assert start["meta"]["argv"] == ["probe", "--dry-run"]
    assert events[-1]["ev"] == "session_end"
    assert not (project_dir / "data" / "probes").exists()

    audit = audit_session(logs[0], EcuCatalog.load())
    assert len(audit.violations) == 0
    assert audit.guard_rejections == 0
    assert audit.checked_tx > 0

    assert cli.main(["audit", str(logs[0])]) == 0
    assert "no violations" in capsys.readouterr().out


def test_dry_run_json_schema(project_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """`--dry-run --json` gives an `obdb.probe-dry-run/1` document with the required keys."""
    code = cli.main(["probe", "--dry-run", "--json", "--note", "café test", "--odometer-km", "0"])
    out = capsys.readouterr().out
    assert code == 0
    document = json.loads(out)
    assert document["schema"] == "obdb.probe-dry-run/1"
    assert {"session_id", "jsonl_path", "lines", "steps", "summary", "audit"} <= document.keys()
    assert Path(document["jsonl_path"]).is_file()
    assert {"step", "line", "guard", "rule", "response"} <= document["lines"][0].keys()
    assert document["summary"]["guard_rejections"] == 0
    assert document["summary"]["lines"] == len(document["lines"])
    assert {"typical", "worst"} <= document["summary"]["estimate_ms"].keys()
    assert document["audit"]["violations"] == 0

    meta = read_events(Path(document["jsonl_path"]))[0]["meta"]
    assert meta["note"] == "café test"
    assert meta["odometer_km"] == 0

    code = cli.main(["audit", "--json", document["jsonl_path"]])
    audit_document = json.loads(capsys.readouterr().out)
    assert code == 0
    assert audit_document["schema"] == "obdb.audit/1"
    assert audit_document["violations"] == []


def test_dry_run_replay_identical(project_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """The runner on a `ReplayTransport` from the dry-run log sends identical bytes and consumes all events."""
    assert cli.main(["probe", "--dry-run"]) == 0
    capsys.readouterr()
    (original,) = _session_logs(project_dir)

    replay = ReplayTransport(original)
    session = run_probe_session(
        ProbeMode.DRY_RUN,
        replay,
        EcuCatalog.load(),
        root=project_dir,
        sleep=lambda seconds: None,
    )
    assert replay.remaining == 0
    assert session.exit_code == 0
    assert session.jsonl_path != original
    assert _transport_tx(session.jsonl_path) == _transport_tx(original)


def test_dry_run_subprocess_no_serial(project_dir: Path) -> None:
    """Clean interpreter without `conftest.py`: dry-run through `main()` does not load the `serial` module."""
    code = textwrap.dedent(
        """
        import sys
        from obd_bridge.cli import main
        exit_code = main(["probe", "--dry-run"])
        loaded = sorted(name for name in sys.modules if name == "serial" or name.startswith("serial."))
        print("SERIAL_MODULES=" + ",".join(loaded))
        sys.exit(exit_code)
        """
    )
    completed = subprocess.run(
        [sys.executable, "-I", "-c", code],
        cwd=project_dir,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip().splitlines()[-1] == "SERIAL_MODULES="
    assert len(_session_logs(project_dir)) == 1
    assert not (project_dir / "data" / "probes").exists()


def test_dry_run_text_summary(project_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Dry-run text: T9 columns, JSONL path, line and `STPX` counts, estimated time per the T9 rule."""
    assert cli.main(["probe", "--dry-run"]) == 0
    out = capsys.readouterr().out
    (log,) = _session_logs(project_dir)
    sent = [
        event["data"]
        for event in read_events(log)
        if event["ev"] == "tx" and event["layer"] == "adapter"
    ]
    stpx = [line for line in sent if line.startswith("STPX ")]
    typical = 40 * len(stpx) + 15 * (len(sent) - len(stpx)) + 10 * len(sent)
    worst = 15 * (len(sent) - len(stpx)) + 10 * len(sent)
    for line in stpx:
        timeout = line.rsplit(",T:", 1)[1] if ",T:" in line else "300"
        worst += int(timeout)

    header = out.splitlines()[0].split()
    assert header == ["Step", "Line", "Guard", "Response", "Result"]
    # Path relative to the working directory (the CLI runner uses `root=Path(".")`).
    assert f"  Session log: {log.relative_to(project_dir)}" in out
    assert f"  Lines: {len(sent)}, of which STPX: {len(stpx)}" in out
    assert "  Guard rejections: 0" in out
    assert f"  Estimated time: typical {typical} ms, worst case {worst} ms" in out
    assert "violations: 0" in out
    assert "  Exit code: 0" in out
    assert worst > typical


def test_dry_run_engine_sample_rows(project_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Package D: engine sample lines belong to the module step; in the table they have result `sample`, in JSON `sample: true`."""
    assert cli.main(["probe", "--dry-run", "--json"]) == 0
    document = json.loads(capsys.readouterr().out)
    rows = [row for row in document["lines"] if row["line"] == "STPX H:7E0,D:22F40C,R:1"]
    assert [row["step"] for row in rows] == [*range(12, 23), 24, 25, 26]
    assert all(row["sample"] for row in rows)
    sample_rows = [row for row in document["lines"] if row.get("sample")]
    assert {row["step"] for row in sample_rows} == {*range(12, 23), 24, 25, 26}
    assert {row["line"] for row in sample_rows} == {
        "ATRV", "ATSH7E0", "ATCRA7E8", "STCFCPA7E0,7E8", "STFFCA7E8,7FF", "STPX H:7E0,D:22F40C,R:1",
        "ATSH710", "ATCRA77A", "ATSH7E1", "ATCRA7E9",
    }

    assert cli.main(["probe", "--dry-run"]) == 0
    out = capsys.readouterr().out
    sample_lines = [line for line in out.splitlines() if "D:22F40C" in line]
    assert sample_lines and all(line.split()[-1] == "sample" for line in sample_lines)
    step26 = [line.split() for line in out.splitlines() if line.startswith("26 ")]
    assert [(cols[1], cols[-1]) for cols in step26 if cols[1] in ("ATRV", "ATCS")][-2:] == [("ATRV", "ok"), ("ATCS", "ok")]
