"""Tests of the probe plan `probe/plan.py` (spec T9, FR-23, FR-26).

The plan is pure: it is built from the ECU catalog and the driver's line
builder functions, with no I/O other than reading the catalog. The tests check
step numbering, absence of forbidden lines, agreement of `NOX_DIDS` with the
DID document and that every default branch line passes the guard in the state
in which the driver sends it. The tests use the synthetic catalog and DID
document from `tests/fixtures/mock/`; `test_private_data.py` repeats the
document check against the local, unpublished files.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from conftest import MOCK_CATALOG, MOCK_DIDS_DOC
from obd_bridge import cli
from obd_bridge.policy import AdapterConfigModel, GuardContext, ReadOnlyPolicy
from obd_bridge.policy.adapter_guard import ALLOWLIST
from obd_bridge.probe.plan import (
    ENGINE_RPM_DID,
    GW_IDENT,
    IDENT_FULL,
    INSTALLATION_DIDS,
    NOX_DIDS,
    OBD_BITMAPS,
    LineKind,
    PlanLine,
    ProbeStage,
    ProbeStep,
    StepTag,
    build_steps,
    plan_totals,
    read_did,
)
from obd_bridge.stn.driver import (
    OPEN_PROTOCOL_LINES,
    DriverState,
    FcStrategy,
    address_lines,
    stpx_line,
    target_select_lines,
)
from obd_bridge.probe.report import MAX_PLAN_LINES, SAMPLE_PLAN_TEXT, SHOWN_PLAN_LINES, plan_commands
from obd_bridge.traffic_log import read_events, unescape
from obd_bridge.vag.catalog import EcuCatalog

CATALOG: EcuCatalog = EcuCatalog.load(MOCK_CATALOG)

EXPECTED_NUMBERS: list[int] = [*range(1, 9), *range(10, 23), 24, 25, 26, 27]
EXPECTED_STAGES: dict[int, str] = {
    **{n: "A" for n in range(1, 9)},
    **{n: "B" for n in range(10, 17)},
    **{n: "C" for n in range(17, 22)},
    22: "D",
    24: "D",
    25: "D",
    26: "E",
    27: "E",
}
EXPECTED_TAGS: dict[int, tuple[str, ...]] = {
    1: ("R",),
    2: ("V",),
    3: ("V",),
    4: ("R",),
    5: ("R",),
    6: ("R",),
    7: ("R",),
    8: ("V",),
    10: ("V",),
    11: ("V",),
    **{n: ("B",) for n in range(12, 22)},
    22: ("V", "B"),
    24: ("B",),
    25: ("B",),
    26: ("R", "B"),
    27: ("V",),
}


def _steps() -> dict[int, ProbeStep]:
    return {step.number: step for step in build_steps(CATALOG)}


def _lines(step: ProbeStep) -> list[str]:
    return [item.line for item in step.lines]


def _wire(step: ProbeStep) -> tuple[PlanLine, ...]:
    """Step lines in wire order: engine state sample, then step lines."""
    return (*step.sample, *step.lines)


def _doc_nox_dids(path: Path = MOCK_DIDS_DOC) -> list[str]:
    """DIDs from the table in section `## 01` of the document, in row order."""
    section: list[str] = []
    inside = False
    for raw in path.read_text(encoding="utf-8").splitlines():
        if raw.startswith("## "):
            inside = raw.startswith("## 01")
            continue
        if inside:
            match = re.match(r"^\|\s*([0-9A-F]{4})\s*\|", raw)
            if match:
                section.append(match.group(1))
    return section


def test_steps_numbering() -> None:
    steps = build_steps(CATALOG)
    assert len(steps) == 25
    assert [step.number for step in steps] == EXPECTED_NUMBERS
    assert 9 not in {step.number for step in steps}
    assert 23 not in {step.number for step in steps}
    for step in steps:
        assert isinstance(step.stage, ProbeStage)
        assert step.stage == EXPECTED_STAGES[step.number], step.number
        assert all(isinstance(tag, StepTag) for tag in step.tags)
        assert tuple(step.tags) == EXPECTED_TAGS[step.number], step.number
        assert step.title and step.description
    by_number = _steps()
    assert by_number[1].lines == ()
    assert [(item.line, item.repeat) for item in by_number[24].lines] == [
        (stpx_line(CATALOG.get("02"), bytes.fromhex("22F187")), 100)
    ]
    totals = plan_totals(steps)
    assert totals.steps == 25
    assert totals.lines == sum(item.repeat for step in steps for item in _wire(step))
    assert totals.stpx == sum(
        item.repeat for step in steps for item in _wire(step) if item.line.startswith("STPX ")
    )
    assert totals.lines > totals.stpx >= 100
    # Package D: engine samples before 13 module steps and in step 26, target reselection after the sample.
    assert (totals.lines, totals.stpx) == (335, 211)


def test_no_forbidden_lines() -> None:
    hex_elm = re.compile(r"[0-9A-F]+")
    for step in build_steps(CATALOG):
        for item in _wire(step):
            line = item.line
            assert not line.startswith("STBR"), (step.number, line)
            assert not line.startswith("ATZ"), (step.number, line)
            assert hex_elm.fullmatch(line) is None, (step.number, line)
            if line.startswith("STPX"):
                assert ",R:1" in line, (step.number, line)
                assert item.kind is LineKind.UDS
                assert item.payload is not None and item.target is not None


def test_nox_dids_match_doc() -> None:
    doc = _doc_nox_dids()
    assert len(doc) == 26
    assert list(NOX_DIDS) == doc
    assert set(NOX_DIDS) == set(doc)
    assert NOX_DIDS[0] == "F483"
    assert len(IDENT_FULL) == 11
    assert len(GW_IDENT) == 5
    assert len(OBD_BITMAPS) == 9
    assert len(INSTALLATION_DIDS) == 3
    step18 = _lines(_steps()[18])
    engine = CATALOG.get("01")
    nox_lines = [stpx_line(engine, read_did(did)) for did in NOX_DIDS]
    assert step18[-26:] == nox_lines


def test_default_lines_from_driver_builders() -> None:
    steps = _steps()
    gateway, tcu, engine = CATALOG.get("19"), CATALOG.get("02"), CATALOG.get("01")
    pairs = FcStrategy.ST_PAIRS

    assert tuple(_lines(steps[10])) == OPEN_PROTOCOL_LINES
    assert tuple(_lines(steps[11])) == target_select_lines(gateway, pairs)

    step17 = _lines(steps[17])
    select17 = target_select_lines(tcu, pairs, fc_applied=True, fc_configured={gateway.tx_id})
    assert tuple(step17[:4]) == select17
    assert step17[4:15] == [stpx_line(tcu, read_did(did)) for did in IDENT_FULL]
    assert step17[15:] == [
        stpx_line(tcu, bytes.fromhex(hex_payload)) for hex_payload in ("220600", "1901FF", "1902FF", "190A")
    ]

    configured = {gateway.tx_id, tcu.tx_id, engine.tx_id}
    step22 = _lines(steps[22])
    assert tuple(step22[:2]) == target_select_lines(tcu, pairs, fc_applied=True, fc_configured=configured)
    assert tuple(step22[:2]) == address_lines(tcu)
    assert step22[2:] == ["STCSEGR1", stpx_line(tcu, bytes.fromhex("22F187")), "STCSEGR0"]

    for step in steps.values():
        for item in _wire(step):
            assert any(entry.pattern.fullmatch(item.line) for entry in ALLOWLIST), (step.number, item.line)


def test_lines_pass_guard_in_planned_sequence() -> None:
    """Every default branch line passes the guard in the state in which the driver sends it."""
    policy = ReadOnlyPolicy(CATALOG)
    model = AdapterConfigModel()
    state = DriverState.RAW
    target = None
    for step in build_steps(CATALOG):
        for item in _wire(step):
            if item.kind is LineKind.SELECT:
                selected = CATALOG.get(item.target)
                if state is DriverState.TARGET_SELECTED or target != selected:
                    state, target = DriverState.PROTOCOL_OPEN, selected
            elif state is DriverState.PROTOCOL_OPEN and target is not None:
                state = DriverState.TARGET_SELECTED
            decision = policy.check_line(item.line, GuardContext(state, target, CATALOG, model))
            assert decision.allowed, (step.number, item.line, state, decision.rule, decision.reason)
            model = model.apply(item.line, True)
            if item.line == "STDI":
                state = DriverState.READY
            if item.line == OPEN_PROTOCOL_LINES[-1]:
                state = DriverState.PROTOCOL_OPEN


def _tree(root: Path) -> set[str]:
    """All files and directories under `root` as relative paths."""
    return {path.relative_to(root).as_posix() for path in root.rglob("*")}


def _expanded_default_lines(steps: list[ProbeStep]) -> list[tuple[int, str]]:
    """Pairs (step, line) of the default branch in wire order, with `repeat` expanded."""
    return [(step.number, item.line) for step in steps for item in _wire(step) for _ in range(item.repeat)]


def test_plan_creates_no_files(project_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """`obdb probe` and `obdb probe --json`: code 0, 25 steps, no new files or directories (FR-23)."""
    before = _tree(project_dir)

    assert cli.main(["probe"]) == 0
    text = capsys.readouterr().out
    totals = plan_totals(build_steps(CATALOG))
    assert f"Steps: {totals.steps}; default branch lines: {totals.lines}; STPX lines: {totals.stpx}." in text
    assert _tree(project_dir) == before

    assert cli.main(["probe", "--json"]) == 0
    document = json.loads(capsys.readouterr().out)
    assert document["schema"] == "obdb.probe-plan/1" and document["mode"] == "plan"
    assert len(document["steps"]) == 25
    assert [step["step"] for step in document["steps"]] == EXPECTED_NUMBERS
    assert document["totals"] == {"steps": 25, "lines": totals.lines, "stpx": totals.stpx}
    assert _tree(project_dir) == before


def test_plan_lines_equal_dry_run(project_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Default branch lines of the plan (with `repeat`) are identical to the dry-run `tx` lines (Success Criteria)."""
    steps = build_steps(CATALOG)
    expected = _expanded_default_lines(steps)

    assert cli.main(["probe", "--dry-run", "--json"]) == 0
    document = json.loads(capsys.readouterr().out)
    events = read_events(Path(document["jsonl_path"]))

    adapter_tx = [event["data"] for event in events if event["ev"] == "tx" and event["layer"] == "adapter"]
    assert adapter_tx == [line for _, line in expected]
    transport_tx = [
        unescape(event["data"]) for event in events if event["ev"] == "tx" and event["layer"] == "transport"
    ]
    assert transport_tx == [f"{line}\r".encode("ascii") for _, line in expected]

    # The assignment of lines to steps from the session markers matches the plan.
    assert [(row["step"], row["line"]) for row in document["lines"]] == expected
    assert {row["guard"] for row in document["lines"]} == {"allowed"}
    totals = plan_totals(steps)
    assert document["summary"]["lines"] == totals.lines
    assert document["summary"]["stpx"] == totals.stpx
    assert document["summary"]["guard_rejections"] == 0


def _with_sample(step: ProbeStep, body: str) -> str:
    """`Commands` column with the engine state sample prefix (package D) when the step has one."""
    return f"{SAMPLE_PLAN_TEXT}, {body}" if step.sample else body


def test_plan_text_rendering() -> None:
    """`Commands` column: engine sample, `100 × <line>` for `repeat`, shortening `… (+N)` above 6 lines."""
    steps = _steps()
    assert plan_commands(steps[24]) == f"{SAMPLE_PLAN_TEXT}, 100 × {steps[24].lines[0].line}"
    assert plan_commands(steps[1]) == "(no lines)"
    long_steps = [step for step in steps.values() if len(step.lines) > MAX_PLAN_LINES]
    assert long_steps, "the plan should have steps shortened in the table"
    for step in long_steps:
        shown = ", ".join(item.line for item in step.lines[:SHOWN_PLAN_LINES])
        hidden = len(step.lines) - SHOWN_PLAN_LINES
        assert plan_commands(step) == _with_sample(step, f"{shown}, \u2026 (+{hidden})"), step.number
    short_steps = [step for step in steps.values() if 1 < len(step.lines) <= MAX_PLAN_LINES]
    assert short_steps, "the plan should have steps shown in full"
    for step in short_steps:
        assert plan_commands(step) == _with_sample(step, ", ".join(item.line for item in step.lines)), step.number


def test_engine_sample_lines() -> None:
    """Package D: sample of ATRV and RPM 01 (22 F40C) before every module step and in step 26."""
    steps = _steps()
    engine, gateway, tcu = CATALOG.get("01"), CATALOG.get("19"), CATALOG.get("02")
    rpm = stpx_line(engine, read_did(ENGINE_RPM_DID))
    assert rpm == "STPX H:7E0,D:22F40C,R:1"
    with_sample = [number for number, step in steps.items() if step.sample]
    assert with_sample == [*range(12, 23), 24, 25, 26]
    base = ["ATRV", *address_lines(engine), rpm]
    # The first sample configures the engine FC pair (previously in step 18).
    assert _lines_of(steps[12].sample) == [
        "ATRV", *address_lines(engine), "STCFCPA7E0,7E8", "STFFCA7E8,7FF", rpm, *address_lines(gateway),
    ]
    # Step without its own target selection: the sample ends with a reselection of the step target.
    for number in (13, 14, 15, 16):
        assert _lines_of(steps[number].sample) == [*base, *address_lines(gateway)], number
    for number in (24, 25):
        assert _lines_of(steps[number].sample) == [*base, *address_lines(tcu)], number
    for number in (17, 18, 19, 20, 21, 22, 26):
        assert _lines_of(steps[number].sample) == base, number
        assert number == 26 or steps[number].lines[0].kind is LineKind.SELECT
    assert _lines(steps[18])[:2] == list(address_lines(engine)) and _lines(steps[18])[2].startswith("STPX")
    assert _lines(steps[12]) == [stpx_line(gateway, read_did("F187"))]
    assert _lines(steps[26]) == ["ATRV", "ATCS"]
    # The step target (field `ecu`) does not include the engine from the sample.
    assert steps[13].targets == ("19",) and steps[26].targets == ()
    document = steps[13].as_dict()
    assert [line["line"] for line in document["sample"]] == _lines_of(steps[13].sample)


def _lines_of(lines: tuple[PlanLine, ...]) -> list[str]:
    return [item.line for item in lines]
