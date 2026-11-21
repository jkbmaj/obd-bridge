"""Probe reports: plan, dry-run, execute and the `obdb.probe/1` file (spec T9).

The module formats results and performs no I/O except `write_probe_file`
(atomic write via `yamlio.write_atomic`, no overwrite) and reading the
closed JSONL log in the dry-run report. Runner types are accepted
structurally (attributes of `ProbeSession`, `ProbeResult`, `StepResult`), so
the module does not import the runner at runtime.

JSON documents:
    `obdb.probe-plan/1` (plan without flags), `obdb.probe-dry-run/1` (dry-run),
    `obdb.probe-run/1` (`--execute` summary).
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from obd_bridge.probe.engine import (
    SAMPLE_MARKER,
    WARNING_CHARGING_LOW,
    WARNING_VOLTAGE_LOW,
    WARNING_VOLTAGE_UNREADABLE,
)
from obd_bridge.probe.plan import PlanLine, ProbeStep, plan_document, plan_totals
from obd_bridge.stn.driver import DEFAULT_STPX_TIMEOUT_MS
from obd_bridge.stn.profile import PROBE_SCHEMA
from obd_bridge.traffic_log import EventKind, Layer, read_events
from obd_bridge.yamlio import dump_yaml, write_atomic

if TYPE_CHECKING:
    from obd_bridge.probe.engine import ProbeWarning
    from obd_bridge.probe.runner import ProbeSession, StepResult

__all__ = [
    "DRY_RUN_SCHEMA",
    "MAX_PLAN_LINES",
    "PLAN_COLUMNS",
    "RUN_SCHEMA",
    "SAMPLE_PLAN_TEXT",
    "SAMPLE_RESULT",
    "SHOWN_PLAN_LINES",
    "dry_run_document",
    "dry_run_lines",
    "estimate_ms",
    "format_progress",
    "format_warning",
    "plan_commands",
    "plan_line_text",
    "probe_document",
    "probe_path_for",
    "render_dry_run_json",
    "render_dry_run_text",
    "render_plan_json",
    "render_plan_text",
    "render_probe_yaml",
    "render_run_json",
    "render_run_text",
    "run_document",
    "write_probe_file",
]

DRY_RUN_SCHEMA: Final[str] = "obdb.probe-dry-run/1"
"""Schema of the `obdb probe --dry-run --json` document."""

RUN_SCHEMA: Final[str] = "obdb.probe-run/1"
"""Schema of the `obdb probe --execute --json` document."""

PLAN_COLUMNS: Final[tuple[str, ...]] = ("Stage", "Step", "Tags", "Commands", "Description")
"""Plan table columns."""

DRY_RUN_COLUMNS: Final[tuple[str, ...]] = ("Step", "Line", "Guard", "Response", "Result")
"""Dry-run table columns."""

MAX_PLAN_LINES: Final[int] = 6
"""A step with more lines is shortened in the plan table."""

SHOWN_PLAN_LINES: Final[int] = 4
"""Number of lines shown for a shortened step (the rest as `… (+N)`)."""

SAMPLE_PLAN_TEXT: Final[str] = "engine sample (ATRV, RPM 01)"
"""Prefix of the plan `Commands` column for a step with an engine state sample (package D)."""

SAMPLE_RESULT: Final[str] = "sample"
"""Value of the dry-run table `Result` column for engine state sample lines."""

_VOLTAGE_KINDS: Final[frozenset[str]] = frozenset(
    {WARNING_VOLTAGE_LOW, WARNING_VOLTAGE_UNREADABLE, WARNING_CHARGING_LOW}
)

TYPICAL_ADAPTER_MS: Final[int] = 15
"""Estimated time of a typical adapter command."""

TYPICAL_STPX_MS: Final[int] = 40
"""Estimated time of a typical `STPX` line."""

RATE_LIMIT_MS: Final[int] = 10
"""Driver rate limit added to every line."""

_SEPARATOR: Final[str] = "  "
_STPX_TIMEOUT_RE: Final = re.compile(r",T:([0-9]+)$")


# ---------------------------------------------------------------------------
# Text table


def _table(headers: Sequence[str], rows: Iterable[Sequence[str]]) -> list[str]:
    """Table with left-aligned columns, two-space separator, no wrapping."""
    body = [[str(cell) for cell in row] for row in rows]
    widths = [len(header) for header in headers]
    for row in body:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))
    out: list[str] = []
    for row in (list(headers), *body):
        out.append(_SEPARATOR.join(cell.ljust(widths[index]) for index, cell in enumerate(row)).rstrip())
    return out


# ---------------------------------------------------------------------------
# Plan


def plan_line_text(line: PlanLine) -> str:
    """Plan line in the table: `100 × <line>` for `repeat > 1`."""
    return f"{line.repeat} × {line.line}" if line.repeat > 1 else line.line


def plan_commands(step: ProbeStep) -> str:
    """`Commands` column: engine sample as prefix; steps with more than 6 lines show the first 4 and `… (+N)`."""
    texts = [plan_line_text(line) for line in step.lines]
    if len(texts) > MAX_PLAN_LINES:
        hidden = len(texts) - SHOWN_PLAN_LINES
        texts = [*texts[:SHOWN_PLAN_LINES], f"… (+{hidden})"]
    if step.sample:
        texts = [SAMPLE_PLAN_TEXT, *texts]
    return ", ".join(texts) if texts else "(no lines)"


def _plan_description(step: ProbeStep) -> str:
    if not step.conditional:
        return step.description
    return f"{step.description} Conditional branches: {'; '.join(step.conditional)}."


def render_plan_text(steps: Sequence[ProbeStep]) -> str:
    """Plan table (`Stage`, `Step`, `Tags`, `Commands`, `Description`) with a summary footer."""
    rows = [
        (
            step.stage.value,
            str(step.number),
            ", ".join(tag.value for tag in step.tags),
            plan_commands(step),
            _plan_description(step),
        )
        for step in steps
    ]
    totals = plan_totals(steps)
    lines = _table(PLAN_COLUMNS, rows)
    lines.append("")
    lines.append(
        f"Steps: {totals.steps}; default branch lines: {totals.lines}; STPX lines: {totals.stpx}."
    )
    return "\n".join(lines)


def render_plan_json(steps: Sequence[ProbeStep]) -> str:
    """The `obdb.probe-plan/1` document as JSON."""
    return _json(plan_document(steps))


# ---------------------------------------------------------------------------
# Dry-run


def dry_run_lines(events: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Session lines from the log: `{step, line, guard, rule, response, sample}` in event order.

    A `tx` of the `adapter` layer gives a line with the guard decision and the first
    response line (`rx` of the `adapter` layer without echo); a `guard` event gives a
    rejected line (`rejected`) without a response. The step comes from the last marker;
    `sample` is True for lines after an `engine_sample` marker (engine sample).
    """
    rows: list[dict[str, Any]] = []
    step: int | None = None
    sample = False
    awaiting: dict[str, Any] | None = None
    for event in events:
        ev, layer = event.get("ev"), event.get("layer")
        meta = event.get("meta") or {}
        guard = event.get("guard") or {}
        if ev == EventKind.MARKER and meta.get("phase") == "start":
            step = meta.get("step")
            sample = meta.get("kind") == SAMPLE_MARKER
        elif ev == EventKind.TX and layer == Layer.ADAPTER:
            awaiting = {
                "step": step,
                "line": event.get("data", ""),
                "guard": guard.get("decision"),
                "rule": guard.get("rule"),
                "response": None,
                "sample": sample,
            }
            rows.append(awaiting)
        elif ev == EventKind.RX and layer == Layer.ADAPTER and awaiting is not None and not meta.get("echo"):
            awaiting["response"] = event.get("data")
            awaiting = None
        elif ev == EventKind.GUARD:
            awaiting = None
            rows.append(
                {
                    "step": step,
                    "line": event.get("data", ""),
                    "guard": guard.get("decision", "rejected"),
                    "rule": guard.get("rule"),
                    "response": None,
                    "sample": sample,
                }
            )
    return rows


def _stpx_timeout_ms(line: str) -> int:
    match = _STPX_TIMEOUT_RE.search(line)
    return int(match.group(1)) if match else DEFAULT_STPX_TIMEOUT_MS


def estimate_ms(lines: Iterable[str]) -> dict[str, int]:
    """Estimated session time in ms (spec T9, dry-run).

    Typical: 15 ms per adapter command, 40 ms per `STPX`, plus a 10 ms limit per
    line. Worst case: `STPX` counted as T (the `T:` field or 300 ms).
    """
    typical = worst = 0
    for line in lines:
        if line.startswith("STPX "):
            typical += TYPICAL_STPX_MS
            worst += _stpx_timeout_ms(line)
        else:
            typical += TYPICAL_ADAPTER_MS
            worst += TYPICAL_ADAPTER_MS
        typical += RATE_LIMIT_MS
        worst += RATE_LIMIT_MS
    return {"typical": typical, "worst": worst}


def _line_results(session: ProbeSession, rows: Sequence[Mapping[str, Any]]) -> list[str]:
    """Entry result for every line: consecutive step entries with the same line; engine sample: `sample`."""
    pending: dict[int, list[Any]] = {}
    for step in session.result.steps:
        pending.setdefault(step.step, []).extend(step.items)
    out: list[str] = []
    for row in rows:
        if row.get("sample"):
            out.append(SAMPLE_RESULT)
            continue
        items = pending.get(row["step"], [])
        match = next((item for item in items if item.line == row["line"]), None)
        if match is None and row.get("guard") == "rejected":
            match = next((item for item in items if item.result == "error"), None)
        if match is not None:
            items.remove(match)
            out.append(str(match.result))
        else:
            out.append("-")
    return out


def _summary(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    sent = [str(row["line"]) for row in rows if row.get("guard") == "allowed"]
    return {
        "lines": len(sent),
        "stpx": sum(1 for line in sent if line.startswith("STPX ")),
        "guard_rejections": sum(1 for row in rows if row.get("guard") == "rejected"),
        "estimate_ms": estimate_ms(sent),
    }


def dry_run_document(session: ProbeSession) -> dict[str, Any]:
    """The `obdb.probe-dry-run/1` document from the lines of the closed session log."""
    rows = dry_run_lines(read_events(session.jsonl_path))
    return {
        "schema": DRY_RUN_SCHEMA,
        "session_id": session.session_id,
        "jsonl_path": str(session.jsonl_path),
        "lines": [
            {
                "step": row["step"],
                "line": row["line"],
                "guard": row["guard"],
                "rule": row["rule"],
                "response": row["response"],
                "sample": bool(row.get("sample")),
            }
            for row in rows
        ],
        "steps": [{"step": step.step, "result": str(step.result)} for step in session.result.steps],
        "summary": _summary(rows),
        "audit": {"checked_tx": session.audit.checked_tx, "violations": len(session.audit.violations)},
    }


def render_dry_run_json(session: ProbeSession) -> str:
    """The `obdb.probe-dry-run/1` document as JSON."""
    return _json(dry_run_document(session))


def render_dry_run_text(session: ProbeSession) -> str:
    """Dry-run line table (`Step`, `Line`, `Guard`, `Response`, `Result`) and summary."""
    rows = dry_run_lines(read_events(session.jsonl_path))
    results = _line_results(session, rows)
    table = _table(
        DRY_RUN_COLUMNS,
        (
            (
                str(row["step"]) if row["step"] is not None else "-",
                str(row["line"]),
                str(row["guard"] or "-"),
                str(row["response"] or ""),
                result,
            )
            for row, result in zip(rows, results, strict=True)
        ),
    )
    summary = _summary(rows)
    estimate = summary["estimate_ms"]
    audit = session.audit
    table.extend(
        [
            "",
            "Dry-run summary:",
            f"  Session log: {session.jsonl_path}",
            f"  Lines: {summary['lines']}, of which STPX: {summary['stpx']}",
            f"  Guard rejections: {summary['guard_rejections']}",
            f"  Estimated time: typical {estimate['typical']} ms, worst case {estimate['worst']} ms",
            f"  Audit: checked tx lines: {audit.checked_tx}, violations: {len(audit.violations)}",
            f"  Exit code: {session.exit_code}",
        ]
    )
    return "\n".join(table)


# ---------------------------------------------------------------------------
# Execute


def format_progress(step: StepResult) -> str:
    """Progress line on stderr, e.g. `Step 12 (B): ok`; repeat: `Step 17 (C, repeat): ok`."""
    repeat = ", repeat" if step.repeat_of is not None else ""
    return f"Step {step.step} ({step.stage}{repeat}): {step.result}"


def format_warning(warning: ProbeWarning) -> str:
    """Warning line (stderr at detection time and in the summary), e.g. `Warning, voltage: ...`."""
    topic = "voltage" if warning.kind in _VOLTAGE_KINDS else "engine"
    return f"Warning, {topic}: {warning.message}"


def _audit_block(session: ProbeSession) -> dict[str, int]:
    audit = session.audit
    return {
        "checked_tx": audit.checked_tx,
        "violations": len(audit.violations),
        "guard_rejections": audit.guard_rejections,
    }


def run_document(session: ProbeSession) -> dict[str, Any]:
    """The `obdb.probe-run/1` document (`--execute --json` summary)."""
    stop = session.result.stop
    return {
        "schema": RUN_SCHEMA,
        "session_id": session.session_id,
        "jsonl_path": str(session.jsonl_path),
        "probe_path": str(session.probe_path) if session.probe_path is not None else None,
        "outcome": str(session.result.outcome),
        "stop": stop.as_dict() if stop is not None else None,
        "exit_code": session.exit_code,
        "steps": [
            {"step": step.step, "result": str(step.result), "repeat_of": step.repeat_of}
            for step in session.result.steps
        ],
        "warnings": [warning.as_dict() for warning in session.result.warnings],
        "audit": _audit_block(session),
    }


def render_run_json(session: ProbeSession) -> str:
    """The `obdb.probe-run/1` document as JSON."""
    return _json(run_document(session))


def render_run_text(session: ProbeSession) -> str:
    """`--execute` summary in English: outcome, stop, warnings, paths, FC, NRC 0x78, audit, code."""
    result = session.result
    stop = result.stop
    stop_text = "none" if stop is None else f"step {stop.step}: {stop.reason} (code {stop.exit_code})"
    audit = _audit_block(session)
    return "\n".join(
        [
            f"Probe outcome: {result.outcome}",
            f"Stop reason: {stop_text}",
            *(format_warning(warning) for warning in result.warnings),
            f"Session log: {session.jsonl_path}",
            f"Probe file: {session.probe_path if session.probe_path is not None else 'none'}",
            f"FC strategy: {result.fc_strategy or 'undetermined'}",
            f"NRC 0x78 mode: {result.nrc78_mode}",
            (
                f"Audit: checked tx lines: {audit['checked_tx']}, violations: {audit['violations']}, "
                f"guard rejections: {audit['guard_rejections']}"
            ),
            f"Exit code: {session.exit_code}",
        ]
    )


# ---------------------------------------------------------------------------
# Probe file


def probe_path_for(root: Path, jsonl_path: Path, session_id: str) -> Path:
    """`<root>/data/probes/<YYYY-MM-DD>/<session_id>.yaml`; date from the session log directory.

    The probe `session_id` already ends with the command name (`...-probe`, on collision
    `...-probe-2`), so the file name does not repeat the suffix.
    """
    return Path(root) / "data" / "probes" / Path(jsonl_path).parent.name / f"{session_id}.yaml"


def probe_document(session: ProbeSession) -> dict[str, Any]:
    """The `obdb.probe/1` document (field order as in spec T9); profile blocks consistent with T8."""
    result = session.result
    stop = result.stop
    return {
        "schema": PROBE_SCHEMA,
        "session_id": session.session_id,
        "session_log": str(session.jsonl_path),
        "mode": str(session.mode.value),
        "started_at": str(session.started_at),
        "finished_at": str(session.finished_at),
        "tool_version": session.tool_version,
        "commit": session.commit,
        "transport": session.transport_url,
        "baud": session.baud,
        "odometer_km": session.odometer_km,
        "note": session.note,
        "outcome": str(result.outcome),
        "stop": stop.as_dict() if stop is not None else None,
        "exit_code": session.exit_code,
        "run_exit_code": session.run_exit_code,
        "adapter": {
            key: (dict(value) if isinstance(value, Mapping) else value) for key, value in result.adapter.items()
        },
        "commands": {str(key): str(value) for key, value in result.commands.items()},
        "fc_strategy": result.fc_strategy,
        "nrc78_mode": str(result.nrc78_mode),
        "timing": {key: dict(value) for key, value in result.timing.items()},
        "stcsegr1_lines": list(result.stcsegr1_lines),
        "installation": result.installation,
        "engine": dict(result.engine),
        "warnings": [warning.as_dict() for warning in result.warnings],
        "checklist": [step.as_dict() for step in result.steps],
        "audit": _audit_block(session),
    }


def render_probe_yaml(document: Mapping[str, Any]) -> str:
    """YAML of the probe file; strings that look like dates (e.g. `started_at`) are quoted."""
    return dump_yaml(dict(document))


def write_probe_file(path: Path, document: Mapping[str, Any]) -> Path:
    """One-time atomic write of the probe file; an existing file gives `FileExistsError`."""
    write_atomic(path, render_probe_yaml(document))
    return Path(path)


def _json(document: Mapping[str, Any]) -> str:
    return json.dumps(document, ensure_ascii=False, indent=2)
