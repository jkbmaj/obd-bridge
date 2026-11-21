"""Runner for the `obdb probe` probe and session orchestration (spec T9, T6, T8; FR-22, FR-24, FR-25).

`ProbeRunner` executes the plan steps (`probe/plan.py`) on the real stack:
`StnDriver`, `ElmUdsConnection`, `ReadOnlyUdsClient` and `ReadOnlyPolicy`.
The lines of the default branch come from the plan, and the runner picks the
driver or client method for them; the public API does not accept arbitrary
strings. The runner implements the conditional branches (`1903`, `1904`,
skipping step 22, stop conditions).

`run_probe_session` runs the whole session in the order from the M2 audit:
`session_start`, steps 1 to 27, `session_end` with `run_exit_code`, closing
the JSONL, `audit_session` on the closed file, the final exit code (2 on a
violation detected by the audit, otherwise `run_exit_code`), and for
`--execute` a single atomic write of the `obdb.probe/1` probe file.

Safety:
    `ReadOnlyViolation` aborts the current step and moves on to stage E.
    After `TransportError` the driver sends no further lines: step 26 is
    skipped, and step 27 closes the port without `STPC`. Exception: a final
    `STPX` timeout with a successful drain of the read up to `>`
    (`StpxTimeout.drained`) leaves the session usable, so stage E runs steps
    26 and 27. After `KeyboardInterrupt` stage E starts by finishing the
    current command (`StnDriver.finish_pending`); step 26 runs when the
    adapter has returned to the prompt. A second Ctrl-C during that drain is
    logged with an `error` event, and the port is closed without draining
    again and without `STPC`. A detected adapter reset stops the probe with
    code 3 and skips step 26; the driver then allows only `STPC`. Ctrl-C in
    the progress output or in the step marker is treated as an interruption
    of the step, and during `session_end`, the audit and the probe file
    write it is deferred until the write completes
    (`ProbeSession.deferred_interrupts`, one CLI message on stderr).
    A payload outside the client methods is evaluated by
    `ReadOnlyPolicy.check_uds` and rejected with a `guard` event of the `uds`
    layer before it reaches the driver.

Engine state (package D):
    Before each module step (stages B to D) and once in stage E the runner
    takes a sample from the `ProbeStep.sample` lines: `ATRV` and the engine
    speed of engine 01 (`22 F40C` through `ReadOnlyUdsClient.read_did`, the
    same guard as the rest of the probe). The sample before step k+1 is the
    "after" sample of step k. An engine state change between them marks the
    result of step k (`engine_event`), and the step is repeated once at the
    first `running` sample (a repeat with `repeat_of`, the same path as the
    original, the measurement is valid with a `running` sample also after the
    repeat). No such sample until the end of the probe gives a warning about
    a missing measurement with the engine running. Voltage warnings: 12.4 V
    with the engine off or in an unknown state, 13.2 V with the engine
    running; each kind once, through `on_warning` at the moment of detection
    and in `ProbeResult.warnings`. None of this stops the probe; after a stop
    the runner takes no more samples. No engine speed (NRC or NO DATA) in all
    samples or a failed FC configuration of engine 01 gives one
    `engine_unavailable` warning; after a failed FC configuration the
    following samples are `ATRV` only.

    Repeats: the aggregate fields of the probe file (`stcsegr1_lines`,
    `installation`, `nrc78_mode`, `timing`, FC statuses in `commands`) come
    only from the first execution of a step; the result of a repeat stays
    only in its checklist entry (`repeat_of`).
"""

from __future__ import annotations

import math
import platform
import re
import signal
import threading
import time
from collections.abc import Callable, Iterable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import StrEnum
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, Final, TextIO

from obd_bridge import __version__
from obd_bridge.audit import AuditResult, audit_session
from obd_bridge.errors import (
    AdapterError,
    AdapterResponseError,
    ReadOnlyViolation,
    TransportError,
    UdsError,
)
from obd_bridge.policy import LAYER_UDS, ReadOnlyPolicy
from obd_bridge.probe import report
from obd_bridge.probe.engine import (
    SAMPLE_MARKER,
    WARNING_CHARGING_LOW,
    WARNING_ENGINE_EVENT,
    WARNING_ENGINE_UNAVAILABLE,
    WARNING_NO_RUNNING,
    WARNING_VOLTAGE_LOW,
    WARNING_VOLTAGE_UNREADABLE,
    EngineSample,
    EngineState,
    ProbeWarning,
    decode_rpm,
    engine_event_text,
    engine_state,
    state_changed,
)
from obd_bridge.probe.plan import (
    ADDRESS_ENGINE,
    INSTALLATION_DIDS,
    MAX_SNAPSHOT_RECORDS,
    READ_DTC_BY_MASK,
    READ_DTC_SNAPSHOT_IDS,
    LineKind,
    PlanLine,
    ProbeStage,
    ProbeStep,
    build_steps,
    dtc_snapshot_payload,
)
from obd_bridge.probe.preflight import PreflightMode, confirm
from obd_bridge.stn.driver import (
    FORMAT_LINES,
    OPEN_PROTOCOL_LINES,
    RULE_FC_UNAVAILABLE,
    RULE_STATE,
    RULE_TARGET,
    AdapterQuery,
    DriverError,
    DriverState,
    ProbeCommand,
    StnDriver,
    StpxTimeout,
    address_lines,
    parse_voltage,
    stpx_line,
)
from obd_bridge.stn.parser import AdapterReply, ReplyOutcome, UdsExchange
from obd_bridge.traffic_log import EventKind, Layer, SessionCommand, TrafficLog
from obd_bridge.transport.base import ByteTransport
from obd_bridge.transport.null import NullTransport
from obd_bridge.uds.client import (
    DtcReport,
    DtcReportType,
    NoResponse,
    ReadOnlyUdsClient,
    ResponsePendingUnresolved,
    UdsNegativeResponse,
)
from obd_bridge.uds.connection import ElmUdsConnection
from obd_bridge.vag.catalog import EcuCatalog, EcuTarget

__all__ = [
    "BAUD",
    "CHARGING_MIN_V",
    "DEFERRED_INTERRUPT_NOTICE",
    "EXIT_ADAPTER",
    "EXIT_OK",
    "EXIT_STOP",
    "EXIT_VIOLATION",
    "TIMING_KEY",
    "VOLTAGE_MIN_V",
    "ItemResult",
    "ItemStatus",
    "Outcome",
    "ProbeMode",
    "ProbeResult",
    "ProbeRunner",
    "ProbeSession",
    "StepResult",
    "StopInfo",
    "classify_step",
    "dry_run_probe",
    "execute_probe",
    "nearest_rank",
    "nrc78_mode",
    "run_probe_session",
    "timing_stats",
]

BAUD: Final[int] = 38400
"""Probe port baud rate (`session_start.meta.baud`, `timing.*.baud`)."""

VOLTAGE_MIN_V: Final[float] = 12.4
"""`ATRV` voltage threshold in step 5 and in samples with the engine off or in an unknown state; below it only a warning (no stop)."""

CHARGING_MIN_V: Final[float] = 13.2
"""`ATRV` voltage threshold in samples with the engine running; below it a warning that the alternator may not be charging (no stop)."""

TIMING_KEY: Final[str] = "stpx_22f187_ms"
"""Key of the step 24 timing statistics in the `timing` block."""

EXIT_OK: Final[int] = 0
EXIT_VIOLATION: Final[int] = 2
EXIT_ADAPTER: Final[int] = 3
EXIT_STOP: Final[int] = 4

_UNSUPPORTED_STEPS: Final[frozenset[int]] = frozenset({2, 3, 4, 10, 11, 12})
"""Steps in which an `unsupported` item decides the step result."""

_STOP_ON_ADAPTER_ERROR: Final[frozenset[int]] = frozenset({2, 3, 4, 10, 11})
"""Steps in which `AdapterError` stops the probe (code 3)."""

_BUS_ERROR_TOKENS: Final[frozenset[str]] = frozenset({"CAN ERROR", "BUS ERROR"})
_NRC78_STEPS: Final[range] = range(12, 26)
_FIRST_BUS_STEP: Final[int] = 12
"""First contact with the bus (gateway F187); `NO DATA` stops the live probe."""
_TIMING_STEP: Final[int] = 24
_SEGMENTATION_STEP: Final[int] = 22
_STATUS_STEP: Final[int] = 26
_CLOSE_STEP: Final[int] = 27
_FC_COMMAND_KEYS: Final[tuple[str, ...]] = ("STCFCPA", "STFFCA", "STCAFCP", "STFAFC", "ATFCSH")
_COMMAND_KEY_RE: Final = re.compile(r"[A-Z@]+?(?=[0-9,]|$)")
_PP_RE: Final = re.compile(r"\b([0-9A-F]{2}):([0-9A-F]{2})\b")
_INSTALLATION_PAYLOAD: Final[bytes] = bytes.fromhex("22" + INSTALLATION_DIDS[0])
_INTERRUPTED: Final[str] = "Interrupted by the operator (Ctrl-C)."
_DRAIN_INTERRUPTED: Final[str] = (
    "Another Ctrl-C while draining the read of the interrupted command; "
    "port closed without draining and without STPC."
)
DEFERRED_INTERRUPT_NOTICE: Final[str] = (
    "Ctrl-C during the audit or the results write was deferred; "
    "write completed, session result unchanged."
)
"""CLI message on stderr when `ProbeSession.deferred_interrupts` is greater than 0."""

_ADAPTER_QUERIES: Final[frozenset[str]] = frozenset(query.value for query in AdapterQuery)
"""Plan lines executed as `driver.query` (closed enum `AdapterQuery`); in practice the `ATRV` of the engine sample."""
_STEP_MARKER: Final[str] = "probe_step"
_SILENT_BUS: Final[str] = (
    "The car does not respond: gateway J533 did not answer the first request of step 12 (F187, NO DATA). "
    "Check the ignition and the adapter connection to the OBD socket."
)


class ProbeMode(StrEnum):
    """Probe session mode (`session_start.meta.mode`, the `mode` field of the probe file)."""

    LIVE = "live"
    DRY_RUN = "dry-run"


class ItemStatus(StrEnum):
    """Item and step result (spec T9, "Item and step classification")."""

    OK = "ok"
    NRC = "nrc"
    NO_DATA = "no_data"
    PENDING_UNRESOLVED = "pending_unresolved"
    UNSUPPORTED = "unsupported"
    ERROR = "error"
    SKIPPED = "skipped"


class Outcome(StrEnum):
    """Result of the whole session (`outcome` of the probe file)."""

    COMPLETED = "completed"
    STOPPED = "stopped"
    ABORTED = "aborted"


# ---------------------------------------------------------------------------
# Result types


@dataclass(frozen=True)
class ItemResult:
    """Step item: one `STPX` line or adapter command.

    Attributes:
        line: line on the wire (for `STPX` the line actually sent, when known).
        result: item result (`ItemStatus`).
        response: final response in hex (UDS) or the adapter response text.
        nrc: NRC code in hex (e.g. `22`) or None.
        error: error description or None.
        pending_count: number of `7F xx 78` messages in the exchange.
        elapsed_ms: time from write to `>` in ms or None.
        lines: raw adapter response lines.
        data: read data for the runner (e.g. the 2A2A list); outside the YAML document.
    """

    line: str
    result: str
    response: str | None = None
    nrc: str | None = None
    error: str | None = None
    pending_count: int = 0
    elapsed_ms: float | None = None
    lines: tuple[str, ...] = ()
    data: bytes | None = field(default=None, repr=False, compare=False)

    def as_dict(self) -> dict[str, Any]:
        """Entry of the `items` list of the probe file."""
        return {
            "line": self.line,
            "result": str(self.result),
            "response": self.response,
            "nrc": self.nrc,
            "error": self.error,
            "pending_count": self.pending_count,
            "elapsed_ms": self.elapsed_ms,
            "lines": list(self.lines),
        }


@dataclass(frozen=True)
class StepResult:
    """Probe step result.

    Attributes:
        step: step number; stage: stage A to E; tags: markers R, V, B;
        title: step title; ecu: VAG address of the target (several targets
        separated by commas) or None; result: step result; items: items;
        repeat_of: number of the repeated step (repeat entry) or None;
        engine_event: marker of an engine state change during the step, e.g.
        `engine state change: running -> off`, or None.
    """

    step: int
    stage: str
    tags: tuple[str, ...]
    title: str
    ecu: str | None
    result: str
    items: tuple[ItemResult, ...] = ()
    repeat_of: int | None = None
    engine_event: str | None = None

    def as_dict(self) -> dict[str, Any]:
        """Entry of the `checklist` list of the probe file."""
        return {
            "step": self.step,
            "stage": self.stage,
            "tags": list(self.tags),
            "ecu": self.ecu,
            "result": str(self.result),
            "repeat_of": self.repeat_of,
            "engine_event": self.engine_event,
            "items": [item.as_dict() for item in self.items],
        }


@dataclass(frozen=True)
class StopInfo:
    """Reason the probe stopped: step, description and run exit code."""

    step: int
    reason: str
    exit_code: int

    def as_dict(self) -> dict[str, Any]:
        """The `stop` block of the probe file."""
        return {"step": self.step, "reason": self.reason, "exit_code": self.exit_code}


@dataclass(frozen=True)
class ProbeResult:
    """Result of the runner pass (before the audit).

    Attributes:
        steps: results of the 25 steps in plan order.
        outcome: `completed`, `stopped` or `aborted`.
        stop: stop reason or None.
        run_exit_code: run exit code (0, 2, 3, 4).
        adapter, commands, fc_strategy, nrc78_mode, timing: profile blocks (T8).
        stcsegr1_lines: raw `STPX` response lines with `STCSEGR1` (step 22).
        installation: comparison of the 2A2A list with the catalog or None.
        atcs: `ATCS` response text from step 26 or None.
        engine: the `engine` block of the probe file (`samples`, `repeated`, `missing_running`).
        warnings: non-stopping warnings in order of detection.
    """

    steps: tuple[StepResult, ...]
    outcome: str
    stop: StopInfo | None
    run_exit_code: int
    adapter: dict[str, Any]
    commands: dict[str, str]
    fc_strategy: str | None
    nrc78_mode: str
    timing: dict[str, dict[str, Any]]
    stcsegr1_lines: tuple[str, ...]
    installation: dict[str, Any] | None
    atcs: str | None
    engine: dict[str, Any] = field(default_factory=dict)
    warnings: tuple[ProbeWarning, ...] = ()

    def step(self, number: int) -> StepResult:
        """Result of step `number` (the original entry, not a repeat); a missing step raises `KeyError`."""
        for result in self.steps:
            if result.step == number:
                return result
        raise KeyError(number)


@dataclass(frozen=True)
class ProbeSession:
    """Probe session result after the audit (data for the CLI output and the probe file).

    Attributes:
        mode: session mode; session_id: identifier; jsonl_path: session log;
        probe_path: probe file (`live` only, otherwise None); started_at,
        finished_at: local time ISO 8601 with ms and time zone; tool_version,
        commit, transport_url, baud, note, odometer_km, preflight: metadata of
        `session_start`; result: runner result; audit: `audit_session` result;
        exit_code: final exit code; run_exit_code: run exit code before the audit;
        deferred_interrupts: number of Ctrl-C deferred during `session_end`,
        the audit and the probe file write.
    """

    mode: ProbeMode
    session_id: str
    jsonl_path: Path
    probe_path: Path | None
    started_at: str
    finished_at: str
    tool_version: str
    commit: str | None
    transport_url: str
    baud: int
    note: str | None
    odometer_km: int | None
    preflight: str
    result: ProbeResult
    audit: AuditResult
    exit_code: int
    run_exit_code: int
    deferred_interrupts: int = 0


# ---------------------------------------------------------------------------
# Classification and statistics


def classify_step(step: int, results: Iterable[str]) -> str:
    """Step result from the item results (spec T9, first matching rule).

    No executed items gives `skipped`; then: any `error`; any `unsupported`
    in steps 2 to 4 and 10 to 12; any `ok`; `pending_unresolved`; `nrc`; all
    `no_data`. The remaining case (only `unsupported` outside those steps,
    possibly with `no_data`) gives `unsupported`.
    """
    executed = [str(result) for result in results if str(result) != ItemStatus.SKIPPED]
    if not executed:
        return ItemStatus.SKIPPED.value
    if ItemStatus.ERROR in executed:
        return ItemStatus.ERROR.value
    if step in _UNSUPPORTED_STEPS and ItemStatus.UNSUPPORTED in executed:
        return ItemStatus.UNSUPPORTED.value
    for status in (ItemStatus.OK, ItemStatus.PENDING_UNRESOLVED, ItemStatus.NRC):
        if status in executed:
            return status.value
    if all(result == ItemStatus.NO_DATA for result in executed):
        return ItemStatus.NO_DATA.value
    return ItemStatus.UNSUPPORTED.value


def nrc78_mode(items: Iterable[ItemResult]) -> str:
    """`needs_r2` with a `pending_unresolved` item, `same_command` with `pending_count > 0`, otherwise `unknown`."""
    collected = list(items)
    if any(item.result == ItemStatus.PENDING_UNRESOLVED for item in collected):
        return "needs_r2"
    if any(item.pending_count > 0 for item in collected):
        return "same_command"
    return "unknown"


def nearest_rank(values: Sequence[float], percent: float) -> float:
    """Nearest-rank percentile: the element of rank `ceil(p / 100 * n)` of the sorted list.

    Raises:
        ValueError: empty list or `percent` outside (0, 100].
    """
    if not values:
        raise ValueError("Percentile of an empty list is undefined")
    if not 0 < percent <= 100:
        raise ValueError(f"Percentile must be in the range (0, 100], got {percent!r}")
    ordered = sorted(values)
    rank = max(1, math.ceil(percent / 100 * len(ordered)))
    return float(ordered[rank - 1])


def timing_stats(values: Sequence[float], baud: int = BAUD) -> dict[str, Any]:
    """Timing statistics in ms (`n`, `p50`, `p95`, `min`, `max`, `baud`), values rounded to 0.1."""
    return {
        "n": len(values),
        "p50": round(nearest_rank(values, 50), 1),
        "p95": round(nearest_rank(values, 95), 1),
        "min": round(float(min(values)), 1),
        "max": round(float(max(values)), 1),
        "baud": baud,
    }


def _command_key(line: str) -> str:
    """Command name without arguments, e.g. `STCTOR75,150` gives `STCTOR`, `STCSEGR0` gives `STCSEGR`."""
    match = _COMMAND_KEY_RE.match(line)
    return match.group(0) if match else line


def _decimal(value: float) -> str:
    return f"{value:.1f}"


# ---------------------------------------------------------------------------
# Runner


class _StepStop(Exception):
    """Stop condition detected by a step handler (e.g. `CAN ERROR`)."""

    def __init__(self, reason: str, exit_code: int) -> None:
        self.reason = reason
        self.exit_code = exit_code
        super().__init__(reason)


class _StepContext:
    """State of the running step: items, current line and the recorded-failure flag."""

    def __init__(self, step: ProbeStep) -> None:
        self.step = step
        self.items: list[ItemResult] = []
        self.line = ""
        self.recorded = False

    def add(self, item: ItemResult) -> None:
        self.items.append(item)


@dataclass(frozen=True)
class _OpenStep:
    """Module step waiting for its "after" sample: step, the sample before it, result index and `repeat_of`."""

    step: ProbeStep
    before: EngineSample
    index: int
    repeat_of: int | None


def _reply_status(reply: AdapterReply) -> str:
    if reply.outcome in (ReplyOutcome.OK, ReplyOutcome.VALUE):
        return ItemStatus.OK.value
    if reply.outcome is ReplyOutcome.UNSUPPORTED:
        return ItemStatus.UNSUPPORTED.value
    return ItemStatus.ERROR.value


def _describe(exc: BaseException) -> str:
    text = str(exc)
    return f"{type(exc).__name__}: {text}" if text else type(exc).__name__


class ProbeRunner:
    """Executes the probe steps on the driver and the read-only UDS clients.

    Parameters:
        driver: driver in the CLOSED state with the session log (`driver.log`).
        catalog: ECU catalog (step targets, comparison of the 2A2A list).
        steps: plan steps (`build_steps(catalog)`).
        on_step: called after each step (also a skipped one) with `StepResult`.
        stop_on_silent_bus: `NO DATA` in step 12 stops the probe with code 4
            (live probe); dry-run has only `NO DATA`, so it passes False.
        on_warning: called at the moment a non-stopping warning is detected
            (`ProbeWarning`: voltage, engine state change, missing measurement).

    `run()` always closes the driver and returns `ProbeResult`; step
    exceptions are mapped to the T9 global conditions and do not leave the runner.
    """

    def __init__(
        self,
        driver: StnDriver,
        catalog: EcuCatalog,
        steps: Sequence[ProbeStep],
        *,
        on_step: Callable[[StepResult], None] | None = None,
        stop_on_silent_bus: bool = False,
        on_warning: Callable[[ProbeWarning], None] | None = None,
    ) -> None:
        self.driver = driver
        self.catalog = catalog
        self.policy: ReadOnlyPolicy = driver.policy
        self.steps = tuple(steps)
        self._on_step = on_step
        self._on_warning = on_warning
        self._stop_on_silent_bus = stop_on_silent_bus
        self._samples: list[EngineSample] = []
        self._open: _OpenStep | None = None
        self._pending_repeats: list[ProbeStep] = []
        self._repeated: list[int] = []
        self._missing_running: list[int] = []
        self._warnings: list[ProbeWarning] = []
        self._warned_kinds: set[str] = set()
        self._carry: dict[int, list[ItemResult]] = {}
        self._engine_disabled = False
        self._rpm_results: list[str] = []
        self._current_repeat: int | None = None
        self._repeat_fc_attempts: set[int] = set()
        self._pending_finished = True
        self._pending_abandoned = False
        self._results: list[StepResult] = []
        self._stop: StopInfo | None = None
        self._outcome = Outcome.COMPLETED
        self._interrupted = False
        self._connection: ElmUdsConnection | None = None
        self._client: ReadOnlyUdsClient | None = None
        self._adapter: dict[str, Any] = {
            "banner": None,
            "elm": None,
            "at1": None,
            "sti": None,
            "stdi": None,
            "voltage_v": None,
            "voltage_warning": None,
            "stvr": None,
            "pp": {},
            "dpn": None,
            "stpr": None,
            "stprs": None,
        }
        self._commands: dict[str, str] = {}
        self._stcsegr1: tuple[str, ...] = ()
        self._installation_raw: bytes | None = None
        self._atcs: str | None = None
        self._handlers: dict[int, Callable[[ProbeStep, _StepContext], None]] = {
            1: self._step_open,
            2: self._step_warm_start,
            3: self._step_format,
            4: self._step_identify,
            5: self._step_voltage,
            6: self._step_pp,
            7: self._step_protocol_info,
            8: self._step_probe_commands,
            10: self._step_open_protocol,
            16: self._step_gateway_dtc,
            _SEGMENTATION_STEP: self._step_segmentation,
            _STATUS_STEP: self._step_status,
            _CLOSE_STEP: self._step_close,
        }

    # -- run ----------------------------------------------------------------

    def run(self) -> ProbeResult:
        """Steps of stages A to D with engine samples, the stage E sample, then stage E; returns the run result."""
        try:
            for step in self.steps:
                if step.stage is ProbeStage.E:
                    continue
                try:
                    if self._stop is not None or self._skip_step(step):
                        self._record_skipped(step)
                        continue
                    before: EngineSample | None = None
                    if step.sample:
                        before = self._sample_point(step, record=True)
                        if before is None:
                            continue
                    index = len(self._results)
                    self._execute(step)
                    if before is not None:
                        self._open = _OpenStep(step, before, index, None)
                except KeyboardInterrupt:
                    self._interrupt_outside(step)
            self._final_sample()
            self._report_missing()
            self._report_engine_unavailable()
            self._finish_pending()
            for step in self.steps:
                if step.stage is not ProbeStage.E:
                    continue
                try:
                    if step.number == _STATUS_STEP and self._status_unavailable():
                        self._record_skipped(step)
                        continue
                    self._execute(step)
                except KeyboardInterrupt:
                    self._interrupt_outside(step)
        finally:
            if self.driver.state is not DriverState.CLOSED:
                try:
                    self.driver.close(after_transport_error=self._close_without_lines())
                except BaseException:  # emergency close; the driver has logged the `error` events
                    pass
        return self._build_result()

    def _finish_pending(self) -> None:
        """Start of stage E: draining the command interrupted by Ctrl-C up to `>` (spec T9).

        Another Ctrl-C during the drain abandons the pending response: an
        `error` event, and step 27 closes the port without draining and without `STPC`.
        """
        if self.driver.pending_line is None:
            return
        try:
            self._pending_finished = self.driver.finish_pending()
        except KeyboardInterrupt:
            self._pending_finished = False
            self._pending_abandoned = True
            self._interrupted = True
            self._log_error("KeyboardInterrupt", _DRAIN_INTERRUPTED)

    def _close_without_lines(self) -> bool:
        """Close without lines: after a transport error or after an abandoned read drain."""
        return self.driver.transport_failed or self._pending_abandoned

    def _interrupt(self, step: ProbeStep) -> None:
        """Ctrl-C: interruption flag, `error` event and stop with code 4 (`aborted`)."""
        self._interrupted = True
        self._log_error("KeyboardInterrupt", _INTERRUPTED)
        self._set_stop(step, _INTERRUPTED, EXIT_STOP, Outcome.ABORTED)

    def _interrupt_outside(self, step: ProbeStep) -> None:
        """Ctrl-C outside a step handler (e.g. between steps): stop, and a step result when there is none."""
        self._interrupt(step)
        if not any(result.step == step.number for result in self._results):
            self._carry_error(step, ItemResult(line="", result=ItemStatus.ERROR.value, error=_INTERRUPTED))
            self._results.append(self._step_result(step, ItemStatus.ERROR.value, self._carry.pop(step.number)))

    def _skip_step(self, step: ProbeStep) -> bool:
        """Step 22 is skipped when `STCSEGR0` in step 8 returned `?`."""
        return step.number == _SEGMENTATION_STEP and self._commands.get("STCSEGR") == ItemStatus.UNSUPPORTED

    def _status_unavailable(self) -> bool:
        """Step 26 without a port, after a transport error, after an adapter reset or without draining the interrupted command."""
        return (
            self.driver.state is DriverState.CLOSED
            or self.driver.transport_failed
            or self.driver.adapter_reset is not None
            or not self._pending_finished
        )

    def _execute(self, step: ProbeStep, repeat_of: int | None = None) -> None:
        """A step or its repeat (`repeat_of`); `error` items carried over from the sample go to the original."""
        ctx = _StepContext(step)
        if repeat_of is None:
            ctx.items.extend(self._carry.pop(step.number, ()))
        handler = self._handlers.get(step.number, self._step_lines)

        def body() -> None:
            self._marker(step, "start", None, repeat_of=repeat_of)
            handler(step, ctx)

        fc_before = len(self.driver.fc_attempts)
        self._current_repeat = repeat_of
        try:
            self._run_guarded(step, ctx, body)
        finally:
            self._current_repeat = None
        if repeat_of is not None:
            self._repeat_fc_attempts.update(range(fc_before, len(self.driver.fc_attempts)))
        result = self._classify(step, ctx)
        # The first-bus-contact conditions apply only to the original of step 12.
        if repeat_of is None and step.number == _FIRST_BUS_STEP and result == ItemStatus.UNSUPPORTED:
            self._set_stop(step, "The adapter does not support STPX (response ?)", EXIT_ADAPTER)
        if (
            repeat_of is None
            and step.number == _FIRST_BUS_STEP
            and result == ItemStatus.NO_DATA
            and self._stop_on_silent_bus
        ):
            self._set_stop(step, _SILENT_BUS, EXIT_STOP)
        self._finish(step, ctx.items, result, repeat_of)

    def _run_guarded(self, step: ProbeStep, ctx: _StepContext, body: Callable[[], None]) -> None:
        """Runs the `body` of a step or sample; maps exceptions to `error` items and T9 stop conditions."""
        try:
            body()
        except _StepStop as stop:
            self._set_stop(step, stop.reason, stop.exit_code)
        except ReadOnlyViolation as exc:
            self._fail_item(ctx, exc)
            self._set_stop(step, f"Read-only policy violation ({exc.rule}): {exc.reason}", EXIT_VIOLATION)
        except StpxTimeout as exc:
            self._fail_item(ctx, exc)
            self._set_stop(step, self._timeout_stop_reason(exc), EXIT_ADAPTER)
        except TransportError as exc:
            self._fail_item(ctx, exc)
            self._set_stop(step, f"Transport error: {_describe(exc)}", EXIT_ADAPTER)
        except KeyboardInterrupt:
            self._fail_item(ctx, None, _INTERRUPTED)
            self._interrupt(step)
        except AdapterError as exc:
            self._fail_item(ctx, exc)
            if self.driver.adapter_reset is None and step.number in _STOP_ON_ADAPTER_ERROR:
                self._set_stop(step, self._adapter_stop_reason(exc), EXIT_ADAPTER)
        except Exception as exc:  # an internal error must not skip stage E or the probe file
            self._fail_item(ctx, exc)
            self._log_error(type(exc).__name__, str(exc))
            self._set_stop(step, f"Internal error: {_describe(exc)}", EXIT_ADAPTER)
        if self.driver.adapter_reset is not None:
            self._set_stop(step, self._reset_stop_reason(), EXIT_ADAPTER)

    def _reset_stop_reason(self) -> str:
        """Stop reason after a reset; `STPC` is mentioned only with an open protocol."""
        if self.driver.state in (DriverState.PROTOCOL_OPEN, DriverState.TARGET_SELECTED):
            closing = "Further lines blocked; only STPC is allowed on close."
        else:
            closing = "Further lines blocked; close without STPC (the protocol was not open)."
        return f"Adapter reset or reply desync detected ({self.driver.adapter_reset}). {closing}"

    @staticmethod
    def _timeout_stop_reason(exc: StpxTimeout) -> str:
        exchange = exc.exchange
        pending = f", received {exchange.pending_count} x 7F xx 78" if exchange.pending_count else ""
        drained = (
            "the adapter returned to the prompt"
            if exc.drained
            else "the adapter did not return to the prompt, further lines blocked"
        )
        return f"No ECU response within the time limit to {exchange.line}{pending}; {drained}"

    def _classify(self, step: ProbeStep, ctx: _StepContext) -> str:
        results = [item.result for item in ctx.items]
        has_error = ItemStatus.ERROR in results
        if step.number == 1 or (step.number == _CLOSE_STEP and not results):
            return ItemStatus.ERROR.value if has_error else ItemStatus.OK.value
        if step.number == _CLOSE_STEP:
            return classify_step(step.number, results)
        if step.number == 8 and results:
            return ItemStatus.ERROR.value if has_error else ItemStatus.OK.value
        if step.number == 11 and self.driver.fc_strategy is not None and not has_error:
            return ItemStatus.OK.value
        if step.number == _TIMING_STEP and ItemStatus.OK in results:
            return ItemStatus.OK.value
        return classify_step(step.number, results)

    def _step_result(
        self,
        step: ProbeStep,
        result: str,
        items: Sequence[ItemResult] = (),
        repeat_of: int | None = None,
    ) -> StepResult:
        targets = step.targets
        return StepResult(
            step=step.number,
            stage=step.stage.value,
            tags=tuple(tag.value for tag in step.tags),
            title=step.title,
            ecu=",".join(targets) if targets else None,
            result=str(result),
            items=tuple(items),
            repeat_of=repeat_of,
        )

    def _finish(
        self, step: ProbeStep, items: Sequence[ItemResult], result: str, repeat_of: int | None = None
    ) -> None:
        step_result = self._step_result(step, result, items, repeat_of)
        self._results.append(step_result)
        self._notify(step, step_result, marker=True)

    def _record_skipped(self, step: ProbeStep) -> None:
        """Skipped step; with `error` items carried over from the sample or from `on_warning` the result is `error`."""
        if self._carry.get(step.number):
            self._record_failed(step)
            return
        step_result = self._step_result(step, ItemStatus.SKIPPED.value)
        self._results.append(step_result)
        self._notify(step, step_result, marker=False)

    def _notify(self, step: ProbeStep, step_result: StepResult, *, marker: bool) -> None:
        """The `end` marker and progress output; Ctrl-C in them does not lose the step result (stop with code 4)."""
        try:
            if marker:
                self._marker(step, "end", step_result.result, repeat_of=step_result.repeat_of)
            if self._on_step is not None:
                self._on_step(step_result)
        except KeyboardInterrupt:
            self._interrupt(step)

    def _set_stop(self, step: ProbeStep, reason: str, exit_code: int, outcome: Outcome = Outcome.STOPPED) -> None:
        """The first stop condition wins (later ones, e.g. in stage E, do not change the code)."""
        if self._stop is None:
            self._stop = StopInfo(step.number, reason, exit_code)
            self._outcome = outcome

    def _fail_item(self, ctx: _StepContext, exc: BaseException | None, message: str | None = None) -> None:
        """An `error` item for the exception, unless the step handler has already recorded it."""
        if ctx.recorded:
            return
        ctx.recorded = True
        if isinstance(exc, StpxTimeout):
            ctx.add(self._exchange_item(ctx.line, ItemStatus.ERROR, exc.exchange, error=str(exc)))
            return
        reply = exc.reply if isinstance(exc, DriverError) else None
        ctx.add(
            ItemResult(
                line=ctx.line,
                result=ItemStatus.ERROR.value,
                response=reply.text if reply is not None else None,
                error=message or (_describe(exc) if exc is not None else None),
                lines=reply.lines if reply is not None else (),
            )
        )

    def _adapter_stop_reason(self, exc: AdapterError) -> str:
        if isinstance(exc, DriverError) and exc.rule == RULE_FC_UNAVAILABLE:
            return "No supported Flow Control strategy (all responses ?)"
        return f"Adapter error: {exc}"

    # -- events ---------------------------------------------------------------

    def _ecu(self) -> str | None:
        target = self.driver.target
        return target.vag_address if target is not None else None

    def _marker(
        self,
        step: ProbeStep,
        phase: str,
        result: str | None,
        *,
        kind: str = _STEP_MARKER,
        repeat_of: int | None = None,
        after_repeat: int | None = None,
    ) -> None:
        """Marker of a step (`probe_step`) or an engine sample (`engine_sample`); repeat fields only when set."""
        meta: dict[str, Any] = {
            "kind": kind,
            "step": step.number,
            "stage": step.stage.value,
            "phase": phase,
            "result": result,
        }
        if repeat_of is not None:
            meta["repeat_of"] = repeat_of
        if after_repeat is not None:
            meta["after_repeat"] = after_repeat
        self.driver.log.emit(EventKind.MARKER, Layer.APP, ecu=self._ecu(), meta=meta)

    def _log_error(self, kind: str, message: str) -> None:
        self.driver.log.emit(
            EventKind.ERROR,
            Layer.APP,
            message,
            ecu=self._ecu(),
            meta={"type": kind, "message": message, "state": self.driver.state.value},
        )

    # -- adapter items --------------------------------------------------------

    def _reply_item(self, line: str, reply: AdapterReply | None, error: str | None = None) -> ItemResult:
        if reply is None:
            return ItemResult(line=line, result=ItemStatus.ERROR.value, error=error)
        result = ItemStatus.ERROR.value if error is not None else _reply_status(reply)
        return ItemResult(
            line=line,
            result=result,
            response=reply.text,
            error=error,
            elapsed_ms=self._elapsed(),
            lines=reply.lines,
        )

    def _elapsed(self) -> float | None:
        return self.driver.last_elapsed_ms

    def _ok_item(self, line: str) -> ItemResult:
        return ItemResult(line=line, result=ItemStatus.OK.value, response="OK", lines=("OK",))

    def _query(self, ctx: _StepContext, query: AdapterQuery) -> AdapterReply:
        ctx.line = query.value
        reply = self.driver.query(query)
        ctx.add(self._reply_item(query.value, reply))
        return reply

    def _sequence(self, ctx: _StepContext, lines: Sequence[str], call: Callable[[], object]) -> None:
        """Driver method sending `lines` in order; each line requires `OK`."""
        ctx.line = lines[0]
        try:
            call()
        except DriverError as exc:
            if exc.line in lines:
                index = lines.index(exc.line)
                for line in lines[:index]:
                    ctx.add(self._ok_item(line))
                ctx.add(self._reply_item(exc.line, exc.reply, error=str(exc)))
                ctx.recorded = True
            raise
        for line in lines:
            ctx.add(self._ok_item(line))

    @staticmethod
    def _value(reply: AdapterReply) -> str | None:
        if reply.outcome is ReplyOutcome.VALUE and reply.lines:
            return reply.lines[0]
        return None

    # -- stage A --------------------------------------------------------------

    def _step_open(self, step: ProbeStep, ctx: _StepContext) -> None:
        ctx.line = "(port open)"
        self._adapter["banner"] = self.driver.open()

    def _step_warm_start(self, step: ProbeStep, ctx: _StepContext) -> None:
        ctx.line = "ATWS"
        try:
            reply = self.driver.warm_start()
        except DriverError as exc:
            ctx.add(self._reply_item("ATWS", exc.reply, error=str(exc)))
            ctx.recorded = True
            raise
        ctx.add(self._reply_item("ATWS", reply))

    def _step_format(self, step: ProbeStep, ctx: _StepContext) -> None:
        self._sequence(ctx, FORMAT_LINES, self.driver.set_format)

    def _step_identify(self, step: ProbeStep, ctx: _StepContext) -> None:
        sti, stdi = AdapterQuery.STI.value, AdapterQuery.STDI.value
        ctx.line = sti
        try:
            info = self.driver.identify(None)
        except DriverError as exc:
            if exc.line == stdi:
                ctx.add(ItemResult(line=sti, result=ItemStatus.OK.value))
            ctx.add(self._reply_item(exc.line or sti, exc.reply, error=str(exc)))
            ctx.recorded = True
            raise
        ctx.add(ItemResult(line=sti, result=ItemStatus.OK.value, response=info.sti, lines=(info.sti,)))
        ctx.add(ItemResult(line=stdi, result=ItemStatus.OK.value, response=info.stdi, lines=(info.stdi,)))
        self._adapter["sti"] = info.sti
        self._adapter["stdi"] = info.stdi
        ati = self._query(ctx, AdapterQuery.ATI)
        at1 = self._query(ctx, AdapterQuery.AT1)
        self._adapter["elm"] = info.elm or self._value(ati)
        self._adapter["at1"] = self._value(at1)

    def _step_voltage(self, step: ProbeStep, ctx: _StepContext) -> None:
        atrv = self._query(ctx, AdapterQuery.ATRV)
        stvr = self._query(ctx, AdapterQuery.STVR)
        text = self._value(atrv)
        volts = parse_voltage(text) if text is not None else None
        self._adapter["voltage_v"] = volts
        self._adapter["stvr"] = self._value(stvr)
        # The voltage threshold temporarily only warns (owner decision 2026-11-21:
        # no maintenance charger during the tests); the probe does not stop.
        # The engine state in step 5 is not known, so the 12.4 V threshold applies.
        if volts is None:
            message = (
                f"Unreadable ATRV voltage ({atrv.text!r}); threshold {_decimal(VOLTAGE_MIN_V)} V is not enforced"
            )
            self._adapter["voltage_warning"] = message
            self._warn(step, WARNING_VOLTAGE_UNREADABLE, message, ctx=ctx)
        elif volts < VOLTAGE_MIN_V:
            message = (
                f"Voltage {_decimal(volts)} V below the threshold {_decimal(VOLTAGE_MIN_V)} V; "
                "threshold is not enforced"
            )
            self._adapter["voltage_warning"] = message
            self._warn(step, WARNING_VOLTAGE_LOW, message, ctx=ctx)

    def _step_pp(self, step: ProbeStep, ctx: _StepContext) -> None:
        reply = self._query(ctx, AdapterQuery.ATPPS)
        if reply.outcome is ReplyOutcome.VALUE:
            self._adapter["pp"] = dict(_PP_RE.findall("\n".join(reply.lines)))

    def _step_protocol_info(self, step: ProbeStep, ctx: _StepContext) -> None:
        for query, key in ((AdapterQuery.ATDPN, "dpn"), (AdapterQuery.STPR, "stpr"), (AdapterQuery.STPRS, "stprs")):
            self._adapter[key] = self._value(self._query(ctx, query))

    def _step_probe_commands(self, step: ProbeStep, ctx: _StepContext) -> None:
        for command in ProbeCommand:
            ctx.line = command.value
            reply = self.driver.probe_command(command)
            item = self._reply_item(command.value, reply)
            ctx.add(item)
            status = item.result if item.result in (ItemStatus.OK, ItemStatus.UNSUPPORTED) else "untested"
            self._commands[_command_key(command.value)] = str(status)

    # -- stages B to D --------------------------------------------------------

    def _step_open_protocol(self, step: ProbeStep, ctx: _StepContext) -> None:
        self._sequence(ctx, OPEN_PROTOCOL_LINES, self.driver.open_protocol)

    def _step_lines(self, step: ProbeStep, ctx: _StepContext) -> list[tuple[bytes, Any]]:
        """Runs the `SELECT` and `UDS` lines of the step; returns (payload, read result) pairs."""
        values: list[tuple[PlanLine, Any]] = []
        self._run_lines(step, ctx, step.lines, values)
        return [(line.payload, value) for line, value in values if line.payload is not None]

    def _run_lines(
        self,
        step: ProbeStep,
        ctx: _StepContext,
        lines: Sequence[PlanLine],
        values: list[tuple[PlanLine, Any]],
    ) -> None:
        """`SELECT` and `UDS` lines and adapter queries (`AdapterQuery`) in plan order.

        In practice adapter queries occur only in the engine sample lines
        (`ATRV`); steps with their own adapter commands have separate handlers.

        `values` receives (plan line, result) pairs: the UDS read result or
        the adapter response; the list grows as lines run, so an exception
        keeps the results of the lines already executed.
        """
        index = 0
        while index < len(lines):
            line = lines[index]
            if line.kind is LineKind.SELECT:
                end = index
                while end < len(lines) and lines[end].kind is LineKind.SELECT and lines[end].target == line.target:
                    end += 1
                self._select(ctx, str(line.target))
                index = end
                continue
            if line.kind is LineKind.UDS and line.payload is not None and line.target is not None:
                self._ensure_target(ctx, line.target)
                for _ in range(line.repeat):
                    values.append((line, self._uds(ctx, line.line, line.payload)))
                index += 1
                continue
            if line.kind is LineKind.ADAPTER and line.line in _ADAPTER_QUERIES:
                values.append((line, self._query(ctx, AdapterQuery(line.line))))
                index += 1
                continue
            raise ValueError(f"Step {step.number}: line {line.line!r} has no handler in the runner")

    def _step_gateway_dtc(self, step: ProbeStep, ctx: _StepContext) -> None:
        """Step 16: 1902FF, conditionally 1903 and 1904 for the records from 1903 (rec other than FF, max. 10)."""
        values = self._step_lines(step, ctx)
        report_by_mask = next(
            (value for payload, value in values if payload == READ_DTC_BY_MASK and isinstance(value, DtcReport)),
            None,
        )
        if report_by_mask is None or not report_by_mask.records:
            return
        target = self._current_target()
        snapshot_ids = self._uds(ctx, stpx_line(target, READ_DTC_SNAPSHOT_IDS), READ_DTC_SNAPSHOT_IDS)
        if not isinstance(snapshot_ids, DtcReport):
            return
        records = [(dtc, record) for dtc, record in snapshot_ids.snapshot_ids if record != 0xFF]
        for dtc, record in records[:MAX_SNAPSHOT_RECORDS]:
            payload = dtc_snapshot_payload(dtc, record)
            self._uds(ctx, stpx_line(target, payload), payload)

    def _step_segmentation(self, step: ProbeStep, ctx: _StepContext) -> None:
        """Step 22: `STCSEGR1`, `STPX` through `driver.transact`, `STCSEGR0` after a successful `STCSEGR1`."""
        uds_line: PlanLine | None = None
        previous: PlanLine | None = None
        for line in step.lines:
            if line.kind is LineKind.SELECT:
                same_group = (
                    previous is not None and previous.kind is LineKind.SELECT and previous.target == line.target
                )
                if not same_group:
                    self._select(ctx, str(line.target))
            elif line.kind is LineKind.UDS:
                uds_line = line
            previous = line
        if uds_line is None or uds_line.payload is None or uds_line.target is None:
            raise ValueError(f"Step {step.number}: no STPX line in the plan")
        self._ensure_target(ctx, uds_line.target)
        if self._segmentation(ctx, True).outcome is not ReplyOutcome.OK:
            return
        try:
            self._raw_stpx(ctx, uds_line.line, uds_line.payload)
        except KeyboardInterrupt:
            raise  # the interrupted command waits for `>`; drained in `_finish_pending` at the start of stage E
        except BaseException:
            # After a transport error and after a detected reset the driver would reject STCSEGR0 without a write.
            if not self.driver.transport_failed and self.driver.adapter_reset is None:
                try:
                    self._segmentation(ctx, False)
                except (AdapterError, TransportError, ReadOnlyViolation) as exc:
                    ctx.add(ItemResult(line="STCSEGR0", result=ItemStatus.ERROR.value, error=_describe(exc)))
            raise
        self._segmentation(ctx, False)

    def _segmentation(self, ctx: _StepContext, enabled: bool) -> AdapterReply:
        line = "STCSEGR1" if enabled else "STCSEGR0"
        ctx.line = line
        reply = self.driver.set_rx_segmentation(enabled)
        ctx.add(self._reply_item(line, reply))
        return reply

    def _raw_stpx(self, ctx: _StepContext, line: str, payload: bytes) -> None:
        ctx.line = line
        exchange = self.driver.transact(payload)
        if self._current_repeat is None:
            self._stcsegr1 = exchange.lines
        token = exchange.error_token
        if token is None:
            result = ItemStatus.OK
        elif token == "?":
            result = ItemStatus.UNSUPPORTED
        elif token == "NO DATA":
            result = ItemStatus.NO_DATA
        else:
            result = ItemStatus.ERROR
        ctx.add(self._exchange_item(line, result, exchange))
        if token in _BUS_ERROR_TOKENS:
            raise _StepStop(f"{token} on the CAN bus in step 22", EXIT_STOP)

    # -- target and UDS -------------------------------------------------------

    def _current_target(self) -> EcuTarget:
        target = self.driver.target
        if target is None:
            raise AdapterError("No target selected for the UDS request")
        return target

    def _ensure_target(self, ctx: _StepContext, address: str) -> None:
        """Selects the target when the current one is different or not configured (e.g. after a skipped step)."""
        if (
            self._client is None
            or self._ecu() != address
            or self.driver.state is not DriverState.TARGET_SELECTED
        ):
            self._select(ctx, address)

    def _select(self, ctx: _StepContext, address: str) -> None:
        target = self.catalog.get(address)
        ctx.line = address_lines(target)[0]
        before = len(self.driver.fc_attempts)
        try:
            self.driver.select_target(target)
        except DriverError as exc:
            self._select_items(ctx, target, before, exc)
            ctx.recorded = True
            raise
        self._select_items(ctx, target, before, None)
        self._connection = ElmUdsConnection(self.driver)
        self._client = ReadOnlyUdsClient(self._connection, self.policy)

    def _select_items(self, ctx: _StepContext, target: EcuTarget, before: int, exc: DriverError | None) -> None:
        addressing = address_lines(target)
        if exc is not None and exc.rule in (RULE_STATE, RULE_TARGET):
            ctx.add(ItemResult(line=addressing[0], result=ItemStatus.ERROR.value, error=str(exc)))
            return
        if exc is not None and exc.line in addressing:
            index = addressing.index(exc.line)
            for line in addressing[:index]:
                ctx.add(self._ok_item(line))
            ctx.add(self._reply_item(exc.line, exc.reply, error=str(exc)))
            return
        for line in addressing:
            ctx.add(self._ok_item(line))
        attempts = self.driver.fc_attempts[before:]
        for attempt in attempts:
            response = "OK" if attempt.result == "ok" else "?"
            ctx.add(ItemResult(line=attempt.line, result=attempt.result, response=response, lines=(response,)))
        if exc is not None and exc.rule != RULE_FC_UNAVAILABLE:
            reply = exc.reply
            ctx.add(
                ItemResult(
                    line=exc.line or addressing[0],
                    result=ItemStatus.ERROR.value,
                    response=reply.text if reply is not None else None,
                    error=str(exc),
                    lines=reply.lines if reply is not None else (),
                )
            )

    def _uds(self, ctx: _StepContext, line: str, payload: bytes) -> Any:
        """One request through `ReadOnlyUdsClient`; returns the read result or None."""
        ctx.line = line
        connection = self._connection
        try:
            value = self._dispatch_uds(bytes(payload))
        except UdsNegativeResponse as exc:
            ctx.add(self._exchange_item(line, ItemStatus.NRC, exc.exchange, nrc=f"{exc.nrc:02X}"))
            return None
        except NoResponse as exc:
            ctx.add(self._exchange_item(line, ItemStatus.NO_DATA, exc.exchange))
            return None
        except ResponsePendingUnresolved as exc:
            ctx.add(self._exchange_item(line, ItemStatus.PENDING_UNRESOLVED, exc.exchange))
            return None
        except AdapterResponseError as exc:
            exchange = exc.exchange if isinstance(exc.exchange, UdsExchange) else None
            token = exchange.error_token if exchange is not None else None
            if token == "?":
                ctx.add(self._exchange_item(line, ItemStatus.UNSUPPORTED, exchange))
                return None
            ctx.add(self._exchange_item(line, ItemStatus.ERROR, exchange, error=str(exc)))
            if token in _BUS_ERROR_TOKENS:
                raise _StepStop(f"{token} on the CAN bus", EXIT_STOP) from exc
            return None
        except UdsError as exc:
            exchange = getattr(exc, "exchange", None)
            exchange = exchange if isinstance(exchange, UdsExchange) else None
            ctx.add(self._exchange_item(line, ItemStatus.ERROR, exchange, error=_describe(exc)))
            return None
        exchange = connection.last_exchange if connection is not None else None
        data = value if isinstance(value, bytes) else None
        ctx.add(self._exchange_item(line, ItemStatus.OK, exchange, data=data))
        if payload == _INSTALLATION_PAYLOAD and data is not None and self._current_repeat is None:
            self._installation_raw = data
        return value

    def _dispatch_uds(self, payload: bytes) -> Any:
        """Client method for the plan payload; any other payload shape goes through policy evaluation."""
        client = self._client
        if client is None:
            raise AdapterError("No UDS client: no target selected")
        if len(payload) == 3 and payload[0] == 0x22:
            return client.read_did(int.from_bytes(payload[1:3], "big"))
        if len(payload) >= 2 and payload[0] == 0x19:
            sub = payload[1]
            if sub in (DtcReportType.NUMBER_BY_MASK, DtcReportType.BY_MASK) and len(payload) == 3:
                return client.read_dtcs(DtcReportType(sub), payload[2])
            if sub in (DtcReportType.SNAPSHOT_IDS, DtcReportType.SUPPORTED) and len(payload) == 2:
                return client.read_dtcs(DtcReportType(sub))
            if sub == 0x04 and len(payload) == 6:
                return client.read_dtc_snapshot(int.from_bytes(payload[2:5], "big"), payload[5])
        self._reject_payload(payload)
        raise UdsError(f"No read-only client method for payload {payload.hex().upper()}")

    def _reject_payload(self, payload: bytes) -> None:
        """Policy evaluation for a payload without a client method; rejection: `guard` event and exception."""
        decision = self.policy.check_uds(payload)
        if decision.allowed:
            return
        subject = payload.hex().upper()
        self.driver.log.emit(
            EventKind.GUARD,
            Layer.UDS,
            subject,
            ecu=self._ecu(),
            guard={"decision": "rejected", "rule": decision.rule, "reason": decision.reason},
            meta={"source": "probe_runner"},
        )
        raise ReadOnlyViolation(LAYER_UDS, decision.rule, decision.reason or "", subject)

    def _exchange_item(
        self,
        line: str,
        result: ItemStatus,
        exchange: UdsExchange | None,
        *,
        nrc: str | None = None,
        error: str | None = None,
        data: bytes | None = None,
    ) -> ItemResult:
        if exchange is None:
            return ItemResult(line=line, result=result.value, nrc=nrc, error=error, data=data)
        if exchange.final is not None:
            response: str | None = exchange.final.hex().upper()
        else:
            response = exchange.error_token
        return ItemResult(
            line=exchange.line,
            result=result.value,
            response=response,
            nrc=nrc,
            error=error,
            pending_count=exchange.pending_count,
            elapsed_ms=exchange.elapsed_ms,
            lines=exchange.lines,
            data=data,
        )

    # -- engine state (package D) ---------------------------------------------

    def _sample_point(self, step: ProbeStep, *, record: bool) -> EngineSample | None:
        """Sample before step `step`, evaluation of the previous module step and pending repeats.

        Returns the last sample (the "before" sample of step `step`) or None after a stop.
        With `record=True` step `step` gets the result `error` (sample error) or
        `skipped` (stop in a repeat), because it will not be executed.
        """
        sample = self._take_sample(step, None, record=record)
        if sample is None:
            return None
        self._close_open(step, sample)
        while self._stop is None and self._pending_repeats and sample.state == EngineState.RUNNING:
            repeated = self._pending_repeats.pop(0)
            self._run_repeat(repeated, sample)
            if self._stop is not None:
                break
            after = self._take_sample(step, repeated.number, record=record)
            if after is None:
                return None
            sample = after
            self._close_open(step, sample)
        if self._stop is not None:
            if record and not self._has_original(step):
                self._record_skipped(step)
            return None
        return sample

    def _final_sample(self) -> None:
        """Stage E sample (the `sample` lines of step 26) after the last module step; only without a stop and with an open protocol.

        A stop in this sample (e.g. Ctrl-C) leaves `error` items for step 26
        (`_carry`), so step 26 has the result `error`, also when it is skipped.
        """
        final = self._final_step()
        if final is None or not final.sample or self._stop is not None:
            return
        if self.driver.state not in (DriverState.PROTOCOL_OPEN, DriverState.TARGET_SELECTED):
            return
        try:
            self._sample_point(final, record=False)
        except KeyboardInterrupt:
            self._interrupt(final)
            self._carry_error(final, ItemResult(line="", result=ItemStatus.ERROR.value, error=_INTERRUPTED))

    def _final_step(self) -> ProbeStep | None:
        """The stage E step with an engine sample (step 26) or None."""
        return next((step for step in self.steps if step.stage is ProbeStage.E and step.sample), None)

    def _take_sample(self, step: ProbeStep, after_repeat: int | None, *, record: bool) -> EngineSample | None:
        """Sample lines `step.sample` (ATRV, selecting engine 01, `22 F40C`, reselecting the step target); None after a stop.

        NRC, NO DATA and other engine speed read errors, an engine selection
        error and an `STPX` timeout with a successful read drain
        (`StpxTimeout.drained`) give the state `unknown` without a stop.
        Ctrl-C, adapter reset, transport error, timeout without drain and a
        guard violation behave as in a step (`_run_guarded`); `error` items go
        to step `step` (result `error` immediately with `record=True`,
        otherwise when the step is executed).
        """
        ctx = _StepContext(step)
        values: list[tuple[PlanLine, Any]] = []

        def body() -> None:
            self._marker(step, "start", None, kind=SAMPLE_MARKER, after_repeat=after_repeat)
            self._sample_lines(step, ctx, values)

        self._run_guarded(step, ctx, body)
        voltage: float | None = None
        rpm_data: bytes | None = None
        for line, value in values:
            if isinstance(value, AdapterReply):
                text = self._value(value)
                voltage = parse_voltage(text) if text is not None else None
            elif line.kind is LineKind.UDS:
                rpm_data = value if isinstance(value, bytes) else None
        rpm = decode_rpm(rpm_data)
        sample = EngineSample(step.number, after_repeat, voltage, rpm, engine_state(rpm))
        self._samples.append(sample)
        try:
            self._marker(step, "end", sample.state.value, kind=SAMPLE_MARKER, after_repeat=after_repeat)
        except KeyboardInterrupt:
            self._interrupt(step)
        if self._stop is None:
            self._check_voltage(step, sample)
        if self._stop is not None:
            # Sample line errors come before the interruption in `on_warning` (already in `_carry`).
            errors = [item for item in ctx.items if item.result == ItemStatus.ERROR]
            self._carry[step.number] = errors + self._carry.get(step.number, [])
            if not self._carry[step.number]:
                self._carry_error(step, ItemResult(line="", result=ItemStatus.ERROR.value, error=self._stop.reason))
            if record:
                self._record_failed(step)
            return None
        return sample

    def _sample_lines(self, step: ProbeStep, ctx: _StepContext, values: list[tuple[PlanLine, Any]]) -> None:
        """Sample lines in plan order: adapter queries, the engine 01 part, reselecting the step target.

        After a failed engine FC configuration (`_engine_disabled`) the engine
        part is skipped. Reselecting the step target goes through `_ensure_target`,
        so the selection lines are sent only when the current target is different.
        """
        adapter = [line for line in step.sample if line.kind is LineKind.ADAPTER]
        engine = [line for line in step.sample if line.target == ADDRESS_ENGINE]
        restore = next(
            (line.target for line in step.sample if line.target is not None and line.target != ADDRESS_ENGINE),
            None,
        )
        self._run_lines(step, ctx, adapter, values)
        if engine and not self._engine_disabled:
            self._sample_engine(step, ctx, engine, values)
        if restore is not None and self._stop is None:  # Ctrl-C in `on_warning` stops further lines
            self._ensure_target(ctx, restore)

    def _sample_engine(
        self, step: ProbeStep, ctx: _StepContext, lines: Sequence[PlanLine], values: list[tuple[PlanLine, Any]]
    ) -> None:
        """Selecting engine 01 and reading the engine speed; errors without consequences for the session give the state `unknown` without a stop.

        A failed engine FC configuration disables the engine part in the
        following samples and gives one `engine_unavailable` warning. An engine
        speed read timeout with a successful drain (`drained`) is an `error`
        item of the sample. The remaining exceptions (reset, transport, timeout
        without drain) go to `_run_guarded`.
        """
        rpm_line = next((line.line for line in lines if line.kind is LineKind.UDS), None)
        try:
            self._run_lines(step, ctx, lines, values)
        except DriverError as exc:
            if exc.rule in (RULE_STATE, RULE_TARGET) or not self._session_usable():
                raise
            ctx.recorded = False
            if self._engine_fc_failed(exc):
                self._engine_disabled = True
                self._warn(
                    step,
                    WARNING_ENGINE_UNAVAILABLE,
                    "Engine state detection inactive: failed Flow Control configuration of engine 01 "
                    f"({exc.line or 'no FC strategy'}). Following samples ATRV only (state unknown); "
                    "the probe continues.",
                )
            return
        except StpxTimeout as exc:
            if not exc.drained or not self._session_usable():
                raise
            ctx.add(self._exchange_item(ctx.line, ItemStatus.ERROR, exc.exchange, error=str(exc)))
            self._rpm_results.append(ItemStatus.ERROR.value)
            return
        result = next((item.result for item in reversed(ctx.items) if item.line == rpm_line), None)
        if result is not None:
            self._rpm_results.append(result)

    def _session_usable(self) -> bool:
        """Session without a transport error and without a detected adapter reset (further lines allowed)."""
        return not self.driver.transport_failed and self.driver.adapter_reset is None

    def _engine_fc_failed(self, exc: DriverError) -> bool:
        """Engine 01 selection error in the FC configuration (pair, filter or no strategy), not in the addressing."""
        if exc.rule == RULE_FC_UNAVAILABLE:
            return True
        return exc.line is not None and exc.line not in address_lines(self.catalog.get(ADDRESS_ENGINE))

    def _report_engine_unavailable(self) -> None:
        """One `engine_unavailable` warning when every engine speed read returned NRC or NO DATA.

        Requires a bus response (an NRC to the engine speed read or a positive
        `STPX` response in steps 12 to 25); with a silent bus the cause is the
        step 12 stop, not missing engine speed.
        """
        final = self._final_step()
        if final is None or not self._rpm_results or not self._samples:
            return
        if not all(result in (ItemStatus.NRC, ItemStatus.NO_DATA) for result in self._rpm_results):
            return
        if ItemStatus.NRC not in self._rpm_results and not self._bus_answered():
            return
        self._warn(
            final,
            WARNING_ENGINE_UNAVAILABLE,
            "Engine state detection inactive: engine control unit 01 does not report engine speed "
            f"(22 F40C: NRC or NO DATA in all samples, {len(self._rpm_results)}). "
            "Engine state changes are not detected, step repeats do not work.",
            step=self._samples[-1].step,
        )

    def _bus_answered(self) -> bool:
        """Whether any module step (12 to 25) got a positive response to `STPX`."""
        return any(
            item.result == ItemStatus.OK and item.line.startswith("STPX ")
            for result in self._results
            if result.step in _NRC78_STEPS
            for item in result.items
        )

    def _carry_error(self, step: ProbeStep, item: ItemResult) -> None:
        """An `error` item for step `step`, which gets its result later (sample, `on_warning`)."""
        self._carry.setdefault(step.number, []).append(item)

    def _close_open(self, at: ProbeStep, after: EngineSample) -> None:
        """Evaluation of the module step waiting for the "after" sample: change marker, repeat queue, missing measurement."""
        current, self._open = self._open, None
        if current is None:
            return
        before, number = current.before, current.step.number
        event: str | None = None
        if state_changed(before.state, after.state):
            event = engine_event_text(before.state, after.state)
            self._results[current.index] = replace(self._results[current.index], engine_event=event)
        if current.repeat_of is not None:
            if after.state != EngineState.RUNNING:
                detail = f"in the repeat {event}" if event else f"after the repeat engine state: {after.state}"
                self._missing(at, number, detail)
            return
        if event is None:
            return
        self._warn(
            at,
            WARNING_ENGINE_EVENT,
            f"Step {number}: {event}; result recorded with a marker, the step will be repeated once "
            "when the engine is running stably.",
            step=number,
        )
        if number not in self._repeated and current.step not in self._pending_repeats:
            self._pending_repeats.append(current.step)

    def _run_repeat(self, step: ProbeStep, before: EngineSample) -> None:
        """One repeat of a module step along the same path as the original (`repeat_of`)."""
        self._repeated.append(step.number)
        index = len(self._results)
        self._execute(step, repeat_of=step.number)
        self._open = _OpenStep(step, before, index, step.number)

    def _report_missing(self) -> None:
        """End of stages B to D: steps without a measurement with the engine running (pending or interrupted repeats).

        Ctrl-C in `on_warning` then applies to step 26 (the next one to run).
        """
        current = self._open
        final = self._final_step()
        if current is not None and current.repeat_of is not None:
            self._open = None
            self._missing(final or current.step, current.step.number, "repeat without a sample after the step")
        for step in self._pending_repeats:
            self._missing(final or step, step.number, "after the state change the engine was not running stably")
        self._pending_repeats.clear()

    def _missing(self, at: ProbeStep, number: int, detail: str) -> None:
        if number in self._missing_running:
            return
        self._missing_running.append(number)
        self._warn(
            at,
            WARNING_NO_RUNNING,
            f"Step {number}: no module measurement with the engine running ({detail}).",
            step=number,
        )

    def _has_original(self, step: ProbeStep) -> bool:
        return any(result.step == step.number and result.repeat_of is None for result in self._results)

    def _record_failed(self, step: ProbeStep) -> None:
        """Step not executed after a stop in its sample or in `on_warning`: result `error` with the carried-over items."""
        errors = self._carry.pop(step.number, [])
        if not errors:
            reason = self._stop.reason if self._stop is not None else _INTERRUPTED
            errors = [ItemResult(line="", result=ItemStatus.ERROR.value, error=reason)]
        step_result = self._step_result(step, ItemStatus.ERROR.value, errors)
        self._results.append(step_result)
        self._notify(step, step_result, marker=False)

    def _check_voltage(self, step: ProbeStep, sample: EngineSample) -> None:
        """Threshold 13.2 V with the engine running, 12.4 V with the engine off or unknown; `cranking` not evaluated."""
        volts = sample.voltage_v
        if volts is None:
            return
        place = self._sample_place(step, sample)
        if sample.state == EngineState.RUNNING and volts < CHARGING_MIN_V:
            self._warn(
                step,
                WARNING_CHARGING_LOW,
                f"Voltage {_decimal(volts)} V with the engine running ({place}) below the threshold "
                f"{_decimal(CHARGING_MIN_V)} V; the alternator may not be charging. The probe continues.",
            )
        elif sample.state in (EngineState.OFF, EngineState.UNKNOWN) and volts < VOLTAGE_MIN_V:
            self._warn(
                step,
                WARNING_VOLTAGE_LOW,
                f"Voltage {_decimal(volts)} V ({place}, engine: {sample.state.value}) below the threshold "
                f"{_decimal(VOLTAGE_MIN_V)} V; threshold is not enforced",
            )

    @staticmethod
    def _sample_place(step: ProbeStep, sample: EngineSample) -> str:
        if sample.after_repeat is not None:
            return f"sample after the repeat of step {sample.after_repeat}"
        if step.stage is ProbeStage.E:
            return "sample in stage E"
        return f"sample before step {step.number}"

    def _warn(
        self,
        at: ProbeStep,
        kind: str,
        message: str,
        *,
        step: int | None = None,
        ctx: _StepContext | None = None,
    ) -> None:
        """Non-stopping warning; kinds other than `engine_event` and `engine_no_running` once per session.

        Ctrl-C in `on_warning` is an interruption of step `at`: stop with code 4
        and an `error` item in `ctx` (the running step) or carried over to the
        result of step `at` (`_carry`).
        """
        if kind not in (WARNING_ENGINE_EVENT, WARNING_NO_RUNNING):
            if kind in self._warned_kinds:
                return
            self._warned_kinds.add(kind)
        warning = ProbeWarning(kind, at.number if step is None else step, message)
        self._warnings.append(warning)
        if self._on_warning is None:
            return
        try:
            self._on_warning(warning)
        except KeyboardInterrupt:
            self._interrupt(at)
            item = ItemResult(line="", result=ItemStatus.ERROR.value, error=_INTERRUPTED)
            if ctx is not None:
                ctx.add(item)
            else:
                self._carry_error(at, item)

    # -- stage E --------------------------------------------------------------

    def _step_status(self, step: ProbeStep, ctx: _StepContext) -> None:
        ctx.line = AdapterQuery.ATRV.value
        status = self.driver.read_status()
        voltage = None if status.voltage_v is None else f"{status.voltage_v:.1f}V"
        result = ItemStatus.OK.value if status.voltage_v is not None else ItemStatus.ERROR.value
        ctx.add(ItemResult(line=AdapterQuery.ATRV.value, result=result, response=voltage))
        ctx.add(
            ItemResult(
                line=AdapterQuery.ATCS.value,
                result=ItemStatus.OK.value,
                response=status.can_status,
                elapsed_ms=self._elapsed(),
                lines=tuple(status.can_status.splitlines()),
            )
        )
        self._atcs = status.can_status

    def _step_close(self, step: ProbeStep, ctx: _StepContext) -> None:
        ctx.line = "STPC"
        before = self.driver.log.counters["lines_tx"]
        reply = self.driver.close(after_transport_error=self._close_without_lines())
        if reply is not None:
            ctx.add(self._reply_item("STPC", reply))
        elif self.driver.log.counters["lines_tx"] > before:
            ctx.add(ItemResult(line="STPC", result=ItemStatus.ERROR.value, error="No response to STPC"))

    # -- result ---------------------------------------------------------------

    def _build_result(self) -> ProbeResult:
        steps = tuple(self._results)
        commands = {_command_key(command.value): "untested" for command in ProbeCommand}
        commands.update(self._commands)
        for key in _FC_COMMAND_KEYS:
            commands.setdefault(key, "untested")
        for index, attempt in enumerate(self.driver.fc_attempts):
            if index in self._repeat_fc_attempts:
                continue
            key = _command_key(attempt.line)
            if commands.get(key) != "ok":
                commands[key] = attempt.result
        timing_values = [
            item.elapsed_ms
            for step in steps
            if step.step == _TIMING_STEP and step.repeat_of is None
            for item in step.items
            if item.result == ItemStatus.OK and item.elapsed_ms is not None
        ]
        timing = {TIMING_KEY: timing_stats(timing_values)} if timing_values else {}
        nrc_items = [
            item for step in steps if step.step in _NRC78_STEPS and step.repeat_of is None for item in step.items
        ]
        strategy = self.driver.fc_strategy
        stop = self._stop
        return ProbeResult(
            steps=steps,
            outcome=self._outcome.value,
            stop=stop,
            run_exit_code=stop.exit_code if stop is not None else EXIT_OK,
            adapter=dict(self._adapter),
            commands=commands,
            fc_strategy=strategy.value if strategy is not None else None,
            nrc78_mode=nrc78_mode(nrc_items),
            timing=timing,
            stcsegr1_lines=self._stcsegr1,
            installation=self._installation(),
            atcs=self._atcs,
            engine={
                "samples": [sample.as_dict() for sample in self._samples],
                "repeated": list(self._repeated),
                "missing_running": list(self._missing_running),
            },
            warnings=tuple(self._warnings),
        )

    def _installation(self) -> dict[str, Any] | None:
        """The 2A2A list (80 entries of 1 byte each, 00 empty) compared with the catalog."""
        raw = self._installation_raw
        if raw is None:
            return None
        addresses: list[str] = []
        for byte in raw:
            address = f"{byte:02X}"
            if byte and address not in addresses:
                addresses.append(address)
        known = {entry.address for entry in self.catalog.entries()}
        uds = [target.vag_address for target in self.catalog.all_uds()]
        return {
            "addresses": addresses,
            "not_in_catalog": [address for address in addresses if address not in known],
            "catalog_uds_missing": [address for address in uds if address not in addresses],
        }


# ---------------------------------------------------------------------------
# Session


def _local_now() -> datetime:
    return datetime.now().astimezone()


def _iso(moment: datetime) -> str:
    return moment.isoformat(timespec="milliseconds")


def _no_sleep(seconds: float) -> None:
    """Wait skipped in dry-run (`NullTransport` has no hardware to protect)."""


@contextmanager
def _sigint_deferred() -> Iterator[list[int]]:
    """Defers SIGINT (Ctrl-C) for the duration of the block; yields the list of received signals.

    Works only in the main thread and with a SIGINT handler set from Python;
    in all other cases the block runs unchanged.
    """
    received: list[int] = []
    previous = signal.getsignal(signal.SIGINT)
    if threading.current_thread() is not threading.main_thread() or previous is None:
        yield received
        return

    def handler(signum: int, frame: object) -> None:
        received.append(signum)

    signal.signal(signal.SIGINT, handler)
    try:
        yield received
    finally:
        signal.signal(signal.SIGINT, previous)


def _package_version(name: str) -> str | None:
    try:
        return version(name)
    except PackageNotFoundError:
        return None


def run_probe_session(
    mode: ProbeMode | str,
    transport: ByteTransport,
    catalog: EcuCatalog,
    *,
    note: str | None = None,
    odometer_km: int | None = None,
    preflight: str = PreflightMode.NOT_APPLICABLE.value,
    argv: Sequence[str] = (),
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    now: Callable[[], datetime] | None = None,
    root: Path = Path("."),
    steps: Sequence[ProbeStep] | None = None,
    on_step: Callable[[StepResult], None] | None = None,
    on_warning: Callable[[ProbeWarning], None] | None = None,
) -> ProbeSession:
    """Full probe session: log, runner, `session_end`, audit, final exit code and probe file (`live`).

    Parameters:
        mode: `live` (`--execute`) or `dry-run`.
        transport: byte medium (opened only in step 1).
        catalog: ECU catalog; `ReadOnlyPolicy` and the plan are built from it.
        note, odometer_km, preflight, argv: `session_start` metadata.
        clock, sleep: monotonic clock and driver wait.
        now: local time with time zone (`session_id`, `tw`, `started_at`).
        root: project directory for `data/sessions/` and `data/probes/`.
        steps: plan steps (default `build_steps(catalog)`).
        on_step: called after each step (progress on stderr in the CLI).
        on_warning: called at the moment a non-stopping warning is detected (stderr in the CLI).

    Completion order (M2 audit): `session_end` with `run_exit_code`, closing
    the JSONL, `audit_session`, final exit code (2 on a violation, otherwise
    `run_exit_code`), a single atomic write of the probe file (`live` only).
    Ctrl-C during this sequence is deferred and does not interrupt the write;
    the run is already finished, so the session result does not change, and
    the number of deferred Ctrl-C goes to `ProbeSession.deferred_interrupts`.
    """
    session_mode = ProbeMode(mode)
    now_fn = now or _local_now
    plan_steps = list(steps) if steps is not None else build_steps(catalog)
    command = SessionCommand.PROBE if session_mode is ProbeMode.LIVE else SessionCommand.PROBE_DRY_RUN
    log = TrafficLog.create(command.value, root=root, clock=clock, now=now_fn)
    try:
        started_at = _iso(now_fn())
        start = log.session_start(
            {
                "tool_version": __version__,
                "transport_url": transport.url,
                "baud": BAUD,
                "mode": session_mode.value,
                "argv": list(argv),
                "odometer_km": odometer_km,
                "note": note,
                "preflight": str(preflight),
                "python": platform.python_version(),
                "udsoncan": _package_version("udsoncan"),
            }
        )
        driver = StnDriver(transport, ReadOnlyPolicy(catalog), log, clock=clock, sleep=sleep)
        runner = ProbeRunner(
            driver,
            catalog,
            plan_steps,
            on_step=on_step,
            stop_on_silent_bus=session_mode is ProbeMode.LIVE,
            on_warning=on_warning,
        )
        result = runner.run()
        with _sigint_deferred() as deferred:
            try:
                log.session_end({"atcs": result.atcs, "run_exit_code": result.run_exit_code})
                finished_at = _iso(now_fn())
            finally:
                log.close()
            session = _finalize_session(
                session_mode,
                log,
                transport,
                catalog,
                result,
                root=root,
                started_at=started_at,
                finished_at=finished_at,
                start_meta=start["meta"],
                note=note,
                odometer_km=odometer_km,
                preflight=str(preflight),
            )
        if deferred:
            session = replace(session, deferred_interrupts=len(deferred))
        return session
    finally:
        log.close()


def _finalize_session(
    session_mode: ProbeMode,
    log: TrafficLog,
    transport: ByteTransport,
    catalog: EcuCatalog,
    result: ProbeResult,
    *,
    root: Path,
    started_at: str,
    finished_at: str,
    start_meta: dict[str, Any],
    note: str | None,
    odometer_km: int | None,
    preflight: str,
) -> ProbeSession:
    """Audit of the closed JSONL, final exit code and a single write of the probe file (`live`)."""
    audit = audit_session(log.path, catalog)
    exit_code = EXIT_VIOLATION if audit.exit_code != EXIT_OK else result.run_exit_code
    probe_path = (
        report.probe_path_for(root, log.path, log.session_id) if session_mode is ProbeMode.LIVE else None
    )
    session = ProbeSession(
        mode=session_mode,
        session_id=log.session_id,
        jsonl_path=log.path,
        probe_path=probe_path,
        started_at=started_at,
        finished_at=finished_at,
        tool_version=__version__,
        commit=start_meta.get("commit"),
        transport_url=transport.url,
        baud=BAUD,
        note=note,
        odometer_km=odometer_km,
        preflight=preflight,
        result=result,
        audit=audit,
        exit_code=exit_code,
        run_exit_code=result.run_exit_code,
    )
    if probe_path is not None:
        report.write_probe_file(probe_path, report.probe_document(session))
    return session


def execute_probe(
    catalog: EcuCatalog,
    transport_factory: Callable[[str], ByteTransport],
    *,
    url: str,
    yes: bool = False,
    stdin: TextIO | Any | None = None,
    stderr: TextIO | Any | None = None,
    note: str | None = None,
    odometer_km: int | None = None,
    argv: Sequence[str] = (),
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    now: Callable[[], datetime] | None = None,
    root: Path = Path("."),
    on_step: Callable[[StepResult], None] | None = None,
    on_warning: Callable[[ProbeWarning], None] | None = None,
) -> ProbeSession:
    """`obdb probe --execute`: preflight, then the transport from the factory and a `live` session.

    Preflight runs before the factory is called and before the JSONL is
    created, so a refusal (`PreflightAborted`, code 1) leaves no files and no open port.
    """
    preflight = confirm(stdin, stderr, yes, url)
    transport = transport_factory(url)
    return run_probe_session(
        ProbeMode.LIVE,
        transport,
        catalog,
        note=note,
        odometer_km=odometer_km,
        preflight=preflight,
        argv=argv,
        clock=clock,
        sleep=sleep,
        now=now,
        root=root,
        on_step=on_step,
        on_warning=on_warning,
    )


def dry_run_probe(
    catalog: EcuCatalog,
    *,
    note: str | None = None,
    odometer_km: int | None = None,
    argv: Sequence[str] = (),
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = _no_sleep,
    now: Callable[[], datetime] | None = None,
    root: Path = Path("."),
    on_step: Callable[[StepResult], None] | None = None,
) -> ProbeSession:
    """`obdb probe --dry-run`: the same stack with `NullTransport`, preflight `n/a`, no probe file."""
    return run_probe_session(
        ProbeMode.DRY_RUN,
        NullTransport(),
        catalog,
        note=note,
        odometer_km=odometer_km,
        preflight=PreflightMode.NOT_APPLICABLE.value,
        argv=argv,
        clock=clock,
        sleep=sleep,
        now=now,
        root=root,
        on_step=on_step,
    )
