"""Audit of a recorded JSONL session (`obdb audit`, spec T10, FR-27, audit M6).

`audit_session(path, catalog)` replays the session from the log and evaluates
every line sent to the adapter with the current read-only policy. The function
is shared by the CLI and by the automatic audit after a probe.

Safety:
    The audit does not trust `state` events or guard decisions recorded in the
    log. The adapter configuration model (`AdapterConfigModel`) is built only
    from `tx`/`rx` pairs of the `transport` layer; every line from the log
    changes the model, including a line rejected by the audit, because the
    model describes the adapter, not the decision. `state` events are checked
    against the transition table on this model, so a forged transition (e.g.
    to TARGET_SELECTED after `ATCAF0`) yields an `AUDIT/state-transition`
    violation, and a subsequent `STPX` an `AUDIT/adapter-config` violation.

Violation cascade:
    A primary violation after which the replayed state is no longer consistent
    (the violating line changed the adapter model, a disallowed state
    transition, a target outside the catalog, or the first
    `AUDIT/adapter-config`) becomes the cause of a cascade. Subsequent
    `AUDIT/adapter-config` and `AUDIT/state-transition` violations are
    secondary and get `caused_by_seq` equal to the `seq` of the cause. The
    cascade ends when `STPX` or a transition to TARGET_SELECTED passes the
    model check again. Text output groups secondary violations into one line
    under the primary violation; `--json` keeps the full list. The exit code
    does not depend on the split.

Adapter reset:
    The audit replays driver reset detection with the same pure function
    (`reset_evidence`): echo after `ATE0`, a banner, `LV RESET`, `SEARCHING` or
    `BUS INIT` in a reply (also one assembled from several `rx` events), and an
    `rx` event with `meta.stale` before a line other than `ATWS` in RAW
    (`stale_input_tolerated`) reset the adapter model. Every later `tx` line
    other than `STPC` yields an `AUDIT/adapter-reset` violation; the first is
    primary, the following ones are secondary.

Exit codes: `AuditResult.exit_code` is 2 when there is at least one violation,
otherwise 0; an invalid or missing file raises `LogFormatError` (code 64).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from obd_bridge.errors import CatalogError, LogFormatError, os_error_text
from obd_bridge.policy import (
    AdapterConfigModel,
    GuardContext,
    ReadOnlyPolicy,
    reply_ok_for,
    reset_evidence,
    stale_input_tolerated,
)
from obd_bridge.policy.adapter_guard import RULE_ADAPTER_CONFIG as LINE_ADAPTER_CONFIG
from obd_bridge.stn.parser import parse_adapter_reply
from obd_bridge.stn.state import DriverState
from obd_bridge.traffic_log import SCHEMA_VERSION, EventKind, Layer, escape, read_events, unescape
from obd_bridge.vag.catalog import EcuCatalog, EcuTarget

__all__ = [
    "JSON_SCHEMA",
    "RULE_ADAPTER_CONFIG",
    "RULE_ADAPTER_RESET",
    "RULE_CHARSET",
    "RULE_FRAMING",
    "RULE_LAYER_MISMATCH",
    "RULE_STATE_TRANSITION",
    "RULE_TARGET",
    "AuditResult",
    "AuditViolation",
    "audit_session",
    "render_json",
    "render_text",
]

JSON_SCHEMA: Final[str] = "obdb.audit/1"
"""Schema identifier of the `--json` output."""

RULE_STATE_TRANSITION: Final[str] = "AUDIT/state-transition"
"""State transition inconsistent with table T10 or with the model replayed from traffic."""

RULE_ADAPTER_CONFIG: Final[str] = "AUDIT/adapter-config"
"""Adapter model condition for `STPX` or `ATFCSM1` not met (guard `LINE/adapter-config`)."""

RULE_ADAPTER_RESET: Final[str] = "AUDIT/adapter-reset"
"""Line other than `STPC` after signs of an adapter reset or a reply desync in the log."""

RULE_TARGET: Final[str] = "AUDIT/target"
"""Target of a `state` event outside the catalog or without a `tx` address."""

RULE_FRAMING: Final[str] = "AUDIT/framing"
"""Transport `tx` bytes without exactly one trailing `\\r`, or containing `\\n`."""

RULE_CHARSET: Final[str] = "AUDIT/charset"
"""Transport `tx` bytes outside ASCII."""

RULE_LAYER_MISMATCH: Final[str] = "AUDIT/layer-mismatch"
"""Transport `tx` without an immediately preceding, allowed adapter `tx` with the same line."""

_CASCADE_RULES: Final[frozenset[str]] = frozenset(
    {RULE_ADAPTER_CONFIG, RULE_STATE_TRANSITION, RULE_ADAPTER_RESET}
)
"""Violation rules that may result from an earlier violation (secondary)."""

_STATE_RULES: Final[frozenset[str]] = frozenset(
    {RULE_ADAPTER_CONFIG, RULE_STATE_TRANSITION, RULE_TARGET, RULE_ADAPTER_RESET}
)
"""Primary violation rules that always make the replayed state or target inconsistent."""

_SEGMENT_SPLIT: Final = re.compile(rb"[\r\n]")
_PROTOCOL_STATES: Final[frozenset[DriverState]] = frozenset(
    {DriverState.PROTOCOL_OPEN, DriverState.TARGET_SELECTED}
)


@dataclass(frozen=True)
class AuditViolation:
    """A single violation detected by the audit.

    Attributes:
        seq: event number in the log.
        line: adapter line (for non-canonical bytes, the `escape` form) or
            None for violations of `state` events.
        rule: rule (guard `LINE/*` or `AUDIT/*`).
        reason: description of the cause.
        caused_by_seq: `seq` of the primary violation this violation results
            from (secondary violation), or None for a primary violation.
    """

    seq: int
    line: str | None
    rule: str
    reason: str
    caused_by_seq: int | None = None

    def to_json(self) -> dict[str, Any]:
        """Form of an entry in the `violations` list of schema `obdb.audit/1`."""
        return {
            "seq": self.seq,
            "line": self.line,
            "rule": self.rule,
            "reason": self.reason,
            "caused_by_seq": self.caused_by_seq,
        }


@dataclass(frozen=True)
class AuditResult:
    """Result of a session audit.

    Attributes:
        path: path of the audited JSONL file.
        mode: `meta.mode` of the `session_start` event, or None.
        checked_tx: number of checked `tx` events of the `transport` layer.
        violations: violations in `seq` order.
        guard_rejections: number of `guard` events (blocked attempts, not violations).
        warnings: warnings (e.g. missing `session_end`).
    """

    path: Path
    mode: str | None
    checked_tx: int
    violations: tuple[AuditViolation, ...]
    guard_rejections: int
    warnings: tuple[str, ...]

    @property
    def exit_code(self) -> int:
        """Exit code: 2 when there is at least one violation, otherwise 0."""
        return 2 if self.violations else 0

    def to_json(self) -> dict[str, Any]:
        """`--json` document in schema `obdb.audit/1`."""
        return {
            "schema": JSON_SCHEMA,
            "path": str(self.path),
            "mode": self.mode,
            "checked_tx": self.checked_tx,
            "violations": [violation.to_json() for violation in self.violations],
            "guard_rejections": self.guard_rejections,
            "warnings": list(self.warnings),
        }


def audit_session(path: Path | str, catalog: EcuCatalog) -> AuditResult:
    """Audits the session log `path` against the catalog `catalog` and the current policy.

    Parameters:
        path: session JSONL file (schema T6).
        catalog: ECU catalog (`EcuCatalog.load()`); the `ReadOnlyPolicy` is built from it.

    Raises:
        LogFormatError: missing file, read error, invalid JSON, broken `seq`
            or an event without required fields (code 64).
    """
    source = Path(path)
    try:
        events = read_events(source)
    except OSError as exc:
        raise LogFormatError(f"Cannot read session file {source}: {os_error_text(exc)}") from exc
    except UnicodeDecodeError as exc:
        raise LogFormatError(
            f"Session file {source} is not valid UTF-8 (invalid byte at position {exc.start})"
        ) from exc
    auditor = _Auditor(source, catalog)
    auditor.run(events)
    return auditor.result()


def render_json(result: AuditResult) -> str:
    """Audit result as JSON (`--json`), non-ASCII characters not escaped."""
    return json.dumps(result.to_json(), ensure_ascii=False, indent=2)


def _secondary_phrase(count: int) -> str:
    """Form of "secondary violation" after a number (singular for 1, plural otherwise)."""
    if count == 1:
        return "secondary violation"
    if count % 10 in (2, 3, 4) and count % 100 not in (12, 13, 14):
        return "secondary violations"
    return "secondary violations"


def render_text(result: AuditResult) -> str:
    """Audit result as text for the terminal.

    Primary violations are printed one by one; secondary ones (with
    `caused_by_seq`) go into one summary line under the last primary violation
    with the `seq` of the cause.
    """
    primary = [v for v in result.violations if v.caused_by_seq is None]
    secondary: dict[int, list[AuditViolation]] = {}
    for violation in result.violations:
        if violation.caused_by_seq is not None:
            secondary.setdefault(violation.caused_by_seq, []).append(violation)
    total = f"Violations: {len(result.violations)}"
    if secondary:
        total += f" (primary: {len(primary)}, secondary: {len(result.violations) - len(primary)})"
    out = [
        f"Session audit: {result.path}",
        f"Mode: {result.mode or 'unknown'}",
        f"Checked tx lines: {result.checked_tx}",
        f"Guard rejections (blocked attempts): {result.guard_rejections}",
        total,
    ]
    for index, violation in enumerate(primary):
        subject = f" {violation.line}" if violation.line is not None else ""
        out.append(f"  seq {violation.seq} [{violation.rule}]{subject}: {violation.reason}")
        following = primary[index + 1] if index + 1 < len(primary) else None
        effects = secondary.get(violation.seq)
        if effects and (following is None or following.seq != violation.seq):
            counts: dict[str, int] = {}
            for effect in effects:
                counts[effect.rule] = counts.get(effect.rule, 0) + 1
            by_rule = ", ".join(f"{rule}: {count}" for rule, count in counts.items())
            out.append(
                f"    and {len(effects)} {_secondary_phrase(len(effects))} "
                f"({by_rule}; seq {effects[0].seq} to {effects[-1].seq}), "
                f"caused by violation seq {violation.seq}"
            )
    if result.warnings:
        out.append(f"Warnings: {len(result.warnings)}")
        out.extend(f"  {warning}" for warning in result.warnings)
    if result.violations:
        out.append(f"Result: violations detected (code {result.exit_code})")
    else:
        out.append(f"Result: no violations (code {result.exit_code})")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Session replay


def _fmt(state: DriverState, address: str | None) -> str:
    """State with target as shown in messages, e.g. `PROTOCOL_OPEN(19)`."""
    return f"{state.value}({address})" if address is not None else state.value


class _Auditor:
    """Audit event loop: state, target and adapter model replayed from traffic."""

    def __init__(self, path: Path, catalog: EcuCatalog) -> None:
        self._path = path
        self._catalog = catalog
        self._policy = ReadOnlyPolicy(catalog)
        self._state = DriverState.CLOSED
        self._target: EcuTarget | None = None
        self._address: str | None = None
        self._model = AdapterConfigModel()
        self._pending: str | None = None
        self._pending_seq: int | None = None
        self._corrupted_by: int | None = None
        self._primary_seqs: set[int] = set()
        # Reply to the last line (also assembled from several `rx` events) for reset detection.
        self._rx_line: str | None = None
        self._rx_raw = b""
        self._rx_format_ok: frozenset[str] = frozenset()
        self._stale_seq: int | None = None
        self._reset: tuple[int, str] | None = None
        self._seen_tx = False
        self._seen_state = False
        self._session_end_seq: int | None = None
        self._after_end_reported = False
        self._mode: str | None = None
        self._sid: str | None = None
        self._checked_tx = 0
        self._guard_rejections = 0
        self._violations: list[AuditViolation] = []
        self._warnings: list[str] = []
        self._prev: dict[str, Any] | None = None

    # -- loop ----------------------------------------------------------------

    def run(self, events: list[dict[str, Any]]) -> None:
        """Processes events in `seq` order (`read_events` checks continuity)."""
        for event in events:
            self._dispatch(event)
            self._prev = event
        if self._prev is not None and self._is(self._prev, EventKind.TX, Layer.ADAPTER):
            self._warn(f"seq {self._prev['seq']}: adapter layer tx without transport layer tx")
        if self._session_end_seq is None:
            self._warn("Missing session_end event: session interrupted or log incomplete")

    def result(self) -> AuditResult:
        """Result after `run`."""
        return AuditResult(
            path=self._path,
            mode=self._mode,
            checked_tx=self._checked_tx,
            violations=tuple(self._violations),
            guard_rejections=self._guard_rejections,
            warnings=tuple(self._warnings),
        )

    def _dispatch(self, event: dict[str, Any]) -> None:
        seq = event["seq"]
        if event.get("v") != SCHEMA_VERSION:
            raise self._format_error(seq, f"unsupported schema version v={event.get('v')!r}")
        ev = self._str(event, "ev")
        layer = self._str(event, "layer")
        sid = event.get("sid")
        if self._sid is None:
            self._sid = sid if isinstance(sid, str) else None
            meta = event.get("meta")
            mode = meta.get("mode") if isinstance(meta, dict) else None
            self._mode = mode if isinstance(mode, str) else None
        elif sid != self._sid:
            self._warn(f"seq {seq}: sid {sid!r} differs from session sid {self._sid!r}")
        if self._session_end_seq is not None and not self._after_end_reported:
            self._after_end_reported = True
            self._warn(f"seq {seq}: events after session_end (seq {self._session_end_seq})")
        if self._prev is not None and self._is(self._prev, EventKind.TX, Layer.ADAPTER):
            if not (ev == EventKind.TX and layer == Layer.TRANSPORT):
                self._warn(f"seq {self._prev['seq']}: adapter layer tx without transport layer tx")

        if ev == EventKind.TX and layer == Layer.TRANSPORT:
            self._tx_transport(seq, self._str(event, "data"))
        elif ev == EventKind.RX and layer == Layer.TRANSPORT:
            meta = event.get("meta")
            stale = isinstance(meta, dict) and meta.get("stale") is True
            self._rx_transport(seq, self._str(event, "data"), stale=stale)
        elif ev == EventKind.STATE:
            self._state_event(seq, event.get("meta"))
        elif ev == EventKind.GUARD:
            self._guard_rejections += 1
        elif ev == EventKind.SESSION_END and self._session_end_seq is None:
            self._session_end_seq = seq

    # -- transport layer tx and rx --------------------------------------------

    def _tx_transport(self, seq: int, data: str) -> None:
        """Check of `tx` bytes: layer pair, framing, charset and policy."""
        self._checked_tx += 1
        self._seen_tx = True
        if self._pending is not None:
            # Previous line without a reply: result unknown, only narrowing effects.
            self._apply(self._pending, False, self._pending_seq)
            self._pending = None
            self._pending_seq = None
        self._rx_line = None
        raw = self._unescape(seq, data)
        framed = raw.endswith(b"\r") and raw.count(b"\r") == 1 and b"\n" not in raw
        ascii_ok = raw.isascii()
        line = raw[:-1].decode("ascii") if framed and ascii_ok else None
        shown = line if line is not None else escape(raw)
        self._check_layer_pair(seq, raw, shown)
        self._check_reset(seq, line, shown)
        if not framed:
            self._violate(
                seq,
                shown,
                RULE_FRAMING,
                "tx bytes must contain exactly one trailing \\r character and no \\n",
            )
        if not ascii_ok:
            self._violate(seq, shown, RULE_CHARSET, "tx bytes contain non-ASCII characters")
        if line is not None:
            self._check_line(seq, line)
            self._pending = line
            self._pending_seq = seq
            return
        # Non-canonical bytes: the adapter may have executed every segment, so each
        # goes to the policy (when ASCII) and to the model without an OK confirmation.
        for segment in _SEGMENT_SPLIT.split(raw):
            if not segment:
                continue
            text = segment.decode("ascii", errors="replace")
            if ascii_ok:
                self._check_line(seq, text)
            self._apply(text, False, seq)

    def _rx_transport(self, seq: int, data: str, *, stale: bool = False) -> None:
        """Adapter reply: model update for the pending line and reset detection."""
        raw = self._unescape(seq, data)
        if stale:
            # Unread bytes before a write: evaluated at the next line (exception: `ATWS` in RAW).
            if self._stale_seq is None:
                self._stale_seq = seq
            return
        if self._pending is None:
            if self._rx_line is not None:
                # Another read window for the same line (extension after 7F xx 78, completion).
                self._rx_raw += raw
                self._detect_reset(seq)
            return  # banner window or reply to non-canonical bytes
        line, line_seq = self._pending, self._pending_seq
        self._pending = None
        self._pending_seq = None
        self._rx_line, self._rx_raw, self._rx_format_ok = line, raw, self._model.format_ok
        self._apply(line, reply_ok_for(line, parse_adapter_reply(raw, line)), line_seq)
        self._detect_reset(seq)

    def _detect_reset(self, seq: int) -> None:
        """Reset signs in the reply (`reset_evidence`, model before the line): empty model, lockout."""
        if self._reset is not None or self._rx_line is None:
            return
        evidence = reset_evidence(self._rx_line, self._rx_raw, self._rx_format_ok)
        if evidence is not None:
            self._mark_reset(seq, evidence)

    def _mark_reset(self, seq: int, evidence: str) -> None:
        self._reset = (seq, evidence)
        self._model = AdapterConfigModel()

    def _check_reset(self, seq: int, line: str | None, shown: str) -> None:
        """Line after reset signs: only `STPC` is allowed (driver lockout `driver/adapter-reset`)."""
        if self._stale_seq is not None:
            stale_seq, self._stale_seq = self._stale_seq, None
            tolerated = line is not None and (line == "STPC" or stale_input_tolerated(line, self._state))
            if not tolerated and self._reset is None:
                self._mark_reset(stale_seq, f"unread bytes before writing line {shown}")
        if self._reset is None or line == "STPC":
            return
        reset_seq, evidence = self._reset
        self._violate(
            seq,
            shown,
            RULE_ADAPTER_RESET,
            f"Line after signs of an adapter reset or a reply desync (seq {reset_seq}: {evidence}); "
            "only STPC is allowed",
        )

    def _apply(self, line: str, reply_ok: bool, line_seq: int | None) -> None:
        """Model update with a line from the log; a violating line that changed the model opens a cascade."""
        before = self._model
        self._model = before.apply(line, reply_ok)
        if line_seq is None or self._model == before:
            return
        if line_seq in self._primary_seqs:
            self._corrupted_by = line_seq

    def _check_layer_pair(self, seq: int, raw: bytes, shown: str) -> None:
        """Transport `tx` requires an immediately preceding adapter `tx` with the same line."""
        prev = self._prev
        if prev is None or not self._is(prev, EventKind.TX, Layer.ADAPTER):
            self._violate(
                seq,
                shown,
                RULE_LAYER_MISMATCH,
                "No immediately preceding adapter layer tx event",
            )
            return
        guard = prev.get("guard")
        decision = guard.get("decision") if isinstance(guard, dict) else None
        if decision != "allowed":
            self._violate(
                seq,
                shown,
                RULE_LAYER_MISMATCH,
                f"Adapter layer tx event (seq {prev['seq']}) without guard decision allowed",
            )
        adapter_line = prev.get("data")
        expected = (
            adapter_line.encode("ascii") + b"\r"
            if isinstance(adapter_line, str) and adapter_line.isascii()
            else None
        )
        if expected != raw:
            self._violate(
                seq,
                shown,
                RULE_LAYER_MISMATCH,
                f"Transport bytes differ from adapter layer line {adapter_line!r} (seq {prev['seq']})",
            )

    def _check_line(self, seq: int, line: str) -> None:
        """Evaluates the line with the current policy in the replayed context."""
        ctx = GuardContext(self._state, self._target, self._catalog, self._model)
        decision = self._policy.check_line(line, ctx)
        if decision.allowed:
            if line.startswith("STPX "):
                self._corrupted_by = None  # model consistent with the target again: end of cascade
            return
        rule = RULE_ADAPTER_CONFIG if decision.rule == LINE_ADAPTER_CONFIG else decision.rule
        reason = decision.reason or "Line rejected by the read-only policy"
        if decision.uds_rule is not None:
            reason = f"{reason} (UDS rule {decision.uds_rule})"
        self._violate(seq, line, rule, reason)

    # -- state events -----------------------------------------------------------

    def _state_event(self, seq: int, meta: Any) -> None:
        """State transition checked against table T10 on the model replayed from traffic."""
        if not isinstance(meta, dict):
            raise self._format_error(seq, "state event without a meta object")
        new_state = self._parse_state(seq, meta.get("state"), "state")
        new_address = self._parse_address(seq, meta.get("target"), "target")
        prev_state = self._parse_state(seq, meta.get("prev_state"), "prev_state")
        prev_address = self._parse_address(seq, meta.get("prev_target"), "prev_target")

        if (prev_state, prev_address) != (self._state, self._address):
            self._violate(
                seq,
                None,
                RULE_STATE_TRANSITION,
                f"State event gives previous state {_fmt(prev_state, prev_address)}, "
                f"but the replayed state is {_fmt(self._state, self._address)}",
            )
        violations_before = len(self._violations)
        new_target = self._resolve_target(seq, new_address)
        reason = self._transition_reason(new_state, new_address, new_target)
        if (
            reason is None
            and new_state is DriverState.TARGET_SELECTED
            and len(self._violations) == violations_before
        ):
            self._corrupted_by = None  # transition to the target passed the model check: end of cascade
        if reason is not None:
            self._violate(
                seq,
                None,
                RULE_STATE_TRANSITION,
                f"Transition {_fmt(self._state, self._address)} → {_fmt(new_state, new_address)}: {reason}",
            )
        self._seen_state = True
        self._state, self._address, self._target = new_state, new_address, new_target

    def _resolve_target(self, seq: int, address: str | None) -> EcuTarget | None:
        """Target from the catalog; an address that is missing or has no `tx` yields an `AUDIT/target` violation."""
        if address is None:
            return None
        try:
            return self._catalog.get(address)
        except CatalogError as exc:
            self._violate(seq, None, RULE_TARGET, f"Target {address} is not a UDS addressee from the catalog: {exc}")
            return None

    def _transition_reason(
        self, new_state: DriverState, new_address: str | None, new_target: EcuTarget | None
    ) -> str | None:
        """Reason why the transition is inconsistent with table T10, or None when it is allowed."""
        old = self._state
        model = self._model
        if new_state is DriverState.CLOSED:
            return None if new_address is None else "state CLOSED cannot have a target"
        if old is DriverState.CLOSED and new_state is DriverState.RAW and new_address is None:
            if self._seen_state:
                return "CLOSED → RAW allowed only as the first state event of the session"
            if self._seen_tx:
                return "CLOSED → RAW after a line was sent to the adapter"
            return None
        if old is DriverState.RAW and new_state is DriverState.READY and new_address is None:
            if not model.formatted:
                return "no ATE0, ATL0, ATS0 and ATH1 with OK since the last ATWS"
            if not model.identified:
                return "no STI with an STN value since the last ATWS"
            return None
        if old is DriverState.READY and new_state is DriverState.PROTOCOL_OPEN and new_address is None:
            if not model.protocol_open:
                return "protocol 33 is not open (no STP33 with OK)"
            if not model.caf1:
                return "no ATCAF1 with OK after STP33"
            if model.fcsm != 0:
                return "adapter FC mode other than 0 (no ATFCSM0 with OK)"
            return None
        if old in _PROTOCOL_STATES and new_state is DriverState.PROTOCOL_OPEN and new_address is not None:
            return None if new_target is not None else f"target {new_address} is not a UDS module from the catalog"
        if (
            old is DriverState.PROTOCOL_OPEN
            and new_state is DriverState.TARGET_SELECTED
            and new_address is not None
            and new_address == self._address
        ):
            if new_target is None:
                return f"target {new_address} is not a UDS module from the catalog"
            return model.check_stpx(new_target)
        return "transition outside the table of allowed transitions"

    # -- helpers ---------------------------------------------------------------

    def _parse_state(self, seq: int, value: Any, key: str) -> DriverState:
        try:
            return DriverState(value)
        except ValueError as exc:
            raise self._format_error(seq, f"meta.{key} {value!r} is not a driver state") from exc

    def _parse_address(self, seq: int, value: Any, key: str) -> str | None:
        if value is None or isinstance(value, str):
            return value
        raise self._format_error(seq, f"meta.{key} must be an address or null, got {value!r}")

    def _str(self, event: dict[str, Any], key: str) -> str:
        value = event.get(key)
        if not isinstance(value, str):
            raise self._format_error(event["seq"], f"field {key} must be a string, got {value!r}")
        return value

    def _unescape(self, seq: int, data: str) -> bytes:
        try:
            return unescape(data)
        except LogFormatError as exc:
            raise self._format_error(seq, str(exc)) from exc

    def _format_error(self, seq: int, message: str) -> LogFormatError:
        return LogFormatError(f"{self._path}: seq {seq}: {message}")

    @staticmethod
    def _is(event: dict[str, Any], ev: EventKind, layer: Layer) -> bool:
        return event.get("ev") == ev and event.get("layer") == layer

    def _violate(self, seq: int, line: str | None, rule: str, reason: str) -> None:
        """Records a violation; cascade rules during a cascade are secondary (`caused_by_seq`)."""
        caused_by: int | None = None
        if rule in _CASCADE_RULES and self._corrupted_by is not None and self._corrupted_by != seq:
            caused_by = self._corrupted_by
        self._violations.append(
            AuditViolation(seq=seq, line=line, rule=rule, reason=reason, caused_by_seq=caused_by)
        )
        if caused_by is None:
            self._primary_seqs.add(seq)
            if rule in _STATE_RULES:
                self._corrupted_by = seq

    def _warn(self, message: str) -> None:
        self._warnings.append(message)
