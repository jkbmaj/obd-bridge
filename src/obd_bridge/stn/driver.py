"""L1 driver of the STN2120 adapter (`StnDriver`, spec T4, FR-07 to FR-10).

The driver runs the state machine CLOSED, RAW, READY, PROTOCOL_OPEN and
TARGET_SELECTED (no BAUD_HANDSHAKE) and builds every adapter line
internally: from enums (`AdapterQuery`, `ProbeCommand`), from `EcuTarget`
and from the UDS payload. Public methods do not accept arbitrary strings.

Safety:
    `_egress` is the only path to `transport.write`. Every line goes through
    `ReadOnlyPolicy.check_line` with a `GuardContext` (state, target,
    catalog, adapter configuration model) before the write; a rejection
    gives a `guard` event, `ReadOnlyViolation` and zero bytes in the
    transport. The driver never retries a line. The FC pair (`STCFCPA`) is
    always sent before the filter (`STFFCA`). After a `TransportError` the
    driver sends no further line, not even `STPC`.

    The pending reply is recorded before the write; until it is read up to
    `>`, `_egress` rejects every new line. A detected adapter reset or reply
    desync (echo after `ATE0`, banner, `LV RESET`, `SEARCHING`, unread bytes
    before a write) clears the configuration model and blocks every further
    line except `STPC` on close. The content of unread bytes goes to the log
    as `rx` events with `meta.stale`; before `ATWS` in RAW (late banner) the
    bytes are discarded without blocking the session.

The line-building functions (`OPEN_PROTOCOL_LINES`, `fc_lines`,
`target_select_lines`, `stpx_line`) are pure and do no I/O; the probe plan
uses them too, so that the plan and the driver produce identical lines.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final, Literal, NoReturn

from obd_bridge.errors import AdapterError, ReadOnlyViolation, TransportError, TransportTimeout
from obd_bridge.policy import (
    LAYER_ADAPTER,
    AdapterConfigModel,
    GuardContext,
    ReadOnlyPolicy,
    reply_ok_for,
    reset_evidence,
    stale_input_tolerated,
)
from obd_bridge.policy.adapter_model import FORMAT_LINES
from obd_bridge.stn.parser import (
    AdapterReply,
    ReplyOutcome,
    UdsExchange,
    parse_adapter_reply,
    parse_uds_exchange,
    split_lines,
)
from obd_bridge.stn.profile import AdapterProfile
from obd_bridge.stn.state import DriverState, FcStrategy
from obd_bridge.traffic_log import EventKind, Layer, TrafficLog, escape
from obd_bridge.transport.base import ByteTransport
from obd_bridge.vag.catalog import CatalogError, EcuCatalog, EcuTarget

__all__ = [
    "BANNER_TIMEOUT_S",
    "COMMAND_TIMEOUT_S",
    "DEFAULT_STPX_TIMEOUT_MS",
    "FORMAT_LINES",
    "NRC78_TOTAL_LIMIT_S",
    "OPEN_PROTOCOL_LINES",
    "RATE_LIMIT_S",
    "RULE_ADAPTER_RESET",
    "RULE_FC_UNAVAILABLE",
    "RULE_PENDING",
    "RULE_PRECONDITION",
    "RULE_REPLY",
    "RULE_STATE",
    "RULE_TARGET",
    "RULE_TRANSPORT_FAILED",
    "STALE_READ_LIMIT",
    "STALE_READ_TIMEOUT_S",
    "STPX_DRAIN_TIMEOUT_S",
    "STPX_UART_MARGIN_MS",
    "WARM_START_TIMEOUT_S",
    "AdapterInfo",
    "AdapterQuery",
    "AdapterStatus",
    "DriverError",
    "DriverState",
    "FcAttempt",
    "FcStrategy",
    "ProbeCommand",
    "StnDriver",
    "StpxTimeout",
    "address_lines",
    "effective_timeout_ms",
    "fc_lines",
    "needs_fc_config",
    "parse_voltage",
    "stpx_line",
    "stpx_uart_timeout_s",
    "strategy_order",
    "target_select_lines",
]

# ---------------------------------------------------------------------------
# Timing constants (table "Timeouts and pacing" in T4)

BANNER_TIMEOUT_S: Final[float] = 1.0
"""Banner window after the port is opened."""

WARM_START_TIMEOUT_S: Final[float] = 5.0
"""Reply timeout for `ATWS`."""

COMMAND_TIMEOUT_S: Final[float] = 2.0
"""Reply timeout for the other adapter commands."""

DEFAULT_STPX_TIMEOUT_MS: Final[int] = 300
"""ECU timeout set by `STPTO300`; with this value `T:` is omitted."""

STPX_UART_MARGIN_MS: Final[int] = 5000 + 500
"""UART timeout margin above T for `STPX` (T + 5000 + 500 ms)."""

RATE_LIMIT_S: Final[float] = 0.010
"""Minimum interval from receiving `>` to the next write."""

NRC78_TOTAL_LIMIT_S: Final[float] = 30.0
"""Hard total limit of the read windows of one `STPX` when extending after `7F xx 78`."""

STPX_DRAIN_TIMEOUT_S: Final[float] = COMMAND_TIMEOUT_S
"""Finishing the read up to `>` after the final `STPX` timeout."""

STALE_READ_TIMEOUT_S: Final[float] = 0.05
"""Read window for unread bytes before a write (content recorded in the log, `meta.stale`)."""

STALE_READ_LIMIT: Final[int] = 8
"""Maximum number of reads of unread bytes before one write (each gives one `rx` event)."""

# ---------------------------------------------------------------------------
# Driver error rules (`DriverError.rule` attribute)

RULE_STATE: Final[str] = "driver/state"
"""Method called in a driver state where it is not allowed."""

RULE_PRECONDITION: Final[str] = "driver/precondition"
"""A prior step required by the method is missing (e.g. `identify` without `warm_start`)."""

RULE_REPLY: Final[str] = "driver/reply"
"""Adapter reply other than expected."""

RULE_TARGET: Final[str] = "driver/target"
"""Target outside the policy ECU catalog."""

RULE_TRANSPORT_FAILED: Final[str] = "driver/transport-failed"
"""Write attempt after a transport error in this session."""

RULE_FC_UNAVAILABLE: Final[str] = "fc_unavailable"
"""The adapter supports no Flow Control strategy."""

RULE_PENDING: Final[str] = "driver/pending"
"""New line before the reply to the previous one has been read."""

RULE_ADAPTER_RESET: Final[str] = "driver/adapter-reset"
"""Adapter reset or reply desync detected; further lines blocked."""

OPEN_PROTOCOL_LINES: Final[tuple[str, ...]] = (
    "STP33",
    "ATCAF1",
    "ATCFC1",
    "ATFCSM0",
    "ATAL",
    "ATAT1",
    "STPTO300",
)
"""Lines of the READY to PROTOCOL_OPEN transition in wire order."""

_DEFAULT_STRATEGY_ORDER: Final[tuple[FcStrategy, ...]] = (
    FcStrategy.ST_PAIRS,
    FcStrategy.ST_PAIRS_LEGACY,
    FcStrategy.ELM_FALLBACK,
)
_PAIR_STRATEGIES: Final[frozenset[FcStrategy]] = frozenset(
    {FcStrategy.ST_PAIRS, FcStrategy.ST_PAIRS_LEGACY}
)
_PROMPT: Final[bytes] = b">"
_VOLTAGE_RE: Final = re.compile(r"([0-9]+(?:[.,][0-9]+)?)\s*V?")


class AdapterQuery(StrEnum):
    """Closed set of read commands for `StnDriver.query`."""

    ATI = "ATI"
    AT1 = "AT@1"
    STI = "STI"
    STDI = "STDI"
    ATRV = "ATRV"
    STVR = "STVR"
    ATPPS = "ATPPS"
    ATDPN = "ATDPN"
    STPR = "STPR"
    STPRS = "STPRS"
    ATCS = "ATCS"


class ProbeCommand(StrEnum):
    """Existence probing commands (probe step 8) for `StnDriver.probe_command`."""

    STCSEGR0 = "STCSEGR0"
    STCSEGT0 = "STCSEGT0"
    STCFCPC = "STCFCPC"
    STFPC = "STFPC"
    STFCP = "STFCP"
    STFFCC = "STFFCC"
    STCTOR = "STCTOR75,150"
    STCAF0 = "STCAF0"
    STPTO102 = "STPTO102"


@dataclass(frozen=True)
class AdapterInfo:
    """Adapter identification from steps 1 to 4.

    Attributes:
        banner: text from the banner window after the port is opened, or None.
        elm: `ATWS` reply line containing `ELM327`, or None.
        sti: `STI` reply (firmware version), e.g. `STN2120 v4.5.0`.
        stdi: `STDI` reply (hardware version), e.g. `STN2120 r1.0`.
    """

    banner: str | None
    elm: str | None
    sti: str
    stdi: str


@dataclass(frozen=True)
class AdapterStatus:
    """Adapter status from `ATRV` and `ATCS`.

    Attributes:
        voltage_v: voltage from `ATRV` in volts, or None when unreadable.
        can_status: text of the `ATCS` reply (CAN error counters).
    """

    voltage_v: float | None
    can_status: str


@dataclass(frozen=True)
class FcAttempt:
    """Result of one Flow Control configuration line in `select_target`.

    Attributes:
        strategy: strategy the line belongs to.
        target: VAG address of the target.
        line: the sent line, e.g. `STCFCPA710,77A`.
        result: `ok` or `unsupported` (reply `?`).
    """

    strategy: FcStrategy
    target: str
    line: str
    result: Literal["ok", "unsupported"]


class StpxTimeout(TransportTimeout):
    """Final `STPX` timeout (after any extension following `7F xx 78`).

    Attributes:
        exchange: exchange parsed from the bytes received up to the
            interruption, including the finished read (lines, `pending_count`).
        drained: whether finishing the read got `>` (adapter at the prompt,
            session not damaged).
    """

    def __init__(self, exchange: UdsExchange, *, drained: bool) -> None:
        self.exchange = exchange
        self.drained = drained
        pending = f", {exchange.pending_count} x 7F xx 78" if exchange.pending_count else ""
        super().__init__(
            partial=exchange.raw,
            message=f"No ECU response within the time limit for {exchange.line}{pending}",
        )


class DriverError(AdapterError):
    """L1 driver error (code 3) with a rule identifier.

    Attributes:
        rule: error rule, e.g. `driver/state` or `fc_unavailable`.
        line: the line whose reply caused the error, or None.
        reply: parsed adapter reply, or None.
    """

    def __init__(
        self,
        message: str,
        *,
        rule: str,
        line: str | None = None,
        reply: AdapterReply | None = None,
    ) -> None:
        self.rule = rule
        self.line = line
        self.reply = reply
        super().__init__(message)


# ---------------------------------------------------------------------------
# Pure line-building functions


def address_lines(target: EcuTarget) -> tuple[str, str]:
    """Target addressing lines: `ATSH<tx>` and `ATCRA<rx>`."""
    return (f"ATSH{target.tx_id:03X}", f"ATCRA{target.rx_id:03X}")


def fc_lines(strategy: FcStrategy, target: EcuTarget) -> tuple[str, ...]:
    """FC configuration lines of strategy `strategy` for the target; the pair always before the filter."""
    tx, rx = target.tx_id, target.rx_id
    if strategy is FcStrategy.ST_PAIRS:
        return (f"STCFCPA{tx:03X},{rx:03X}", f"STFFCA{rx:03X},7FF")
    if strategy is FcStrategy.ST_PAIRS_LEGACY:
        return (f"STCAFCP{tx:03X},{rx:03X}", f"STFAFC{rx:03X},7FF")
    if strategy is FcStrategy.ELM_FALLBACK:
        return (f"ATFCSH{tx:03X}", "ATFCSD300000", "ATFCSM1")
    raise ValueError(f"Unknown FC strategy: {strategy!r}")


def needs_fc_config(
    target: EcuTarget,
    strategy: FcStrategy,
    fc_applied: bool,
    fc_configured: Iterable[int] = (),
) -> bool:
    """Whether `select_target` sends the FC configuration for the target.

    Condition: `target.fc_mode == "pair"` or `fc_applied`. Pair strategies
    send the configuration once per tx in a session (`fc_configured`);
    `elm_fallback` on every target selection, because `ATFCSH` is a global
    value.
    """
    if target.fc_mode != "pair" and not fc_applied:
        return False
    if strategy is FcStrategy.ELM_FALLBACK:
        return True
    return target.tx_id not in frozenset(fc_configured)


def target_select_lines(
    target: EcuTarget,
    strategy: FcStrategy,
    fc_applied: bool = False,
    fc_configured: Iterable[int] = (),
) -> tuple[str, ...]:
    """`select_target` lines for the branch in which strategy `strategy` succeeds."""
    lines = address_lines(target)
    if needs_fc_config(target, strategy, fc_applied, fc_configured):
        lines += fc_lines(strategy, target)
    return lines


def strategy_order(profile_strategy: FcStrategy | None = None) -> tuple[FcStrategy, ...]:
    """Order of FC strategy attempts: the profile strategy, then the default order, without repeats."""
    order: list[FcStrategy] = []
    if profile_strategy is not None:
        order.append(FcStrategy(profile_strategy))
    order.extend(strategy for strategy in _DEFAULT_STRATEGY_ORDER if strategy not in order)
    return tuple(order)


def effective_timeout_ms(target: EcuTarget, timeout_ms: int | None = None) -> int:
    """ECU timeout for `STPX`: the argument or `target.timeout_ms`."""
    return target.timeout_ms if timeout_ms is None else timeout_ms


def stpx_line(target: EcuTarget, payload: bytes, timeout_ms: int | None = None) -> str:
    """Line `STPX H:<tx>,D:<hex>,R:1[,T:<ms>]`; `T:` only for a timeout other than 300."""
    timeout = effective_timeout_ms(target, timeout_ms)
    line = f"STPX H:{target.tx_id:03X},D:{bytes(payload).hex().upper()},R:1"
    if timeout != DEFAULT_STPX_TIMEOUT_MS:
        line += f",T:{timeout}"
    return line


def stpx_uart_timeout_s(timeout_ms: int) -> float:
    """UART read timeout for `STPX`: T + 5000 + 500 ms, in seconds."""
    return (timeout_ms + STPX_UART_MARGIN_MS) / 1000.0


def parse_voltage(text: str) -> float | None:
    """Voltage from the `ATRV` reply (e.g. `12.6V`) in volts, or None."""
    match = _VOLTAGE_RE.fullmatch(text.strip())
    if match is None:
        return None
    return float(match.group(1).replace(",", "."))


# ---------------------------------------------------------------------------
# Driver


class StnDriver:
    """STN2120 adapter driver with a state machine and a guard before the write.

    Parameters:
        transport: byte medium (`SerialTransport`, `NullTransport`, ...).
        policy: read-only policy; its catalog is the allowlist of recipients.
        log: session traffic log (`TrafficLog`), available as the `log` attribute.
        clock: monotonic clock in seconds (rate limit, `elapsed_ms`).
        sleep: wait function in seconds (rate limit).

    Public attributes:
        state, target, fc_strategy, info, adapter, profile, fc_applied,
        fc_configured, fc_attempts, last_elapsed_ms, transport_failed.
    """

    def __init__(
        self,
        transport: ByteTransport,
        policy: ReadOnlyPolicy,
        log: TrafficLog,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if not isinstance(policy, ReadOnlyPolicy):
            raise TypeError(f"StnDriver requires ReadOnlyPolicy, got {type(policy).__name__}")
        self.transport = transport
        self.policy = policy
        self.log = log
        self._clock = clock
        self._sleep = sleep
        self._reset_session()

    # -- public state --------------------------------------------------------

    @property
    def catalog(self) -> EcuCatalog:
        """ECU catalog of the policy (allowlist of recipients)."""
        return self.policy.catalog

    @property
    def fc_configured(self) -> frozenset[int]:
        """Set of tx IDs configured with pair strategies in this session."""
        return frozenset(self._fc_configured)

    @property
    def fc_attempts(self) -> tuple[FcAttempt, ...]:
        """Results of all FC configuration lines in the session, in send order."""
        return tuple(self._fc_attempts)

    @property
    def transport_failed(self) -> bool:
        """Whether a transport error occurred in the session (after it no line is sent)."""
        return self._transport_failed

    # -- initialization steps ------------------------------------------------

    def open(self) -> str | None:
        """Step 1: CLOSED to RAW; opens the port and returns the banner or None.

        The banner window lasts 1000 ms (`read_until(b">")`); `TransportTimeout`
        with `partial` means a banner without a prompt or no data. The `rx`
        event of the `transport` layer is always emitted, even when empty.
        Then `reset_input()` and a `state` event.

        Raises:
            DriverError: the driver is not in the CLOSED state.
            TransportError: error opening or reading the port.
        """
        self._require_state("open", {DriverState.CLOSED})
        self._reset_session()
        try:
            self.transport.open()
        except TransportError as exc:
            self._transport_error(exc)
            raise
        self._opened = True
        started = self._clock()
        timed_out = False
        try:
            raw = self.transport.read_until(_PROMPT, BANNER_TIMEOUT_S)
        except TransportTimeout as exc:
            raw = bytes(exc.partial)
            timed_out = True
        except TransportError as exc:
            self._transport_error(exc)
            raise
        meta: dict[str, Any] = {"elapsed_ms": self._elapsed_ms(started), "window": "banner"}
        if timed_out:
            meta["timeout"] = True
        self._emit(EventKind.RX, Layer.TRANSPORT, escape(raw), meta=meta)
        try:
            self.transport.reset_input()
        except TransportError as exc:
            self._transport_error(exc)
            raise
        self._last_prompt_at = self._clock()
        lines, _ = split_lines(raw, "")
        self._banner = "\n".join(lines) or None
        self._set_state(DriverState.RAW, None)
        return self._banner

    def warm_start(self) -> AdapterReply:
        """Step 2: `ATWS` in the RAW state; a line with `ELM327` is expected (timeout 5000 ms).

        Raises:
            DriverError: wrong state or a reply without `ELM327`.
        """
        self._require_state("warm_start", {DriverState.RAW})
        self._warm_started = False
        self._formatted = False
        reply = self._command("ATWS", WARM_START_TIMEOUT_S)
        if not reply_ok_for("ATWS", reply):
            raise self._fail(
                f"ATWS: expected a line with ELM327, got {reply.text!r}",
                rule=RULE_REPLY,
                line="ATWS",
                reply=reply,
            )
        self._elm = next(text for text in reply.lines if "ELM327" in text)
        self._warm_started = True
        return reply

    def set_format(self) -> list[AdapterReply]:
        """Step 3: `ATE0`, `ATL0`, `ATS0`, `ATH1` in the RAW state; every line must get `OK`.

        The first reply other than `OK` aborts the sequence.

        Raises:
            DriverError: wrong state or a reply other than `OK`.
        """
        self._require_state("set_format", {DriverState.RAW})
        self._formatted = False
        replies = [self._expect_ok(line) for line in FORMAT_LINES]
        self._formatted = True
        return replies

    def identify(self, profile: AdapterProfile | None = None) -> AdapterInfo:
        """Step 4: `STI`, `STDI`; RAW to READY.

        Requires successful `warm_start` and `set_format` in this session.
        `STI` must start with `STN`. The profile affects only the first FC
        strategy; `None` means conservative mode.

        Raises:
            DriverError: wrong state, missing prior steps or a wrong reply.
        """
        self._require_state("identify", {DriverState.RAW})
        if not (self._warm_started and self._formatted):
            raise self._fail(
                "identify requires a prior successful warm_start and set_format in this session",
                rule=RULE_PRECONDITION,
            )
        if profile is not None and not isinstance(profile, AdapterProfile):
            raise TypeError(f"Profile must be AdapterProfile or None, got {type(profile).__name__}")
        sti = self._command("STI")
        if not reply_ok_for("STI", sti):
            raise self._fail(
                f"STI: expected a value starting with STN, got {sti.text!r}",
                rule=RULE_REPLY,
                line="STI",
                reply=sti,
            )
        stdi = self._command("STDI")
        if stdi.outcome is not ReplyOutcome.VALUE or not stdi.lines:
            raise self._fail(
                f"STDI: expected a value, got {stdi.text!r}",
                rule=RULE_REPLY,
                line="STDI",
                reply=stdi,
            )
        self.profile = profile
        self.info = AdapterInfo(banner=self._banner, elm=self._elm, sti=sti.lines[0], stdi=stdi.lines[0])
        self._set_state(DriverState.READY, None)
        return self.info

    def initialize(self, profile: AdapterProfile | None) -> AdapterInfo:
        """Composition of `warm_start`, `set_format` and `identify(profile)` for future commands."""
        self.warm_start()
        self.set_format()
        return self.identify(profile)

    # -- queries -------------------------------------------------------------

    def query(self, q: AdapterQuery) -> AdapterReply:
        """Read command from the closed set `AdapterQuery`; the reply is not interpreted."""
        if not isinstance(q, AdapterQuery):
            raise TypeError(f"query accepts only AdapterQuery, got {q!r}")
        return self._command(q.value)

    def probe_command(self, c: ProbeCommand) -> AdapterReply:
        """Existence probing command (`ProbeCommand`), only in the READY state."""
        if not isinstance(c, ProbeCommand):
            raise TypeError(f"probe_command accepts only ProbeCommand, got {c!r}")
        self._require_state("probe_command", {DriverState.READY})
        return self._command(c.value)

    def read_status(self) -> AdapterStatus:
        """`ATRV` and `ATCS`: voltage and CAN counters."""
        voltage = self._command(AdapterQuery.ATRV.value)
        can_status = self._command(AdapterQuery.ATCS.value)
        volts = None
        if voltage.outcome is ReplyOutcome.VALUE and voltage.lines:
            volts = parse_voltage(voltage.lines[0])
        return AdapterStatus(voltage_v=volts, can_status=can_status.text)

    # -- protocol and target -------------------------------------------------

    def open_protocol(self) -> None:
        """READY to PROTOCOL_OPEN: the 7 lines of `OPEN_PROTOCOL_LINES`, each with `OK`.

        Raises:
            DriverError: wrong state or a reply other than `OK` (state unchanged).
        """
        self._require_state("open_protocol", {DriverState.READY})
        for line in OPEN_PROTOCOL_LINES:
            self._expect_ok(line)
        self._set_state(DriverState.PROTOCOL_OPEN, None)

    def select_target(self, target: EcuTarget) -> None:
        """PROTOCOL_OPEN or TARGET_SELECTED to TARGET_SELECTED for target `target`.

        Order: `state` event (P, target), `ATSH<tx>`, `ATCRA<rx>`, FC
        configuration according to the T4 rules, `state` event (T, target).
        An error leaves the PROTOCOL_OPEN state with the target, so `STPX` is
        blocked.

        Raises:
            DriverError: wrong state, target outside the catalog, a reply
                other than `OK`, or no supported FC strategy (`fc_unavailable`).
        """
        if not isinstance(target, EcuTarget):
            raise TypeError(f"select_target accepts only EcuTarget, got {target!r}")
        self._require_state("select_target", {DriverState.PROTOCOL_OPEN, DriverState.TARGET_SELECTED})
        self._require_catalog_target(target)
        self._set_state(DriverState.PROTOCOL_OPEN, target)
        for line in address_lines(target):
            self._expect_ok(line)
        if needs_fc_config(target, self._strategies()[0], self.fc_applied, self._fc_configured):
            self._configure_fc(target)
        self._set_state(DriverState.TARGET_SELECTED, target)

    def set_rx_segmentation(self, enabled: bool) -> AdapterReply:
        """`STCSEGR1` or `STCSEGR0`, only in the TARGET_SELECTED state; the reply is not interpreted."""
        if not isinstance(enabled, bool):
            raise TypeError(f"set_rx_segmentation accepts bool, got {enabled!r}")
        self._require_state("set_rx_segmentation", {DriverState.TARGET_SELECTED})
        return self._command("STCSEGR1" if enabled else "STCSEGR0")

    def transact(self, uds_payload: bytes, timeout_ms: int | None = None) -> UdsExchange:
        """One UDS request through `STPX` to the current target, without retries.

        The line comes from `stpx_line`; the UART timeout is T + 5000 + 500 ms,
        where T is `timeout_ms` or `target.timeout_ms`. The payload goes
        through UdsGuard in `_egress` (rule `LINE/uds`).

        Raises:
            DriverError: state other than TARGET_SELECTED.
            ReadOnlyViolation: line rejected by the guard (zero bytes in the transport).
            TransportError, TransportTimeout: medium error.
        """
        if not isinstance(uds_payload, (bytes, bytearray)):
            raise TypeError(f"transact accepts bytes, got {type(uds_payload).__name__}")
        if timeout_ms is not None and (isinstance(timeout_ms, bool) or not isinstance(timeout_ms, int)):
            raise TypeError(f"timeout_ms must be int or None, got {timeout_ms!r}")
        self._require_state("transact", {DriverState.TARGET_SELECTED})
        target = self.target
        if target is None:
            raise self._fail("transact requires a selected target", rule=RULE_STATE)
        line = stpx_line(target, bytes(uds_payload), timeout_ms)
        uart_timeout_s = stpx_uart_timeout_s(effective_timeout_ms(target, timeout_ms))
        raw = self._egress(line, uart_timeout_s, rx_id=target.rx_id)
        return parse_uds_exchange(raw, line, target.rx_id, elapsed_ms=self.last_elapsed_ms)

    # -- close ---------------------------------------------------------------

    @property
    def adapter_reset(self) -> str | None:
        """Description of the detected adapter reset or reply desync, or None."""
        return self._adapter_reset

    @property
    def pending_line(self) -> str | None:
        """Line whose reply has not yet been read up to `>`, or None."""
        return self._pending_line

    def finish_pending(self) -> bool:
        """Finishes reading the pending reply up to `>` with the timeout of its command.

        Returns True when the adapter is at the prompt (no pending reply or a
        successful finish), False after a transport error in the session, a
        failed finish or a detected adapter reset. Sends no line.
        """
        if self._pending_line is not None:
            if self._transport_failed:
                self._pending_line = None
                return False
            try:
                self._receive(self._pending_line, self._pending_timeout_s, self._pending_rx_id, drain=True)
            except (TransportError, DriverError):
                return False
        return not self._transport_failed and self._adapter_reset is None

    def close(self, after_transport_error: bool = False) -> AdapterReply | None:
        """Any state to CLOSED; the port is always closed; returns the `STPC` reply or None.

        A pending reply (e.g. after `KeyboardInterrupt` during a write or a
        read) is first finished with `finish_pending()`. `STPC` is sent only
        in the PROTOCOL_OPEN and TARGET_SELECTED states, after a successful
        finish of the read and with no transport error in the session; after
        a detected adapter reset `STPC` is the only allowed line (the input
        buffer is cleared first, and its content goes to the log first as
        `rx` events with `meta.stale`). `after_transport_error=True` sends no
        line. Errors are logged as an `error` event and do not abort the
        close.
        """
        if self.state is DriverState.CLOSED and not self._opened:
            return None
        # Finishing the read and STPC only without a transport error in the session (audit m4).
        send_lines = not (after_transport_error or self._transport_failed)
        reply: AdapterReply | None = None
        try:
            if self._pending_line is not None:
                if send_lines:
                    # After a detected reset STPC stays allowed as long as the transport works.
                    self.finish_pending()
                    send_lines = not self._transport_failed
                else:
                    self._pending_line = None
            if send_lines and self.state in (DriverState.PROTOCOL_OPEN, DriverState.TARGET_SELECTED):
                try:
                    if self._adapter_reset is not None:
                        # After a reset the buffer is always cleared; the content of unread bytes goes to the log first.
                        self._check_stale_input("STPC", closing=True)
                        self.transport.reset_input()
                    reply = self._command("STPC", closing=True)
                except ReadOnlyViolation as exc:
                    self._emit_error("app", str(exc), type(exc).__name__)
                except (AdapterError, TransportError):
                    pass  # `_fail` or `_transport_error` has already recorded the `error` event
                else:
                    if reply.outcome is not ReplyOutcome.OK:
                        message = f"STPC: expected OK, got {reply.text!r}"
                        self._emit_error("app", message, DriverError.__name__)
            return reply
        finally:
            try:
                self.transport.close()
            except TransportError as exc:
                self._emit_error("transport", str(exc), type(exc).__name__)
            self._opened = False
            self._set_state(DriverState.CLOSED, None)

    # -- egress -------------------------------------------------------------

    def _egress(
        self, line: str, timeout_s: float, *, rx_id: int | None = None, closing: bool = False
    ) -> bytes:
        """The only write path to the transport (T4 steps); returns the reply bytes up to `>`.

        1. CLOSED state, a transport error in the session, a detected adapter
           reset (except `STPC` on close) or an unread reply to the previous
           line: `DriverError`, zero bytes in the transport.
        2. Guard with `GuardContext`; rejection: `guard` event, `ReadOnlyViolation`.
        3. Rate limit of 10 ms from the previous `>`.
        4. Unread bytes in the transport buffer right before the write: content
           in `rx` events with `meta.stale`, then a reply desync and a session
           block (on close and before `ATWS` in RAW the buffer is cleared
           without a block).
        5. `tx` events of the `adapter` and `transport` layers; the pending
           reply is recorded before the write.
        6. Write `line + "\\r"`.
        7. Read up to `>` (`_receive`), `rx` events and model update.

        `rx_id` (for `STPX`) marks frames of other senders as `meta.foreign`
        and enables extending the deadline after `7F xx 78`.
        """
        if self.state is DriverState.CLOSED:
            raise self._fail(
                f"Line {line!r} cannot be sent in the CLOSED state", rule=RULE_STATE, line=line
            )
        if self._transport_failed:
            raise self._fail(
                f"Line {line!r} rejected: a transport error occurred in the session",
                rule=RULE_TRANSPORT_FAILED,
                line=line,
            )
        if self._adapter_reset is not None and not (closing and line == "STPC"):
            raise self._fail(
                f"Line {line!r} rejected: adapter reset or reply desync detected "
                f"({self._adapter_reset})",
                rule=RULE_ADAPTER_RESET,
                line=line,
            )
        if self._pending_line is not None:
            raise self._fail(
                f"Line {line!r} rejected: the reply to {self._pending_line!r} has not been read up to '>'",
                rule=RULE_PENDING,
                line=line,
            )
        ctx = GuardContext(self.state, self.target, self.policy.catalog, self.adapter)
        decision = self.policy.check_line(line, ctx)
        if not decision.allowed:
            meta = {"state": self.state.value}
            if decision.uds_rule is not None:
                meta["uds_rule"] = decision.uds_rule
            self._emit(
                EventKind.GUARD,
                Layer.ADAPTER,
                line,
                guard={"decision": "rejected", "rule": decision.rule, "reason": decision.reason},
                meta=meta,
            )
            raise ReadOnlyViolation(LAYER_ADAPTER, decision.rule, decision.reason or "", line)

        if self._last_prompt_at is not None:
            wait = RATE_LIMIT_S - (self._clock() - self._last_prompt_at)
            if wait > 0:
                self._sleep(wait)

        self._check_stale_input(line, closing)
        data = line.encode("ascii") + b"\r"
        self._emit(
            EventKind.TX,
            Layer.ADAPTER,
            line,
            guard={"decision": "allowed", "rule": decision.rule, "reason": None},
        )
        self._emit(EventKind.TX, Layer.TRANSPORT, escape(data))
        # Pending reply recorded before the write: Ctrl-C during write/flush does not lose it (W2).
        self._pending_line = line
        self._pending_timeout_s = timeout_s
        self._pending_rx_id = rx_id
        self._write_started = self._clock()
        try:
            self.transport.write(data)
        except TransportError as exc:
            self._transport_error(exc)
            raise
        return self._receive(line, timeout_s, rx_id)

    def _check_stale_input(self, line: str, closing: bool) -> None:
        """Unread bytes before a write: content to the log, then a reply desync (session block).

        On close (`STPC`) and before `ATWS` in RAW (`stale_input_tolerated`)
        the bytes are discarded (`reset_input`) and the line is sent.
        """
        try:
            stale = self.transport.pending_input()
        except TransportError as exc:
            self._transport_error(exc)
            raise
        if stale <= 0:
            return
        reason = f"{stale} B of unread data in the buffer before writing line {line}"
        self._log_stale_input(line)
        if closing or stale_input_tolerated(line, self.state):
            context = "Close" if closing else f"Warm start ({self.state.value})"
            self._emit_error("app", f"{context}: discarded {reason}", DriverError.__name__)
            try:
                self.transport.reset_input()
            except TransportError as exc:
                self._transport_error(exc)
                raise
            return
        self._mark_reset(reason)
        raise DriverError(
            f"Line {line!r} rejected: adapter reply desync detected ({reason})",
            rule=RULE_ADAPTER_RESET,
            line=line,
        )

    def _log_stale_input(self, line: str) -> None:
        """Content of unread bytes: `rx` events of the `transport` layer with `meta.stale` (no write).

        Reads in successive `STALE_READ_TIMEOUT_S` windows up to `>` until the
        buffer is empty or a window passes without `>` (at most
        `STALE_READ_LIMIT` reads). Every `read_until` call gives one `rx`
        event, so `ReplayTransport` replays this read unchanged.
        """
        for _ in range(STALE_READ_LIMIT):
            meta: dict[str, Any] = {"stale": True, "before": line}
            try:
                data = self.transport.read_until(_PROMPT, STALE_READ_TIMEOUT_S)
            except TransportTimeout as exc:
                data = bytes(exc.partial)
                meta["timeout"] = True
            except TransportError as exc:
                self._transport_error(exc)
                raise
            self._emit(EventKind.RX, Layer.TRANSPORT, escape(data), meta=meta)
            if meta.get("timeout"):
                return
            try:
                if self.transport.pending_input() <= 0:
                    return
            except TransportError as exc:
                self._transport_error(exc)
                raise

    def _receive(
        self,
        line: str,
        timeout_s: float,
        rx_id: int | None,
        *,
        drain: bool = False,
        prefix: bytes | None = None,
    ) -> bytes:
        """Reads the reply up to `>`, emits `rx` events, detects resets and updates the model.

        For `STPX` (`rx_id` given) a window timeout with new `7F xx 78`
        messages extends the deadline by another T + 5000 + 500 ms window,
        within the total limit `NRC78_TOTAL_LIMIT_S`; the request is not
        retried. The final `STPX` timeout (outside finishing) starts
        `_stpx_timeout`. Every `read_until` call gives one `rx` event of the
        `transport` layer.

        `prefix` holds the bytes received before the final `STPX` timeout
        (finishing from `_stpx_timeout`): one window without extension, and
        the model, the `rx` events of the `adapter` layer and reset detection
        cover the whole reply, `prefix` plus the finished part.
        """
        head = b"" if prefix is None else prefix
        received = bytearray()
        window = timeout_s
        used = 0.0
        pending_seen = 0
        while True:
            try:
                chunk = self.transport.read_until(_PROMPT, window)
            except TransportTimeout as exc:
                partial = bytes(exc.partial)
                received += partial
                used += window
                count = self._pending_count(bytes(received), line, rx_id)
                remaining = NRC78_TOTAL_LIMIT_S - used
                extend = prefix is None and rx_id is not None and count > pending_seen and remaining > 1e-9
                meta: dict[str, Any] = {"elapsed_ms": self._elapsed_ms(self._write_started), "timeout": True}
                if drain:
                    meta["drain"] = True
                if extend:
                    meta["nrc78_extend"] = True
                    meta["pending_count"] = count
                self._emit(EventKind.RX, Layer.TRANSPORT, escape(partial), meta=meta)
                if extend:
                    pending_seen = count
                    window = min(timeout_s, remaining)
                    continue
                if rx_id is not None and not drain:
                    # The pending reply stays until finishing ends (Ctrl-C during it).
                    self._stpx_timeout(exc, line, rx_id, bytes(received))
                self._pending_line = None
                self.adapter = self.adapter.apply(
                    line, reply_ok_for(line, parse_adapter_reply(head + bytes(received), line))
                )
                self._transport_error(exc)
                raise
            except TransportError as exc:
                self._pending_line = None
                self._transport_error(exc)
                raise
            break
        raw = head + bytes(received) + chunk
        self._pending_line = None
        self._last_prompt_at = self._clock()
        self.last_elapsed_ms = self._elapsed_ms(self._write_started)
        meta = {"elapsed_ms": self.last_elapsed_ms}
        if drain:
            meta["drain"] = True
        self._emit(EventKind.RX, Layer.TRANSPORT, escape(chunk), meta=meta)
        self._emit_adapter_lines(raw, line, rx_id)
        evidence = reset_evidence(line, raw, self.adapter.format_ok)
        if evidence is not None:
            self._mark_reset(evidence)
            raise DriverError(
                f"Reply to {line!r} indicates an adapter reset or reply desync ({evidence})",
                rule=RULE_ADAPTER_RESET,
                line=line,
                reply=parse_adapter_reply(raw, line),
            )
        self.adapter = self.adapter.apply(line, reply_ok_for(line, parse_adapter_reply(raw, line)))
        return raw

    def _stpx_timeout(self, exc: TransportTimeout, line: str, rx_id: int, received: bytes) -> NoReturn:
        """Final `STPX` timeout: finishes the read up to `>` through `_receive`, then `StpxTimeout`.

        A successful finish leaves the session working (adapter at the
        prompt), so stage E and `STPC` remain possible. A failed finish marks
        the session as damaged (`_receive` logs the transport error). Reset
        evidence in the finished part gives `DriverError` with rule
        `driver/adapter-reset`, as in a normal reply.
        """
        self._emit_error("transport", str(exc), type(exc).__name__)
        try:
            raw = self._receive(line, STPX_DRAIN_TIMEOUT_S, rx_id, drain=True, prefix=received)
        except TransportTimeout as drain_exc:
            exchange = parse_uds_exchange(received + bytes(drain_exc.partial), line, rx_id)
            raise StpxTimeout(exchange, drained=False) from exc
        exchange = parse_uds_exchange(raw, line, rx_id, elapsed_ms=self.last_elapsed_ms)
        raise StpxTimeout(exchange, drained=True) from exc

    def _pending_count(self, raw: bytes, line: str, rx_id: int | None) -> int:
        """Number of `7F xx 78` messages from `rx_id` in the received bytes (0 for lines other than `STPX`)."""
        if rx_id is None:
            return 0
        return parse_uds_exchange(raw, line, rx_id).pending_count

    def _mark_reset(self, reason: str) -> None:
        """Session block after an adapter reset: configuration model cleared, `error` event."""
        if self._adapter_reset is None:
            self._adapter_reset = reason
        self.adapter = AdapterConfigModel()
        message = f"Adapter reset or reply desync detected: {reason}; further lines blocked"
        self._emit_error("app", message, DriverError.__name__, rule=RULE_ADAPTER_RESET)

    def _emit_adapter_lines(self, raw: bytes, line: str, rx_id: int | None) -> None:
        """`rx` events of the `adapter` layer: one for every non-empty reply line."""
        lines, echo = split_lines(raw, line)
        foreign: frozenset[str] = frozenset()
        if rx_id is not None:
            exchange = parse_uds_exchange(raw, line, rx_id)
            foreign = frozenset(frame.line for frame in exchange.foreign_frames)
        index = 0
        if echo:
            self._emit(EventKind.RX, Layer.ADAPTER, line, meta={"index": index, "echo": True})
            index += 1
        for text in lines:
            meta: dict[str, Any] = {"index": index}
            if text in foreign:
                meta["foreign"] = True
            self._emit(EventKind.RX, Layer.ADAPTER, text, meta=meta)
            index += 1

    # -- helpers -------------------------------------------------------------

    def _reset_session(self) -> None:
        """Initial state of the driver session (constructor and `open`)."""
        self.state: DriverState = DriverState.CLOSED
        self.target: EcuTarget | None = None
        self.fc_strategy: FcStrategy | None = None
        self.fc_applied: bool = False
        self.info: AdapterInfo | None = None
        self.profile: AdapterProfile | None = None
        self.adapter: AdapterConfigModel = AdapterConfigModel()
        self.last_elapsed_ms: float | None = None
        self._fc_configured: set[int] = set()
        self._fc_attempts: list[FcAttempt] = []
        self._banner: str | None = None
        self._elm: str | None = None
        self._warm_started = False
        self._formatted = False
        self._transport_failed = False
        self._opened = False
        self._last_prompt_at: float | None = None
        self._write_started = 0.0
        self._pending_line: str | None = None
        self._pending_timeout_s = COMMAND_TIMEOUT_S
        self._pending_rx_id: int | None = None
        self._adapter_reset: str | None = None

    def _command(self, line: str, timeout_s: float = COMMAND_TIMEOUT_S, *, closing: bool = False) -> AdapterReply:
        """Sends an adapter line through `_egress` and returns the parsed reply."""
        return parse_adapter_reply(self._egress(line, timeout_s, closing=closing), line)

    def _expect_ok(self, line: str) -> AdapterReply:
        """Sends a line and requires an `OK` reply; otherwise `DriverError`."""
        reply = self._command(line)
        if reply.outcome is not ReplyOutcome.OK:
            raise self._fail(
                f"{line}: expected OK, got {reply.text!r}",
                rule=RULE_REPLY,
                line=line,
                reply=reply,
            )
        return reply

    def _strategies(self) -> tuple[FcStrategy, ...]:
        """FC strategies to try: only the established one, or the profile order followed by the default."""
        if self.fc_strategy is not None:
            return (self.fc_strategy,)
        return strategy_order(self.profile.fc_strategy if self.profile is not None else None)

    def _configure_fc(self, target: EcuTarget) -> None:
        """FC configuration of the target according to the T4 strategy selection rules (points 1 to 6)."""
        established = self.fc_strategy is not None
        for strategy in self._strategies():
            unsupported_line: str | None = None
            for line in fc_lines(strategy, target):
                reply = self._command(line)
                if reply.outcome is ReplyOutcome.OK:
                    self._fc_attempts.append(FcAttempt(strategy, target.vag_address, line, "ok"))
                    continue
                if reply.outcome is ReplyOutcome.UNSUPPORTED:
                    self._fc_attempts.append(FcAttempt(strategy, target.vag_address, line, "unsupported"))
                    unsupported_line = line
                    break
                raise self._fail(
                    f"{line}: expected OK or ?, got {reply.text!r}",
                    rule=RULE_REPLY,
                    line=line,
                    reply=reply,
                )
            if unsupported_line is None:
                self.fc_strategy = strategy
                self.fc_applied = True
                if strategy in _PAIR_STRATEGIES:
                    self._fc_configured.add(target.tx_id)
                return
            if established:
                raise self._fail(
                    f"{unsupported_line}: established FC strategy {strategy.value} is not supported (?)",
                    rule=RULE_REPLY,
                    line=unsupported_line,
                )
        raise self._fail(
            f"The adapter supports no FC strategy for target {target.vag_address}",
            rule=RULE_FC_UNAVAILABLE,
        )

    def _require_state(self, method: str, allowed: set[DriverState]) -> None:
        if self.state not in allowed:
            names = ", ".join(state.value for state in DriverState if state in allowed)
            raise self._fail(
                f"{method} is allowed in states {names}, current state: {self.state.value}",
                rule=RULE_STATE,
            )

    def _require_catalog_target(self, target: EcuTarget) -> None:
        catalog = self.policy.catalog
        try:
            known = catalog.get(target.vag_address)
        except CatalogError as exc:
            raise self._fail(f"Target {target.vag_address} is outside the ECU catalog: {exc}", rule=RULE_TARGET) from exc
        if known != target:
            raise self._fail(
                f"Target {target.vag_address} ({target.tx_id:03X}, {target.rx_id:03X}) "
                "does not match the catalog entry",
                rule=RULE_TARGET,
            )

    def _set_state(self, state: DriverState, target: EcuTarget | None) -> None:
        """Sets the state and target; on a change emits a `state` event."""
        prev_state, prev_target = self.state, self.target
        if state is prev_state and target == prev_target:
            return
        self.state, self.target = state, target
        self._emit(
            EventKind.STATE,
            Layer.ADAPTER,
            meta={
                "state": state.value,
                "target": target.vag_address if target is not None else None,
                "prev_state": prev_state.value,
                "prev_target": prev_target.vag_address if prev_target is not None else None,
            },
        )

    def _transport_error(self, exc: TransportError) -> None:
        """Marks the session as damaged and logs an `error` event of the `transport` layer."""
        self._transport_failed = True
        self._pending_line = None
        self._emit_error("transport", str(exc), type(exc).__name__, os_errno=exc.os_errno)

    def _fail(
        self,
        message: str,
        *,
        rule: str,
        line: str | None = None,
        reply: AdapterReply | None = None,
    ) -> DriverError:
        """Logs an `error` event of the `app` layer and returns a `DriverError` to raise."""
        error = DriverError(message, rule=rule, line=line, reply=reply)
        self._emit_error("app", message, type(error).__name__, rule=rule)
        return error

    def _emit_error(
        self, layer: str, message: str, kind: str, *, rule: str | None = None, os_errno: int | None = None
    ) -> None:
        meta: dict[str, Any] = {"type": kind, "message": message, "state": self.state.value}
        if rule is not None:
            meta["rule"] = rule
        if os_errno is not None:
            meta["errno"] = os_errno
        self._emit(EventKind.ERROR, layer, message, meta=meta)

    def _emit(
        self,
        ev: str,
        layer: str,
        data: str = "",
        *,
        guard: dict[str, Any] | None = None,
        meta: dict[str, Any] | None = None,
    ) -> None:
        ecu = self.target.vag_address if self.target is not None else None
        self.log.emit(ev, layer, data, ecu=ecu, guard=guard, meta=meta)

    def _elapsed_ms(self, started: float) -> float:
        """Time since `started` in ms with 0.1 ms resolution (spec T9, `timing` block)."""
        return max(0.0, round((self._clock() - started) * 1000, 1))
