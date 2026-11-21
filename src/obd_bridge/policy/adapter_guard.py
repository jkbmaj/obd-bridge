"""Adapter line guard: AT/ST allowlist, canonical form, addressee and model (spec T2, FR-13, FR-14).

The policy rejects by default. A line passes only when it passes nine checks
in T2 order; the first failure ends the evaluation:

1. `LINE/empty`: empty line.
2. `LINE/charset`: a character outside `[0-9A-Z@:, ]` (also `\\r`, `\\n`, lower case).
3. `LINE/space`: a space other than at index 4 of an `STPX ` line, or more than one.
4. `LINE/no-match`: no full match to an `ALLOWLIST` entry.
5. `LINE/state`: driver state outside the entry's set of states.
6. `LINE/address`: addressee outside the catalog, different from the target, 0x7DF or no target.
7. `LINE/value-range`: `STPTO` or `T:` in `STPX` above 5000 ms.
8. `LINE/adapter-config`: configuration model conditions for `STPX` and `ATFCSM1`.
9. `LINE/uds`: the `D:` field of an `STPX` line rejected by `UdsGuard`.

The guard does not normalize input: a non-canonical line is rejected, never
corrected. The allowlist is a code constant; there is no parameter,
environment variable or option that extends or disables it (FR-17).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from obd_bridge.policy.decision import GuardContext, GuardDecision
from obd_bridge.policy.uds_guard import UdsGuard
from obd_bridge.stn.state import DriverState

__all__ = [
    "ALLOWLIST",
    "FUNCTIONAL_ID",
    "MAX_TIMEOUT_MS",
    "RULE_ADAPTER_CONFIG",
    "RULE_ADDRESS",
    "RULE_CHARSET",
    "RULE_EMPTY",
    "RULE_NO_MATCH",
    "RULE_SPACE",
    "RULE_STATE",
    "RULE_UDS",
    "RULE_VALUE_RANGE",
    "AdapterCommandGuard",
    "AddressKind",
    "AllowEntry",
]

RULE_EMPTY: Final[str] = "LINE/empty"
RULE_CHARSET: Final[str] = "LINE/charset"
RULE_SPACE: Final[str] = "LINE/space"
RULE_NO_MATCH: Final[str] = "LINE/no-match"
RULE_STATE: Final[str] = "LINE/state"
RULE_ADDRESS: Final[str] = "LINE/address"
RULE_VALUE_RANGE: Final[str] = "LINE/value-range"
RULE_ADAPTER_CONFIG: Final[str] = "LINE/adapter-config"
RULE_UDS: Final[str] = "LINE/uds"

FUNCTIONAL_ID: Final[int] = 0x7DF
"""OBD functional address, always rejected regardless of the catalog."""

MAX_TIMEOUT_MS: Final[int] = 5000
"""Upper limit of `STPTO` and of the `T:` field in `STPX`."""

_CHARSET: Final = re.compile(r"[0-9A-Z@:, ]+")
_STPX_PREFIX: Final[str] = "STPX "
_STPX_RULE: Final[str] = "ST/STPX"
_STPTO_RULE: Final[str] = "ST/STPTO"
_FCSM_RULE: Final[str] = "AT/ATFCSM"


class AddressKind(StrEnum):
    """Addressee kind of an allowlist entry (column "Addressee" in T2)."""

    TX = "tx"
    RX = "rx"
    PAIR = "pair"


@dataclass(frozen=True)
class AllowEntry:
    """Allowlist entry.

    Attributes:
        rule: rule identifier, e.g. `ST/STPX`.
        pattern: compiled regex matched with `fullmatch`.
        states: driver states in which the line is allowed.
        address: addressee kind, or None for entries without an address; the
            addresses are in groups 1 (and 2 for a pair) of `pattern`.
    """

    rule: str
    pattern: re.Pattern[str]
    states: frozenset[DriverState]
    address: AddressKind | None = None


_R, _Y, _P, _T = (
    DriverState.RAW,
    DriverState.READY,
    DriverState.PROTOCOL_OPEN,
    DriverState.TARGET_SELECTED,
)
_RY: Final = frozenset({_R, _Y})
_RYPT: Final = frozenset({_R, _Y, _P, _T})
_YPT: Final = frozenset({_Y, _P, _T})
_PT: Final = frozenset({_P, _T})
_ONLY_Y: Final = frozenset({_Y})
_ONLY_T: Final = frozenset({_T})

_ID: Final[str] = "([0-9A-F]{3})"


def _entry(
    rule: str, regex: str, states: frozenset[DriverState], address: AddressKind | None = None
) -> AllowEntry:
    return AllowEntry(rule=rule, pattern=re.compile(regex), states=states, address=address)


ALLOWLIST: Final[tuple[AllowEntry, ...]] = (
    # Reset and format.
    _entry("AT/ATWS", r"ATWS", _RY),
    _entry("AT/ATE0", r"ATE0", _RY),
    _entry("AT/ATL0", r"ATL0", _RY),
    _entry("AT/ATS0", r"ATS0", _RY),
    _entry("AT/ATH", r"ATH[01]", _RY),
    _entry("AT/ATD1", r"ATD1", _RY),
    _entry("AT/ATAL", r"ATAL", _RY),
    # Identification and status.
    _entry("AT/ATI", r"ATI", _RYPT),
    _entry("AT/AT@1", r"AT@1", _RYPT),
    _entry("ST/STI", r"STI", _RYPT),
    _entry("ST/STDI", r"STDI", _RYPT),
    _entry("AT/ATRV", r"ATRV", _RYPT),
    _entry("ST/STVR", r"STVR", _RYPT),
    _entry("AT/ATDP", r"ATDP", _RYPT),
    _entry("AT/ATDPN", r"ATDPN", _RYPT),
    _entry("AT/ATPPS", r"ATPPS", _RYPT),
    _entry("ST/STPR", r"STPR", _RYPT),
    _entry("ST/STPRS", r"STPRS", _RYPT),
    _entry("ST/STPBRR", r"STPBRR", _RYPT),
    _entry("AT/ATCS", r"ATCS", _RYPT),
    # Protocol.
    _entry("ST/STP33", r"STP33", _ONLY_Y),
    _entry("ST/STPC", r"STPC", _YPT),
    # ISO-TP and timing.
    _entry("AT/ATCAF1", r"ATCAF1", _YPT),
    _entry("AT/ATCFC1", r"ATCFC1", _YPT),
    _entry(_FCSM_RULE, r"ATFCSM([01])", _YPT),
    _entry("AT/ATAT", r"ATAT[012]", _YPT),
    _entry("AT/ATST", r"ATST[0-9A-F]{2}", _YPT),
    _entry(_STPTO_RULE, r"STPTO([1-9][0-9]{0,3})", _YPT),
    _entry("ST/STCTOR", r"STCTOR[0-9]{1,3},[0-9]{1,3}", _YPT),
    _entry("ST/STCAF0", r"STCAF0", _ONLY_Y),  # only use: probe step 8 in READY
    _entry("ST/STCSEGR", r"STCSEGR[01]", _YPT),
    _entry("ST/STCSEGT", r"STCSEGT[01]", _YPT),
    _entry("AT/ATFCSD300000", r"ATFCSD300000", _PT),
    # Clearing filters and pairs: READY only (audit M1).
    _entry("AT/ATAR", r"ATAR", _ONLY_Y),
    _entry("ST/STCFCPC", r"STCFCPC", _ONLY_Y),
    _entry("ST/STFAC", r"STFAC", _ONLY_Y),
    _entry("ST/STFPC", r"STFPC", _ONLY_Y),
    _entry("ST/STFFCC", r"STFFCC", _ONLY_Y),
    _entry("ST/STFBC", r"STFBC", _ONLY_Y),
    _entry("ST/STFCP", r"STFCP", _ONLY_Y),
    # Addressing.
    _entry("AT/ATSH", rf"ATSH{_ID}", _PT, AddressKind.TX),
    _entry("AT/ATCRA", rf"ATCRA{_ID}", _PT, AddressKind.RX),
    _entry("AT/ATFCSH", rf"ATFCSH{_ID}", _PT, AddressKind.TX),
    _entry("ST/STFPA", rf"STFPA{_ID},7FF", _PT, AddressKind.RX),
    _entry("ST/STFFCA", rf"STFFCA{_ID},7FF", _PT, AddressKind.RX),
    _entry("ST/STCFCPA", rf"STCFCPA{_ID},{_ID}", _PT, AddressKind.PAIR),
    _entry("ST/STFAP", rf"STFAP{_ID},7FF", _PT, AddressKind.RX),
    _entry("ST/STFAFC", rf"STFAFC{_ID},7FF", _PT, AddressKind.RX),
    _entry("ST/STCAFCP", rf"STCAFCP{_ID},{_ID}", _PT, AddressKind.PAIR),
    # Request.
    _entry(
        _STPX_RULE,
        rf"STPX H:{_ID},D:((?:[0-9A-F]{{2}}){{1,8}}),R:1(?:,T:([1-9][0-9]{{0,3}}))?",
        _ONLY_T,
        AddressKind.TX,
    ),
)
"""Adapter line allowlist (50 entries, table T2)."""


def _state_names(states: frozenset[DriverState]) -> str:
    order = [state for state in DriverState if state in states]
    return ", ".join(state.value for state in order)


class AdapterCommandGuard:
    """Adapter line guard without configuration parameters.

    The `check` method is pure: it has no state, does not log and raises no
    exception for any line of type `str`. The `guard` event is emitted by the caller.
    """

    def __init__(self) -> None:
        self._uds = UdsGuard()

    def check(self, line: str, ctx: GuardContext) -> GuardDecision:
        """Evaluates an adapter line (without terminator) in context `ctx`.

        Returns a decision with the allowlist entry rule on acceptance, or with
        a `LINE/*` rule on rejection (for `LINE/uds` also `uds_rule`).

        Raises:
            TypeError: `line` is not a `str` or `ctx` is not a `GuardContext`.
        """
        if not isinstance(line, str):
            raise TypeError(f"Adapter line must be of type str, got {type(line).__name__}")
        if not isinstance(ctx, GuardContext):
            raise TypeError(f"Guard context must be GuardContext, got {type(ctx).__name__}")

        if not line:
            return GuardDecision.reject(RULE_EMPTY, "An empty adapter line cannot be sent")
        if not _CHARSET.fullmatch(line):
            return GuardDecision.reject(
                RULE_CHARSET,
                "Line contains a character outside the allowed set 0-9, A-Z, @, colon, comma and space",
            )
        if " " in line and not (line.startswith(_STPX_PREFIX) and line.count(" ") == 1):
            return GuardDecision.reject(
                RULE_SPACE, "A space is allowed only as the single space after STPX (index 4)"
            )

        entry, match = self._match(line)
        if entry is None or match is None:
            return GuardDecision.reject(RULE_NO_MATCH, "Line does not match any adapter allowlist entry")

        if ctx.state not in entry.states:
            return GuardDecision.reject(
                RULE_STATE,
                f"Rule {entry.rule} is allowed in states {_state_names(entry.states)}, "
                f"current state: {ctx.state.value}",
            )

        if entry.address is not None:
            reason = self._check_address(entry.address, match, ctx)
            if reason is not None:
                return GuardDecision.reject(RULE_ADDRESS, reason)

        reason = self._check_value_range(entry.rule, match)
        if reason is not None:
            return GuardDecision.reject(RULE_VALUE_RANGE, reason)

        reason = self._check_adapter_config(entry.rule, line, ctx)
        if reason is not None:
            return GuardDecision.reject(RULE_ADAPTER_CONFIG, reason)

        if entry.rule == _STPX_RULE:
            uds = self._uds.check(bytes.fromhex(match.group(2)))
            if not uds.allowed:
                return GuardDecision.reject(
                    RULE_UDS,
                    f"Request in field D: rejected by UdsGuard ({uds.rule}): {uds.reason}",
                    uds_rule=uds.rule,
                )

        return GuardDecision.allow(entry.rule)

    @staticmethod
    def _match(line: str) -> tuple[AllowEntry | None, re.Match[str] | None]:
        """Returns the first allowlist entry with a full match, or (None, None)."""
        for entry in ALLOWLIST:
            match = entry.pattern.fullmatch(line)
            if match is not None:
                return entry, match
        return None, None

    @staticmethod
    def _check_address(kind: AddressKind, match: re.Match[str], ctx: GuardContext) -> str | None:
        """Checks the addressee against the catalog and the current target; rejection reason or None."""
        if kind is AddressKind.PAIR:
            ids = (int(match.group(1), 16), int(match.group(2), 16))
        else:
            ids = (int(match.group(1), 16),)
        if FUNCTIONAL_ID in ids:
            return "Functional address 7DF is always rejected"

        target = ctx.target
        if target is None:
            return "No target selected for a command with an address"
        catalog = ctx.catalog
        if catalog.pair_of(target.tx_id) != (target.tx_id, target.rx_id):
            return f"Target {target.vag_address} ({target.tx_id:03X}, {target.rx_id:03X}) does not match the pair from the catalog"

        if kind is AddressKind.TX:
            (tx,) = ids
            if tx not in catalog.tx_ids():
                return f"CAN ID {tx:03X} is not the tx of any catalog module"
            if tx != target.tx_id:
                return f"CAN ID {tx:03X} differs from the tx of the current target {target.tx_id:03X}"
        elif kind is AddressKind.RX:
            (rx,) = ids
            if rx not in catalog.rx_ids():
                return f"CAN ID {rx:03X} is not the rx of any catalog module"
            if rx != target.rx_id:
                return f"CAN ID {rx:03X} differs from the rx of the current target {target.rx_id:03X}"
        else:
            tx, rx = ids
            if catalog.pair_of(tx) != (tx, rx):
                return f"Pair {tx:03X},{rx:03X} is not the pair of a single catalog module"
            if (tx, rx) != (target.tx_id, target.rx_id):
                return (
                    f"Pair {tx:03X},{rx:03X} differs from the pair of the current target "
                    f"{target.tx_id:03X},{target.rx_id:03X}"
                )
        return None

    @staticmethod
    def _check_value_range(rule: str, match: re.Match[str]) -> str | None:
        """Upper timeout limit of `STPTO` and of the `T:` field in `STPX`."""
        if rule == _STPTO_RULE:
            value = match.group(1)
        elif rule == _STPX_RULE:
            value = match.group(3)
        else:
            return None
        if value is not None and int(value) > MAX_TIMEOUT_MS:
            return f"Timeout {value} ms exceeds {MAX_TIMEOUT_MS} ms"
        return None

    @staticmethod
    def _check_adapter_config(rule: str, line: str, ctx: GuardContext) -> str | None:
        """Adapter configuration model conditions for `STPX` and `ATFCSM1`."""
        if rule == _STPX_RULE:
            return ctx.adapter.check_stpx(ctx.target)
        if rule == _FCSM_RULE and line == "ATFCSM1":
            target = ctx.target
            if target is not None and ctx.catalog.pair_of(target.tx_id) != (target.tx_id, target.rx_id):
                return f"Target {target.vag_address} does not match the pair from the catalog"
            return ctx.adapter.check_fcsm1(target)
        return None
