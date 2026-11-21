"""Model of the volatile STN2120 adapter configuration (spec T2, audit M6).

`AdapterConfigModel` describes the adapter state resulting from the lines sent.
The model is an immutable value: `apply(line, reply_ok)` returns a new model. It
is used by `StnDriver` (the `adapter` field in `GuardContext`) and by the audit,
which rebuilds the model only from `tx`/`rx` pairs of the `transport` layer. The
`reply_ok` argument is decided by the shared function `reply_ok_for(line, reply)`,
so the driver and the audit build the model identically.

Update rule (conservative):
    Narrowing effects (reset, clearing lists, protocol change, disabling
    `CAF1`, unknown value) are always applied, also without an `OK` reply,
    because the adapter state after a failed command is uncertain. Setting
    effects (protocol open, `caf1`, header, filter, pair, FC mode) are applied
    only with `reply_ok`. As a result, uncertainty always tightens the
    `check_stpx` and `check_fcsm1` conditions, never relaxes them.

The model also handles lines outside the allowlist (e.g. `ATCAF0`,
`ATFCSD021101`, `ATZ`), because the audit applies every line from the log to
the model to detect the effects of forged or erroneous sequences.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Any, Final

from obd_bridge.stn.parser import AdapterReply, ReplyOutcome, split_lines
from obd_bridge.stn.state import DriverState

if TYPE_CHECKING:
    from obd_bridge.vag.catalog import EcuTarget

__all__ = [
    "FC_DATA",
    "FORMAT_LINES",
    "AdapterConfigModel",
    "reply_ok_for",
    "reset_evidence",
    "stale_input_tolerated",
]

FC_DATA: Final[str] = "300000"
"""The only allowed FC frame data for `ATFCSD` (audit C1): CTS, BS 0, STmin 0."""

FORMAT_LINES: Final[tuple[str, ...]] = ("ATE0", "ATL0", "ATS0", "ATH1")
"""Formatting lines required to set the `formatted` field."""

# Opposite formatting settings remove the corresponding line from `format_ok`.
_FORMAT_OPPOSITES: Final[dict[str, str]] = {
    "ATE1": "ATE0",
    "ATL1": "ATL0",
    "ATS1": "ATS0",
    "ATH0": "ATH1",
}

# Reset lines: the model returns to the empty state regardless of the reply.
_RESET_LINES: Final[frozenset[str]] = frozenset({"ATWS", "ATZ", "ATD"})

# Lines for which `reply_ok_for` looks for `ELM327` instead of `OK`.
_RESET_REPLY_LINES: Final[frozenset[str]] = frozenset({"ATWS", "ATZ"})

# Queries in which `ELM327` is an ordinary reply value (not a sign of reset).
_ELM_REPLY_LINES: Final[frozenset[str]] = frozenset({"ATI"})

# Adapter texts after a reset or with the automatic protocol (the probe does not use it).
_RESET_MARKERS: Final[tuple[str, ...]] = ("LV RESET", "SEARCHING", "BUS INIT")

# Lines and states in which unread bytes before a write do not block the session:
# `ATWS` in RAW is a reset, and the model in RAW is empty (late banner after opening the port).
_STALE_TOLERATED: Final[frozenset[tuple[str, DriverState]]] = frozenset({("ATWS", DriverState.RAW)})

_ID3: Final[str] = r"([0-9A-F]{3})"
_RE_ATSH: Final = re.compile(r"ATSH(.*)")
_RE_ATCRA: Final = re.compile(r"ATCRA(.*)")
_RE_ATFCSH: Final = re.compile(r"ATFCSH(.*)")
_RE_ATFCSD: Final = re.compile(r"ATFCSD(.*)")
_RE_ATFCSM: Final = re.compile(r"ATFCSM(.*)")
_RE_ATCAF: Final = re.compile(r"ATCAF(.*)")
_RE_ID3: Final = re.compile(_ID3)
_RE_PAIR: Final = re.compile(rf"(?:STCFCPA|STCAFCP){_ID3},{_ID3}")
_RE_FC_FILTER: Final = re.compile(rf"(?:STFFCA|STFAFC){_ID3},7FF")
# A protocol change other than `STP33` closes protocol 33 in the model.
_RE_PROTOCOL: Final = re.compile(r"STP[0-9]+|ATSP.*|ATTP.*")

_STP33: Final[str] = "STP33"


def _id_or_none(value: str) -> int | None:
    """Returns the number for exactly 3 hex digits, or None (unknown value)."""
    return int(value, 16) if _RE_ID3.fullmatch(value) else None


@dataclass(frozen=True)
class AdapterConfigModel:
    """Volatile adapter configuration rebuilt from the lines sent.

    Attributes:
        format_ok: lines from `FORMAT_LINES` that got `OK` since the last reset.
        identified: `STI` returned a value starting with `STN`.
        protocol_open: protocol 33 open (`STP33` with `OK`).
        caf1: automatic ISO-TP formatting enabled (`ATCAF1` after `STP33`).
        fcsm: FC mode (0 or 1); None means an unknown value.
        fcsh: CAN ID of the FC frame header (`ATFCSH`), or None.
        fcsd: FC frame data (`ATFCSD`), or None.
        header: CAN ID of the request header (`ATSH`), or None.
        cra: CAN ID of the receive filter (`ATCRA`), or None.
        pairs: FC pairs (tx, rx) from `STCFCPA` or `STCAFCP`.
        fc_filters: CAN IDs of FC filters from `STFFCA` or `STFAFC` (mask 7FF).
    """

    format_ok: frozenset[str] = field(default_factory=frozenset)
    identified: bool = False
    protocol_open: bool = False
    caf1: bool = False
    fcsm: int | None = None
    fcsh: int | None = None
    fcsd: str | None = None
    header: int | None = None
    cra: int | None = None
    pairs: frozenset[tuple[int, int]] = field(default_factory=frozenset)
    fc_filters: frozenset[int] = field(default_factory=frozenset)

    @property
    def formatted(self) -> bool:
        """True when all lines `ATE0`, `ATL0`, `ATS0` and `ATH1` got `OK`."""
        return all(line in self.format_ok for line in FORMAT_LINES)

    def apply(self, line: str, reply_ok: bool) -> AdapterConfigModel:
        """Returns the model after sending line `line`.

        Parameters:
            line: line sent to the adapter (without terminator).
            reply_ok: result of `reply_ok_for(line, reply)` for the adapter reply.

        Narrowing effects are always applied, setting effects only with
        `reply_ok` (rule in the module description). Lines without effect on the
        model (queries, `STPX`, unknown lines) return the same object.
        """
        if line in _RESET_LINES:
            return AdapterConfigModel()
        changes = self._narrowing(line)
        if reply_ok:
            changes.update(self._setting(line))
        return replace(self, **changes) if changes else self

    def _narrowing(self, line: str) -> dict[str, Any]:
        """Narrowing effects of a line, applied regardless of the reply."""
        changes: dict[str, Any] = {}
        if line == "STPC":
            changes["protocol_open"] = False
        elif line == _STP33:
            changes.update(caf1=False, cra=None)
        elif _RE_PROTOCOL.fullmatch(line):
            changes.update(protocol_open=False, caf1=False, cra=None)
        elif line == "STCFCPC":
            changes["pairs"] = frozenset()
        elif line in {"STFFCC", "STFAC"}:
            changes["fc_filters"] = frozenset()
        elif line == "ATAR":
            changes.update(cra=None, fc_filters=frozenset())
        elif (match := _RE_ATCAF.fullmatch(line)) and match.group(1) != "1":
            changes["caf1"] = False
        elif (match := _RE_ATFCSM.fullmatch(line)) and match.group(1) not in {"0", "1"}:
            changes["fcsm"] = None
        elif (match := _RE_ATFCSD.fullmatch(line)) and match.group(1) != FC_DATA:
            changes["fcsd"] = None
        elif (match := _RE_ATFCSH.fullmatch(line)) and _id_or_none(match.group(1)) is None:
            changes["fcsh"] = None
        elif (match := _RE_ATSH.fullmatch(line)) and _id_or_none(match.group(1)) is None:
            changes["header"] = None
        elif (match := _RE_ATCRA.fullmatch(line)) and _id_or_none(match.group(1)) is None:
            changes["cra"] = None
        return changes

    def _setting(self, line: str) -> dict[str, Any]:
        """Setting effects of a line, applied only with an `OK` reply."""
        if line in FORMAT_LINES:
            return {"format_ok": self.format_ok | {line}}
        if line in _FORMAT_OPPOSITES:
            return {"format_ok": self.format_ok - {_FORMAT_OPPOSITES[line]}}
        if line == "STI":
            return {"identified": True}
        if line == _STP33:
            return {"protocol_open": True}
        if line == "ATCAF1":
            return {"caf1": True}
        if line in {"ATFCSM0", "ATFCSM1"}:
            return {"fcsm": int(line[-1])}
        if match := _RE_ATFCSD.fullmatch(line):
            return {"fcsd": match.group(1)}
        if match := _RE_ATFCSH.fullmatch(line):
            return {"fcsh": _id_or_none(match.group(1))}
        if match := _RE_ATSH.fullmatch(line):
            return {"header": _id_or_none(match.group(1))}
        if match := _RE_ATCRA.fullmatch(line):
            return {"cra": _id_or_none(match.group(1))}
        if match := _RE_PAIR.fullmatch(line):
            pair = (int(match.group(1), 16), int(match.group(2), 16))
            return {"pairs": self.pairs | {pair}}
        if match := _RE_FC_FILTER.fullmatch(line):
            return {"fc_filters": self.fc_filters | {int(match.group(1), 16)}}
        return {}

    def check_fcsm1(self, target: EcuTarget | None) -> str | None:
        """Condition for `ATFCSM1`: `fcsh` equal to the target tx and `fcsd == "300000"`.

        Returns the rejection reason, or None when the condition is met.
        """
        if target is None:
            return "ATFCSM1 requires a selected target"
        if self.fcsh != target.tx_id:
            return (
                f"ATFCSM1 requires a prior ATFCSH{target.tx_id:03X} "
                f"(current FC header: {_fmt_id(self.fcsh)})"
            )
        if self.fcsd != FC_DATA:
            return f"ATFCSM1 requires a prior ATFCSD{FC_DATA} (current FC data: {self.fcsd or 'none'})"
        return None

    def check_stpx(self, target: EcuTarget | None) -> str | None:
        """Condition for `STPX` for target `target` (spec T2, audit C2 and M6).

        Required: protocol open, `caf1`, `header == target.tx_id`,
        `cra == target.rx_id` and an FC condition depending on `fcsm`. Returns
        the rejection reason, or None when all conditions are met.
        """
        if target is None:
            return "STPX requires a selected target"
        if not self.protocol_open:
            return "STPX requires open protocol 33 (STP33)"
        if not self.caf1:
            return "STPX requires ATCAF1 after opening the protocol (automatic ISO-TP formatting)"
        if self.header != target.tx_id:
            return f"Adapter header {_fmt_id(self.header)} does not match target tx {target.tx_id:03X}"
        if self.cra != target.rx_id:
            return f"Adapter receive filter {_fmt_id(self.cra)} does not match target rx {target.rx_id:03X}"
        return self._check_fc(target)

    def _check_fc(self, target: EcuTarget) -> str | None:
        """FC configuration condition for `STPX`."""
        tx, rx = target.tx_id, target.rx_id
        if self.fcsm == 1:
            if self.fcsh != tx:
                return f"FC mode 1 with FC header {_fmt_id(self.fcsh)} instead of target tx {tx:03X}"
            if self.fcsd != FC_DATA:
                return f"FC mode 1 with FC data {self.fcsd or 'none'} instead of {FC_DATA}"
            return None
        if self.fcsm == 0:
            if self.pairs:
                if (tx, rx) not in self.pairs:
                    return f"No FC pair {tx:03X},{rx:03X} for the target while pairs are active"
                if rx not in self.fc_filters:
                    return f"No FC filter {rx:03X},7FF for the target while pairs are active"
                return None
            if target.fc_mode != "auto":
                return f"Target {target.vag_address} requires an FC pair, but the adapter has no pair"
            return None
        return "Adapter FC mode unknown (no ATFCSM0 or ATFCSM1 since reset)"


def _fmt_id(value: int | None) -> str:
    """CAN ID as shown in a report: 3 hex digits or `none`."""
    return "none" if value is None else f"{value:03X}"


def reply_ok_for(line: str, reply: AdapterReply) -> bool:
    """Decides whether reply `reply` confirms execution of line `line`.

    `STI`: the first reply line starts with `STN`. `ATWS` and `ATZ`: some line
    contains `ELM327`. All other lines: the reply is exactly `OK`.
    The result is the `reply_ok` argument of `AdapterConfigModel.apply`.
    """
    if line == "STI":
        return reply.outcome is ReplyOutcome.VALUE and bool(reply.lines) and reply.lines[0].startswith("STN")
    if line in _RESET_REPLY_LINES:
        return any("ELM327" in text for text in reply.lines)
    return reply.outcome is ReplyOutcome.OK


def reset_evidence(line: str, raw: bytes, format_ok: frozenset[str]) -> str | None:
    """Description of signs of an adapter reset or reply desync in reply `raw` to `line`, or None.

    Shared pure function of the driver (`StnDriver._receive`) and the audit, so
    both detect a reset identically. Signs: echo of the line when `format_ok`
    (the model before this line) contains `ATE0`; `ELM327` in the reply to a
    line other than `ATWS`, `ATZ`, `ATD` and `ATI`; the texts `LV RESET`,
    `SEARCHING`, `BUS INIT`. Reset lines (`ATWS`, `ATZ`, `ATD`) are not evaluated.
    """
    if line in _RESET_LINES:
        return None
    lines, echo = split_lines(raw, line)
    if echo and "ATE0" in format_ok:
        return f"echo of line {line} despite ATE0"
    for text in lines:
        if "ELM327" in text and line not in _ELM_REPLY_LINES:
            return f"banner {text!r} in reply to {line}"
        if any(marker in text for marker in _RESET_MARKERS):
            return f"{text!r} in reply to {line}"
    return None


def stale_input_tolerated(line: str, state: DriverState) -> bool:
    """Whether unread bytes before writing line `line` in state `state` do not indicate a desync.

    Applies only to `ATWS` in RAW (late banner after opening the port): the
    bytes are logged and discarded, and the line is sent. In all other cases
    unread bytes block the session (driver) or open the reset lockout in the
    audit. Closing (`STPC`) is decided separately.
    """
    return (line, state) in _STALE_TOLERATED
