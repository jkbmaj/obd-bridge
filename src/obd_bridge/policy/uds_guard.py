"""UDS guard: fixed table of allowed read-only diagnostic requests (spec T2, FR-12).

The policy rejects by default. Only shapes from the table are accepted:
0x22 (1 to 3 DIDs), 0x19 with subfunctions 01, 02, 03, 04, 06 and 0A (04 and 06
without record 0xFF) and OBD services 01, 03, 06, 07, 09 and 0A. Every other SID,
including 0x10 and 0x3E, is rejected entirely.

The table is a code constant. There is no parameter, environment variable or
option that extends or disables it (FR-17).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

from obd_bridge.policy.decision import GuardDecision

__all__ = [
    "ALLOWED_RULES",
    "ALLOWED_SIDS",
    "RULE_EMPTY",
    "RULE_RECORD_FF",
    "RULE_SHAPE",
    "RULE_SID",
    "UdsGuard",
]

RULE_EMPTY: Final[str] = "UDS/empty"
"""Empty payload."""

RULE_SID: Final[str] = "UDS/sid"
"""SID outside the table of allowed services."""

RULE_SHAPE: Final[str] = "UDS/shape"
"""Allowed SID with a disallowed length or subfunction."""

RULE_RECORD_FF: Final[str] = "UDS/record-ff"
"""Record 0xFF (all records) in 0x19 04 or 0x19 06."""


@dataclass(frozen=True)
class _Shape:
    """Shape of an allowed request: rule, permitted lengths and the record 0xFF ban."""

    rule: str
    lengths: frozenset[int]
    forbid_record_ff: bool = False


_SID_READ_DTC: Final[int] = 0x19

# Services without subfunctions: SID at position 0 and permitted lengths of the whole payload.
_SID_SHAPES: Final[Mapping[int, _Shape]] = MappingProxyType(
    {
        0x22: _Shape("UDS/0x22", frozenset({3, 5, 7})),
        0x01: _Shape("OBD/0x01", frozenset(range(2, 8))),
        0x03: _Shape("OBD/0x03", frozenset({1})),
        0x06: _Shape("OBD/0x06", frozenset({2})),
        0x07: _Shape("OBD/0x07", frozenset({1})),
        0x09: _Shape("OBD/0x09", frozenset({2})),
        0x0A: _Shape("OBD/0x0A", frozenset({1})),
    }
)

# Subfunctions of 0x19 (ReadDTCInformation). Bit 0x80 (suppressPosRsp) does not occur
# in any key, so subfunctions with this bit are rejected.
_READ_DTC_SHAPES: Final[Mapping[int, _Shape]] = MappingProxyType(
    {
        0x01: _Shape("UDS/0x19/01", frozenset({3})),
        0x02: _Shape("UDS/0x19/02", frozenset({3})),
        0x03: _Shape("UDS/0x19/03", frozenset({2})),
        0x04: _Shape("UDS/0x19/04", frozenset({6}), forbid_record_ff=True),
        0x06: _Shape("UDS/0x19/06", frozenset({6}), forbid_record_ff=True),
        0x0A: _Shape("UDS/0x19/0A", frozenset({2})),
    }
)

ALLOWED_SIDS: Final[frozenset[int]] = frozenset(_SID_SHAPES) | {_SID_READ_DTC}
"""SIDs from the UdsGuard table (8 entries)."""

ALLOWED_RULES: Final[frozenset[str]] = frozenset(
    shape.rule for shape in (*_SID_SHAPES.values(), *_READ_DTC_SHAPES.values())
)
"""Acceptance rules, one per row of the UdsGuard table (13 entries)."""


def _lengths_text(lengths: frozenset[int]) -> str:
    """Returns the list of permitted lengths in ascending order."""
    return ", ".join(str(n) for n in sorted(lengths))


class UdsGuard:
    """Guard for UDS and OBD requests without configuration parameters.

    The `check` method is pure: it has no state, does not log and raises no
    exception for any bytes payload. The `guard` event is emitted by the caller.
    """

    def check(self, payload: bytes) -> GuardDecision:
        """Evaluates a request payload (SID at position 0) against the UdsGuard table.

        Parameters:
            payload: request bytes (`bytes`, `bytearray` or `memoryview`).

        Returns a decision with the table row rule on acceptance, or with rule
        `UDS/empty`, `UDS/sid`, `UDS/shape` or `UDS/record-ff` on rejection.

        Raises:
            TypeError: payload is not a byte sequence.
        """
        if not isinstance(payload, (bytes, bytearray, memoryview)):
            raise TypeError(
                f"UDS payload must be of type bytes, got {type(payload).__name__}"
            )
        data = bytes(payload)

        if not data:
            return GuardDecision.reject(RULE_EMPTY, "Empty UDS payload: no SID to evaluate")

        sid = data[0]
        if sid == _SID_READ_DTC:
            return self._check_read_dtc(data)

        shape = _SID_SHAPES.get(sid)
        if shape is None:
            return GuardDecision.reject(
                RULE_SID,
                f"SID 0x{sid:02X} is not one of the allowed read-only services",
            )
        return self._check_shape(shape, data)

    @staticmethod
    def _check_read_dtc(data: bytes) -> GuardDecision:
        """Evaluates a 0x19 request against the subfunction table."""
        if len(data) < 2:
            return GuardDecision.reject(RULE_SHAPE, "Missing subfunction of service 0x19")
        sub = data[1]
        shape = _READ_DTC_SHAPES.get(sub)
        if shape is None:
            reason = f"Subfunction 0x{sub:02X} of service 0x19 is not allowed"
            if sub & 0x80:
                reason += " (bit suppressPosRsp 0x80 is not allowed)"
            return GuardDecision.reject(RULE_SHAPE, reason)
        return UdsGuard._check_shape(shape, data)

    @staticmethod
    def _check_shape(shape: _Shape, data: bytes) -> GuardDecision:
        """Checks the payload length and the record 0xFF ban for shape `shape`."""
        if len(data) not in shape.lengths:
            return GuardDecision.reject(
                RULE_SHAPE,
                f"Disallowed length of request {shape.rule}: {len(data)} B "
                f"(allowed: {_lengths_text(shape.lengths)})",
            )
        if shape.forbid_record_ff and data[-1] == 0xFF:
            return GuardDecision.reject(
                RULE_RECORD_FF,
                f"Record 0xFF (all records) in request {shape.rule} is not allowed",
            )
        return GuardDecision.allow(shape.rule)
