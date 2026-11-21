"""DTC codes, DTC status bytes and identification DIDs (pure functions, no I/O).

DTC text form:
    A 3-byte UDS DTC is shown in the 7-character form used by VAG tools
    (OBDeleven, VCDS): the SAE J2012 letter from bits 7..6 of byte 0
    (`P`, `C`, `B`, `U`), a digit from bits 5..4, a hex digit from bits 3..0,
    then byte 1 as two hex digits and byte 2 (failure type byte) as two hex
    digits. Example: `0x520507` is `C120507`, `0xD20100` is `U120100`.

Status byte:
    Bits per ISO 14229-1 (`DTCStatusMask`). A record is a fault only when at
    least one fault bit is set (`FAULT_STATUS_MASK`: bits 0, 1, 2, 3, 5, 7);
    a reply to `19 02 FF` also lists records with only the
    `testNotCompleted...` bits (4, 6) or with status 0x00. `presence` is a
    short label: `active` (bit 0 `testFailed`), `stored` (another fault bit)
    or `no fault` (no fault bit).

Identification DIDs:
    Names follow the VW convention for the `F1xx` range read with service
    0x22. `decode_did_reply` turns a positive `62 <DID> <data>` reply into
    text: ASCII with trailing spaces, NUL and 0xFF padding stripped, or hex
    when the data is not printable.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, Literal

__all__ = [
    "DTC_LETTERS",
    "DTC_STATUS_FLAGS",
    "FAULT_STATUS_MASK",
    "IDENTIFICATION_DID_NAMES",
    "OBDELEVEN_DID_LABELS",
    "PRESENCE_ACTIVE",
    "PRESENCE_NO_FAULT",
    "PRESENCE_STORED",
    "DidValue",
    "decode_did_data",
    "decode_did_reply",
    "did_name",
    "dtc_presence",
    "dtc_status_flags",
    "format_dtc",
    "is_fault_status",
    "is_identification_did",
    "parse_dtc",
]

DTC_LETTERS: Final[str] = "PCBU"
"""SAE J2012 system letters by bits 7..6 of the first DTC byte."""

_DTC_MAX: Final[int] = 0xFFFFFF
_DTC_TEXT_RE: Final = re.compile(r"[PCBU][0-3][0-9A-F]{5}")

DTC_STATUS_FLAGS: Final[tuple[str, ...]] = (
    "testFailed",
    "testFailedThisOperationCycle",
    "pendingDTC",
    "confirmedDTC",
    "testNotCompletedSinceLastClear",
    "testFailedSinceLastClear",
    "testNotCompletedThisOperationCycle",
    "warningIndicatorRequested",
)
"""ISO 14229-1 DTC status bit names, index = bit number (bit 0 first)."""

PRESENCE_ACTIVE: Final[str] = "active"
"""Presence label of a DTC with `testFailed` set."""

PRESENCE_STORED: Final[str] = "stored"
"""Presence label of a DTC without `testFailed` but with another fault bit."""

PRESENCE_NO_FAULT: Final[str] = "no fault"
"""Presence label of a record without any fault bit (e.g. status 0x50 or 0x00)."""

FAULT_STATUS_MASK: Final[int] = 0b1010_1111
"""Fault bits: testFailed (0), testFailedThisOperationCycle (1), pendingDTC (2),
confirmedDTC (3), testFailedSinceLastClear (5), warningIndicatorRequested (7)."""

_POSITIVE_READ_DID: Final[int] = 0x62
_IDENTIFICATION_HIGH: Final[int] = 0xF1
_PADDING: Final[bytes] = b" \x00\xff"
_PRINTABLE: Final[range] = range(0x20, 0x7F)

IDENTIFICATION_DID_NAMES: Final[Mapping[int, str]] = MappingProxyType(
    {
        0xF186: "active diagnostic session",
        0xF187: "spare part number",
        0xF189: "software version",
        0xF18C: "serial number",
        0xF190: "VIN",
        0xF191: "hardware number",
        0xF197: "system name",
        0xF19E: "ODX name",
        0xF1A2: "ODX version",
        0xF1A3: "hardware version",
    }
)
"""Names of identification DIDs (VW convention)."""

OBDELEVEN_DID_LABELS: Final[Mapping[int, str]] = MappingProxyType(
    {
        0xF187: "Software number",
        0xF197: "System description",
    }
)
"""Labels used by the OBDeleven app where they differ from `IDENTIFICATION_DID_NAMES`."""


# ---------------------------------------------------------------------------
# DTC codes


def format_dtc(code: int) -> str:
    """3-byte UDS DTC in the 7-character VAG form, e.g. `0x520507` gives `C120507`.

    Raises:
        TypeError: `code` is not an int (bool is rejected).
        ValueError: `code` outside 0..0xFFFFFF.
    """
    if isinstance(code, bool) or not isinstance(code, int):
        raise TypeError(f"DTC must be int, got {code!r}")
    if not 0 <= code <= _DTC_MAX:
        raise ValueError(f"DTC out of range 0..0xFFFFFF: {code:#x}")
    high = code >> 16
    letter = DTC_LETTERS[high >> 6]
    return f"{letter}{(high >> 4) & 0x3}{high & 0xF:X}{(code >> 8) & 0xFF:02X}{code & 0xFF:02X}"


def parse_dtc(text: str) -> int:
    """Inverse of `format_dtc`: `C120507` (any letter case) gives `0x520507`.

    Raises:
        ValueError: `text` is not a string of exactly 7 characters: a letter
            `P`, `C`, `B` or `U`, a digit 0..3 and five hex digits. Whitespace
            is not accepted.
    """
    if not isinstance(text, str):
        raise ValueError(f"DTC must be a string, got {text!r}")
    upper = text.upper()
    if not _DTC_TEXT_RE.fullmatch(upper):
        raise ValueError(
            f"Invalid DTC {text!r}: expected 7 characters, a letter P/C/B/U, a digit 0..3 "
            "and five hex digits (e.g. C120507)"
        )
    high = (DTC_LETTERS.index(upper[0]) << 6) | (int(upper[1]) << 4) | int(upper[2], 16)
    return (high << 16) | int(upper[3:], 16)


# ---------------------------------------------------------------------------
# DTC status


def _require_status(status: int) -> int:
    if isinstance(status, bool) or not isinstance(status, int):
        raise TypeError(f"DTC status must be int, got {status!r}")
    if not 0 <= status <= 0xFF:
        raise ValueError(f"DTC status out of range 0..0xFF: {status:#x}")
    return status


def dtc_status_flags(status: int) -> tuple[str, ...]:
    """Names of the set bits of a DTC status byte, from bit 0 to bit 7."""
    value = _require_status(status)
    return tuple(name for bit, name in enumerate(DTC_STATUS_FLAGS) if value & (1 << bit))


def is_fault_status(status: int) -> bool:
    """True when at least one bit of `FAULT_STATUS_MASK` is set."""
    return bool(_require_status(status) & FAULT_STATUS_MASK)


def dtc_presence(status: int) -> str:
    """`active` (bit 0 `testFailed`), `stored` (another fault bit) or `no fault` (no fault bit).

    Note: the mapping of `active` and `stored` to the OBDeleven labels
    "static" and "sporadic" is an assumption (static = active, sporadic =
    stored) that still has to be verified against a live read of the same
    module.
    """
    value = _require_status(status)
    if value & 0x01:
        return PRESENCE_ACTIVE
    return PRESENCE_STORED if value & FAULT_STATUS_MASK else PRESENCE_NO_FAULT


# ---------------------------------------------------------------------------
# Identification DIDs


@dataclass(frozen=True)
class DidValue:
    """Decoded identification DID.

    Attributes:
        did: data identifier, e.g. `0xF187`.
        text: ASCII text without trailing padding, or uppercase hex.
        encoding: `ascii` or `hex`.
        data: raw data bytes after `62 <DID>`.
    """

    did: int
    text: str
    encoding: Literal["ascii", "hex"]
    data: bytes


def is_identification_did(did: int) -> bool:
    """True for DIDs in the identification range 0xF100..0xF1FF."""
    return did >> 8 == _IDENTIFICATION_HIGH


def did_name(did: int) -> str | None:
    """Name of an identification DID with the OBDeleven label, or None for an unknown DID.

    Example: `spare part number (OBDeleven: Software number)` for `0xF187`.
    """
    name = IDENTIFICATION_DID_NAMES.get(did)
    if name is None:
        return None
    label = OBDELEVEN_DID_LABELS.get(did)
    return f"{name} (OBDeleven: {label})" if label else name


def decode_did_data(data: bytes) -> tuple[str, Literal["ascii", "hex"]]:
    """DID data as `(text, encoding)`.

    Trailing spaces, NUL and 0xFF bytes are stripped first. When the rest is
    printable ASCII (0x20..0x7E) the result is the text; otherwise it is the
    uppercase hex of the full, unstripped data. All-padding data gives an
    empty ASCII text.
    """
    raw = bytes(data)
    stripped = raw.rstrip(_PADDING)
    if all(byte in _PRINTABLE for byte in stripped):
        return stripped.decode("ascii"), "ascii"
    return raw.hex().upper(), "hex"


def decode_did_reply(reply: bytes) -> DidValue:
    """Positive `62 <DID> <data>` reply as a `DidValue`.

    Raises:
        ValueError: the reply is shorter than 3 bytes or does not start with 0x62.
    """
    raw = bytes(reply)
    if len(raw) < 3 or raw[0] != _POSITIVE_READ_DID:
        raise ValueError(f"Not a positive 0x22 reply: {raw.hex().upper() or '(empty)'}")
    did = int.from_bytes(raw[1:3], "big")
    text, encoding = decode_did_data(raw[3:])
    return DidValue(did=did, text=text, encoding=encoding, data=raw[3:])
