"""Tests of `obd_bridge.uds.dtc`: DTC text form, status byte and identification DID decoding."""

from __future__ import annotations

import pytest

from obd_bridge.uds.dtc import (
    DTC_STATUS_FLAGS,
    FAULT_STATUS_MASK,
    DidValue,
    decode_did_data,
    decode_did_reply,
    did_name,
    dtc_presence,
    dtc_status_flags,
    format_dtc,
    is_fault_status,
    is_identification_did,
    parse_dtc,
)

ROUND_TRIPS: list[tuple[str, int]] = [
    ("C120507", 0x520507),
    ("B125001", 0x925001),
    ("U120100", 0xD20100),
    ("U120A00", 0xD20A00),
    ("C12C800", 0x52C800),
    ("B123413", 0x923413),
    ("C130315", 0x530315),
    ("P000000", 0x000000),
    ("P3FFFFF", 0x3FFFFF),
    ("C000000", 0x400000),
    ("B000000", 0x800000),
    ("U3FFFFF", 0xFFFFFF),
]


@pytest.mark.parametrize(("text", "code"), ROUND_TRIPS)
def test_dtc_round_trip(text: str, code: int) -> None:
    assert format_dtc(code) == text
    assert parse_dtc(text) == code
    assert parse_dtc(text.lower()) == code


def test_all_four_letters() -> None:
    assert [format_dtc(top << 22)[0] for top in range(4)] == ["P", "C", "B", "U"]


@pytest.mark.parametrize(
    "text",
    ["", "C10480", "C1205070", "X104807", "C404807", "C10480G", " C120507", "C120507 ", "C1048 07", "C-04807"],
)
def test_parse_dtc_rejects_invalid(text: str) -> None:
    with pytest.raises(ValueError, match="Invalid DTC"):
        parse_dtc(text)


@pytest.mark.parametrize("value", [None, 520507, b"C120507"])
def test_parse_dtc_rejects_non_string(value: object) -> None:
    with pytest.raises(ValueError, match="must be a string"):
        parse_dtc(value)  # type: ignore[arg-type]


def test_format_dtc_range_and_type() -> None:
    with pytest.raises(ValueError):
        format_dtc(-1)
    with pytest.raises(ValueError):
        format_dtc(0x1000000)
    with pytest.raises(TypeError):
        format_dtc(True)
    with pytest.raises(TypeError):
        format_dtc("520507")  # type: ignore[arg-type]


def test_status_flags_per_bit() -> None:
    for bit, name in enumerate(DTC_STATUS_FLAGS):
        assert dtc_status_flags(1 << bit) == (name,)
    assert dtc_status_flags(0x00) == ()
    assert dtc_status_flags(0x09) == ("testFailed", "confirmedDTC")
    assert dtc_status_flags(0xFF) == DTC_STATUS_FLAGS
    assert DTC_STATUS_FLAGS[7] == "warningIndicatorRequested"


@pytest.mark.parametrize(
    ("status", "presence"),
    [
        (0x09, "active"),
        (0x01, "active"),
        (0x51, "active"),
        (0x08, "stored"),
        (0x28, "stored"),
        (0x02, "stored"),
        (0x04, "stored"),
        (0x20, "stored"),
        (0x80, "stored"),
        (0x50, "no fault"),
        (0x10, "no fault"),
        (0x40, "no fault"),
        (0x00, "no fault"),
    ],
)
def test_presence(status: int, presence: str) -> None:
    assert dtc_presence(status) == presence
    assert is_fault_status(status) is (presence != "no fault")


def test_fault_mask_bits() -> None:
    assert FAULT_STATUS_MASK == 0xAF
    assert [bit for bit in range(8) if FAULT_STATUS_MASK & (1 << bit)] == [0, 1, 2, 3, 5, 7]


def test_status_range() -> None:
    with pytest.raises(ValueError):
        dtc_status_flags(0x100)
    with pytest.raises(ValueError):
        dtc_presence(-1)
    with pytest.raises(TypeError):
        dtc_presence(None)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (b"TEST907468  ", ("TEST907468", "ascii")),
        (b"MockGateway\x00\x00", ("MockGateway", "ascii")),
        (b"9001\xff\xff", ("9001", "ascii")),
        (b"H05 \x00\xff ", ("H05", "ascii")),
        (b"  lead", ("  lead", "ascii")),
        (b"", ("", "ascii")),
        (b"   \x00", ("", "ascii")),
        (b"\x01\x02\x03", ("010203", "hex")),
        (b"AB\x07CD  ", ("41420743442020", "hex")),
    ],
)
def test_decode_did_data(data: bytes, expected: tuple[str, str]) -> None:
    assert decode_did_data(data) == expected


def test_decode_did_reply() -> None:
    value = decode_did_reply(bytes.fromhex("62F187") + b"TEST907468 ")
    assert value == DidValue(did=0xF187, text="TEST907468", encoding="ascii", data=b"TEST907468 ")
    assert decode_did_reply(bytes.fromhex("62F18C")).text == ""
    for reply in (b"", bytes.fromhex("62F1"), bytes.fromhex("7F2231"), bytes.fromhex("5902FF")):
        with pytest.raises(ValueError, match="Not a positive 0x22 reply"):
            decode_did_reply(reply)


def test_did_names() -> None:
    assert did_name(0xF187) == "spare part number (OBDeleven: Software number)"
    assert did_name(0xF197) == "system name (OBDeleven: System description)"
    assert did_name(0xF189) == "software version"
    assert did_name(0xF191) == "hardware number"
    assert did_name(0xF1A3) == "hardware version"
    assert did_name(0xF19E) == "ODX name"
    assert did_name(0xF1A2) == "ODX version"
    assert did_name(0xF190) == "VIN"
    assert did_name(0xF18C) == "serial number"
    assert did_name(0xF1FF) is None
    assert is_identification_did(0xF100) and is_identification_did(0xF1FF)
    assert not is_identification_did(0x0600) and not is_identification_did(0xF200)
