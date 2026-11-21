"""Tests of layer L0 (spec T3; FR-03, FR-04, FR-05, FR-06).

No test opens `/dev/*`: `SerialTransport` gets a fake
`serial.serial_for_url` and the URL `fake://port`.
"""

from __future__ import annotations

import errno
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import serial
import serial.tools.list_ports

from obd_bridge.errors import ObdBridgeError, ReplayMismatch, TransportError, TransportTimeout
from obd_bridge.traffic_log import escape
from obd_bridge.transport import ByteTransport, NullTransport, ReplayTransport, SerialTransport
from obd_bridge.transport.serial_transport import FTDI_VENDOR_ID, find_adapter_ports

_TERMINATOR = b"\r\r>"


# ---------------------------------------------------------------------------
# SerialTransport


class _FakePort:
    """Fake pyserial port that records the order of operations."""

    def __init__(self, calls: list[tuple[str, object]], chunks: list[bytes] | None = None) -> None:
        object.__setattr__(self, "calls", calls)
        object.__setattr__(self, "chunks", list(chunks or []))
        object.__setattr__(self, "is_open", False)

    def __setattr__(self, name: str, value: object) -> None:
        self.calls.append((f"set:{name}", value))
        object.__setattr__(self, name, value)

    def open(self) -> None:
        self.calls.append(("open", None))
        object.__setattr__(self, "is_open", True)

    def close(self) -> None:
        self.calls.append(("close", None))
        object.__setattr__(self, "is_open", False)

    @property
    def in_waiting(self) -> int:
        return len(self.chunks[0]) if self.chunks else 0

    def read(self, size: int = 1) -> bytes:
        return self.chunks.pop(0) if self.chunks else b""

    def write(self, data: bytes) -> int:
        self.calls.append(("write", bytes(data)))
        return len(data)

    def flush(self) -> None:
        self.calls.append(("flush", None))

    def reset_input_buffer(self) -> None:
        self.calls.append(("reset_input_buffer", None))


def _install_fake_serial(
    monkeypatch: pytest.MonkeyPatch, chunks: list[bytes] | None = None, error: Exception | None = None
) -> list[tuple[str, object]]:
    calls: list[tuple[str, object]] = []

    def fake_serial_for_url(url: str, *args: Any, **kwargs: Any) -> _FakePort:
        assert "/dev/" not in url
        calls.append(("serial_for_url", {"url": url, "args": args, **kwargs}))
        if error is not None:
            raise error
        return _FakePort(calls, chunks)

    monkeypatch.setattr(serial, "serial_for_url", fake_serial_for_url)
    return calls


def test_serial_open_without_dtr_pulse(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _install_fake_serial(monkeypatch, chunks=[b"ELM327 v1.3a\r", b"\r>"])
    transport = SerialTransport("fake://port")
    assert isinstance(transport, ByteTransport)
    assert transport.can_set_baudrate is True

    transport.open()

    name, kwargs = calls[0]
    assert name == "serial_for_url"
    assert kwargs == {
        "url": "fake://port",
        "args": (),
        "baudrate": 38400,
        "bytesize": 8,
        "parity": "N",
        "stopbits": 1,
        "rtscts": False,
        "dsrdtr": False,
        "timeout": 0.05,
        "do_not_open": True,
    }
    # dtr and rts set to False before open(), without a pulse.
    assert calls[1:4] == [("set:dtr", False), ("set:rts", False), ("open", None)]

    transport.write(b"ATI\r")
    assert ("write", b"ATI\r") in calls
    assert transport.read_until(b">", 1.0) == b"ELM327 v1.3a\r\r>"
    with pytest.raises(TransportTimeout) as excinfo:
        transport.read_until(b">", 0.01)
    assert excinfo.value.partial == b""
    transport.reset_input()
    assert ("reset_input_buffer", None) in calls
    transport.close()
    transport.close()
    assert calls.count(("close", None)) == 1

    # A pyserial exception is turned into TransportError with a fixed message.
    _install_fake_serial(monkeypatch, error=serial.SerialException("no port"))
    failing = SerialTransport("fake://missing")
    with pytest.raises(TransportError) as excinfo_open:
        failing.open()
    assert "fake://missing" in str(excinfo_open.value)
    with pytest.raises(TransportError):
        failing.write(b"ATI\r")


def test_serial_exclusive_only_for_local_device(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls = _install_fake_serial(monkeypatch, chunks=[b"OK\r\r>", b"\r"])
    device = str(tmp_path / "cu.usbserial-TEST")
    local = SerialTransport(device)
    local.open()
    assert calls[0][1]["exclusive"] is True and calls[0][1]["url"] == device

    for url in ("socket://127.0.0.1:35000", "fake://port", "loop://"):
        calls = _install_fake_serial(monkeypatch)
        SerialTransport(url).open()
        assert "exclusive" not in calls[0][1], url

    # pending_input: bytes after `>` in the internal buffer plus the port `in_waiting`.
    local.write(b"ATI\r")
    assert local.read_until(b">", 1.0) == b"OK\r\r>"
    assert local.pending_input() == 1
    local.close()


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (FileNotFoundError(errno.ENOENT, "No such file or directory"), "file does not exist"),
        (PermissionError(errno.EACCES, "Permission denied"), "permission denied"),
        (OSError(errno.EBUSY, "Resource busy"), "port in use by another program"),
        (
            serial.SerialException(errno.EAGAIN, "Could not exclusively lock port x: Resource temporarily unavailable"),
            "port in use by another program",
        ),
    ],
)
def test_serial_errors_without_system_text(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, error: Exception, expected: str
) -> None:
    _install_fake_serial(monkeypatch, error=error)
    device = str(tmp_path / "cu.usbserial-TEST")
    with pytest.raises(TransportError) as caught:
        SerialTransport(device).open()
    message = str(caught.value)
    assert message == f"Cannot open port {device}: {expected}"
    assert caught.value.os_errno == error.errno
    for system_text in ("No such file", "Permission denied", "Resource", "Could not"):
        assert system_text not in message


def test_serial_read_until_partial_on_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_serial(monkeypatch, chunks=[b"SEARCHING", b"...\r"])
    transport = SerialTransport("fake://port")
    transport.open()
    with pytest.raises(TransportTimeout) as excinfo:
        transport.read_until(b">", 0.05)
    assert excinfo.value.partial == b"SEARCHING...\r"
    assert excinfo.value.exit_code == 3


# ---------------------------------------------------------------------------
# NullTransport

_NULL_TABLE: list[tuple[str, bytes]] = [
    ("ATWS", b"\rELM327 v1.3a"),
    ("ATI", b"ELM327 v1.3a"),
    ("AT@1", b"SCANTOOL.NET LLC"),
    ("STI", b"STN2120 v4.5.0"),
    ("STDI", b"STN2120 r1.0"),
    ("ATRV", b"12.6V"),
    ("STVR", b"12.60"),
    ("ATPPS", b"03:19 F  0C:68 N  21:FF F  24:00 F\r25:00 F  26:00 F  2A:04 F"),
    ("ATDPN", b"A6"),
    ("ATDP", b"AUTO, ISO 15765-4 (CAN 11/500)"),
    ("STPR", b"33"),
    ("STPRS", b"ISO 15765-4 (CAN 11/500)"),
    ("STPBRR", b"500000"),
    ("ATCS", b"T:00 R:00"),
    ("STPX H:7E1,D:22F187,R:1", b"NO DATA"),
    ("ATL0", b"OK"),
    ("STP33", b"OK"),
]


@pytest.mark.parametrize(("line", "expected"), _NULL_TABLE, ids=[row[0] for row in _NULL_TABLE])
def test_null_responses(line: str, expected: bytes) -> None:
    transport = NullTransport()
    assert isinstance(transport, ByteTransport)
    assert transport.url == "null://"
    assert transport.can_set_baudrate is False
    transport.open()
    # Banner window: the first read before a write gives an empty timeout.
    with pytest.raises(TransportTimeout) as excinfo:
        transport.read_until(b">", 1.0)
    assert excinfo.value.partial == b""
    # ATE0 is still echoed (echo is on when it is received).
    transport.write(b"ATE0\r")
    assert transport.read_until(b">", 1.0) == b"ATE0\rOK" + _TERMINATOR
    transport.write(line.encode("ascii") + b"\r")
    assert transport.read_until(b">", 1.0) == expected + _TERMINATOR
    assert transport.lines == ["ATE0", line]


def test_null_echo_after_atws_and_baudrate() -> None:
    transport = NullTransport()
    transport.open()
    transport.write(b"ATI\r")
    assert transport.read_until(b">", 1.0) == b"ATI\rELM327 v1.3a" + _TERMINATOR
    transport.write(b"ATE0\r")
    transport.read_until(b">", 1.0)
    transport.write(b"ATI\r")
    assert transport.read_until(b">", 1.0) == b"ELM327 v1.3a" + _TERMINATOR
    # ATWS with echo off: no echo, but after the reset echo comes back.
    transport.write(b"ATWS\r")
    assert transport.read_until(b">", 1.0) == b"\rELM327 v1.3a" + _TERMINATOR
    transport.write(b"STI\r")
    assert transport.read_until(b">", 1.0) == b"STI\rSTN2120 v4.5.0" + _TERMINATOR
    with pytest.raises(TransportError):
        transport.set_baudrate(115200)
    transport.close()


def test_null_does_not_import_serial() -> None:
    code = (
        "import sys\n"
        "import obd_bridge.transport.null\n"
        "assert 'serial' not in sys.modules, 'null'\n"
        "import obd_bridge.transport, obd_bridge.transport.replay, obd_bridge.transport.serial_transport\n"
        "assert 'serial' not in sys.modules, 'transport package'\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=60, check=False
    )
    assert result.returncode == 0, result.stderr


# ---------------------------------------------------------------------------
# ReplayTransport


def _event(
    seq: int, ev: str, layer: str, data: str = "", meta: dict[str, Any] | None = None
) -> dict[str, Any]:
    return {
        "v": 1,
        "sid": "test",
        "seq": seq,
        "tm": 0.0,
        "tw": "2026-11-20T10:00:00.000+01:00",
        "ev": ev,
        "layer": layer,
        "ecu": None,
        "data": data,
        "guard": None,
        "meta": meta or {},
    }


def _session_events() -> list[dict[str, Any]]:
    """Banner (timeout), ATI, STPX with a reply and a read that ends with a timeout."""
    raw = [
        ("session_start", "app", "", {"mode": "dry-run"}),
        ("rx", "transport", escape(b""), {"timeout": True, "elapsed_ms": 1000}),
        ("tx", "adapter", "ATI", {}),
        ("tx", "transport", escape(b"ATI\r"), {}),
        ("rx", "transport", escape(b"ELM327 v1.3a\r\r>"), {"elapsed_ms": 5}),
        ("rx", "adapter", "ELM327 v1.3a", {"index": 0}),
        ("tx", "transport", escape(b"STPX H:7E1,D:22F187,R:1\r"), {}),
        ("rx", "transport", escape(b"7E9 10 0E 62 F1 87\\\x01\r"), {"timeout": True}),
        ("session_end", "app", "", {}),
    ]
    return [_event(seq, ev, layer, data, meta) for seq, (ev, layer, data, meta) in enumerate(raw)]


def _write_jsonl(path: Path, events: list[dict[str, Any]]) -> Path:
    path.write_text("".join(json.dumps(event) + "\n" for event in events), encoding="utf-8")
    return path


def test_replay_matches_and_timeout(tmp_path: Path) -> None:
    path = _write_jsonl(tmp_path / "session.jsonl", _session_events())
    transport = ReplayTransport(path)
    assert isinstance(transport, ByteTransport)
    assert transport.remaining == 5
    transport.open()
    with pytest.raises(TransportTimeout) as banner:
        transport.read_until(b">", 1.0)
    assert banner.value.partial == b""
    transport.write(b"ATI\r")
    assert transport.read_until(b">", 1.0) == b"ELM327 v1.3a\r\r>"
    transport.reset_input()
    transport.write(b"STPX H:7E1,D:22F187,R:1\r")
    with pytest.raises(TransportTimeout) as timeout:
        transport.read_until(b">", 1.0)
    assert timeout.value.partial == b"7E9 10 0E 62 F1 87\\\x01\r"
    assert transport.remaining == 0
    transport.close()

    # A list of events instead of a file works the same way.
    from_list = ReplayTransport(_session_events())
    assert from_list.remaining == 5


@pytest.mark.parametrize(
    ("scenario", "expected_seq"),
    [
        ("different_tx", 3),
        ("read_instead_of_write", 6),
        ("write_instead_of_read", 1),
        ("end_of_events", None),
    ],
)
def test_replay_mismatch(scenario: str, expected_seq: int | None) -> None:
    transport = ReplayTransport(_session_events())
    transport.open()
    with pytest.raises(ReplayMismatch) as excinfo:
        if scenario == "different_tx":
            with pytest.raises(TransportTimeout):
                transport.read_until(b">", 1.0)
            transport.write(b"ATZ\r")
        elif scenario == "read_instead_of_write":
            with pytest.raises(TransportTimeout):
                transport.read_until(b">", 1.0)
            transport.write(b"ATI\r")
            transport.read_until(b">", 1.0)
            transport.read_until(b">", 1.0)
        elif scenario == "write_instead_of_read":
            transport.write(b"ATI\r")
        else:
            with pytest.raises(TransportTimeout):
                transport.read_until(b">", 1.0)
            transport.write(b"ATI\r")
            transport.read_until(b">", 1.0)
            transport.write(b"STPX H:7E1,D:22F187,R:1\r")
            with pytest.raises(TransportTimeout):
                transport.read_until(b">", 1.0)
            transport.write(b"ATI\r")
    error = excinfo.value
    assert error.seq == expected_seq
    assert error.exit_code == 5
    assert isinstance(error, ObdBridgeError)
    assert not isinstance(error, TransportError)
    if scenario == "different_tx":
        assert error.expected == b"ATI\r"
        assert error.actual == b"ATZ\r"


# ---------------------------------------------------------------------------
# Adapter detection


class _FakePortInfo:
    """Entry of a fake `comports()` list: device path and USB vendor ID."""

    def __init__(self, device: str, vid: int | None) -> None:
        self.device = device
        self.vid = vid


def test_find_adapter_ports_filters_ftdi_and_sorts(monkeypatch: pytest.MonkeyPatch) -> None:
    """Only ports with the FTDI vendor ID, sorted; other USB serial chips and ports without a VID are skipped."""
    ports = [
        _FakePortInfo("/dev/cu.usbserial-TEST0002", FTDI_VENDOR_ID),
        _FakePortInfo("/dev/cu.Bluetooth-Incoming-Port", None),
        _FakePortInfo("/dev/cu.usbmodem-TEST", 0x2341),
        _FakePortInfo("/dev/cu.usbserial-TEST0001", FTDI_VENDOR_ID),
    ]
    monkeypatch.setattr(serial.tools.list_ports, "comports", lambda: ports)
    assert find_adapter_ports() == ["/dev/cu.usbserial-TEST0001", "/dev/cu.usbserial-TEST0002"]
    monkeypatch.setattr(serial.tools.list_ports, "comports", lambda: [])
    assert find_adapter_ports() == []


def test_find_adapter_ports_never_opens_a_port(monkeypatch: pytest.MonkeyPatch) -> None:
    """Detection enumerates only: neither `serial_for_url` nor `Serial.open` is called."""
    opened: list[str] = []
    monkeypatch.setattr(serial, "serial_for_url", lambda url, *a, **k: opened.append(url))
    monkeypatch.setattr(serial.Serial, "open", lambda self: opened.append(str(self.port)))
    monkeypatch.setattr(
        serial.tools.list_ports, "comports", lambda: [_FakePortInfo("/dev/cu.usbserial-TEST0001", FTDI_VENDOR_ID)]
    )
    assert find_adapter_ports() == ["/dev/cu.usbserial-TEST0001"]
    assert opened == []


def test_find_adapter_ports_enumeration_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """An OS error while listing ports gives `TransportError` with a fixed description."""

    def failing() -> list[_FakePortInfo]:
        raise PermissionError(errno.EACCES, "denied")

    monkeypatch.setattr(serial.tools.list_ports, "comports", failing)
    with pytest.raises(TransportError, match="Cannot list serial ports: permission denied"):
        find_adapter_ports()
