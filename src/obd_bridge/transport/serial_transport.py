"""Serial transport `SerialTransport` on pyserial (spec T3, FR-03).

The module does not import `serial` at module level: the import happens
inside `open()` and `find_adapter_ports()`, so dry-run and replay do not
load pyserial. The port is
created with `do_not_open=True`, and the DTR and RTS lines are set to `False`
before `open()` so that opening does not send a pulse that resets the
adapter. A local device (path without a URL scheme) is opened with
`exclusive=True` (`flock` lock on POSIX), so a second process does not share
the port.

`find_adapter_ports()` lists connected USB serial ports with an FTDI chip
(the USB-serial chip of OBDLink adapters) for `--execute` without
`--transport`. It only enumerates devices through the operating system and
never opens a port.

Error messages use fixed descriptions from `os_error_text` instead of the
system text; the original `errno` goes to the `TransportError.os_errno`
attribute and to the session log.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any, Final

from obd_bridge.errors import TransportError, TransportTimeout, os_errno, os_error_text

__all__ = ["BAUDRATE", "FTDI_VENDOR_ID", "READ_POLL_S", "SerialTransport", "find_adapter_ports", "is_local_device"]

BAUDRATE: int = 38400
"""UART baud rate of the STN2120 adapter (8N1, no flow control)."""

READ_POLL_S: float = 0.05
"""Timeout of a single pyserial read in seconds (one `read_until` loop step)."""


FTDI_VENDOR_ID: Final[int] = 0x0403
"""USB vendor ID of FTDI, the USB-serial chip used by OBDLink STN2120 adapters."""


def find_adapter_ports() -> list[str]:
    """Sorted device paths of connected USB serial ports with an FTDI chip.

    Enumeration only: no port is opened and nothing is sent. An enumeration
    failure gives `TransportError`.
    """
    from serial.tools import list_ports  # import only here: plan, dry-run and replay do not load pyserial

    try:
        ports = list_ports.comports()
    except OSError as exc:
        raise _error("Cannot list serial ports", exc) from exc
    return sorted(port.device for port in ports if port.vid == FTDI_VENDOR_ID)


def is_local_device(url: str) -> bool:
    """Whether `url` is a local device path (without a pyserial `<name>://` scheme)."""
    return "://" not in url


def _error(message: str, exc: BaseException) -> TransportError:
    """`TransportError` with a fixed description of the cause and the original `errno`."""
    return TransportError(f"{message}: {os_error_text(exc)}", os_errno=os_errno(exc))


class SerialTransport:
    """Transport over a pyserial serial port.

    Parameters:
        url: device path or pyserial URL (e.g. `/dev/cu.usbserial-X`).
        clock: monotonic clock in seconds (replaced in tests).
    """

    can_set_baudrate: bool = True

    def __init__(self, url: str, *, clock: Callable[[], float] = time.monotonic) -> None:
        self.url = url
        self._clock = clock
        self._port: Any = None
        self._pending = bytearray()
        self._serial_errors: tuple[type[BaseException], ...] = (OSError,)

    @property
    def is_open(self) -> bool:
        """Whether the port is open."""
        return self._port is not None

    def open(self) -> None:
        """Opens the port at 38400 8N1 without a DTR/RTS pulse; a pyserial error gives `TransportError`.

        A local device gets `exclusive=True`; a pyserial URL (e.g.
        `socket://`) is opened without this parameter.
        """
        if self._port is not None:
            return
        import serial  # import only here: dry-run and replay do not load pyserial

        self._serial_errors = (serial.SerialException, OSError, ValueError)
        options: dict[str, Any] = {
            "baudrate": BAUDRATE,
            "bytesize": 8,
            "parity": "N",
            "stopbits": 1,
            "rtscts": False,
            "dsrdtr": False,
            "timeout": READ_POLL_S,
            "do_not_open": True,
        }
        if is_local_device(self.url):
            options["exclusive"] = True
        port: Any = None
        try:
            port = serial.serial_for_url(self.url, **options)
            port.dtr = False
            port.rts = False
            port.open()
        except self._serial_errors as exc:
            if port is not None:
                try:
                    port.close()
                except self._serial_errors:
                    pass
            raise _error(f"Cannot open port {self.url}", exc) from exc
        self._port = port
        self._pending.clear()

    def close(self) -> None:
        """Closes the port; calling it on a closed port has no effect."""
        port, self._port = self._port, None
        self._pending.clear()
        if port is None:
            return
        try:
            port.close()
        except self._serial_errors as exc:
            raise _error(f"Error closing port {self.url}", exc) from exc

    def write(self, data: bytes) -> None:
        """Writes bytes and flushes the port output buffer."""
        port = self._require_open()
        try:
            port.write(bytes(data))
            port.flush()
        except self._serial_errors as exc:
            raise _error(f"Error writing to port {self.url}", exc) from exc

    def read_until(self, marker: bytes, timeout_s: float) -> bytes:
        """Reads up to and including the marker within `timeout_s`, measured by the monotonic clock.

        Bytes received after the marker stay in the buffer for the next read.
        When the time elapses it raises `TransportTimeout(partial=<received bytes>)`.
        """
        port = self._require_open()
        deadline = self._clock() + timeout_s
        buffer = self._pending
        while True:
            index = buffer.find(marker)
            if index >= 0:
                end = index + len(marker)
                result = bytes(buffer[:end])
                del buffer[:end]
                return result
            if self._clock() >= deadline:
                partial = bytes(buffer)
                buffer.clear()
                raise TransportTimeout(partial=partial)
            try:
                chunk = port.read(max(1, port.in_waiting))
            except self._serial_errors as exc:
                raise _error(f"Error reading from port {self.url}", exc) from exc
            if chunk:
                buffer += chunk

    def reset_input(self) -> None:
        """Clears the port input buffer and the internal buffer."""
        port = self._require_open()
        self._pending.clear()
        try:
            port.reset_input_buffer()
        except self._serial_errors as exc:
            raise _error(f"Error clearing the buffer of port {self.url}", exc) from exc

    def pending_input(self) -> int:
        """Bytes in the internal buffer (after the last `>`) plus the port `in_waiting`."""
        port = self._require_open()
        try:
            waiting = int(port.in_waiting)
        except self._serial_errors as exc:
            raise _error(f"Error reading the buffer state of port {self.url}", exc) from exc
        return len(self._pending) + waiting

    def set_baudrate(self, baud: int) -> None:
        """Sets `port.baudrate`; no code in this iteration calls it."""
        port = self._require_open()
        try:
            port.baudrate = baud
        except self._serial_errors as exc:
            raise _error(f"Cannot set baud rate {baud} on port {self.url}", exc) from exc

    def _require_open(self) -> Any:
        if self._port is None:
            raise TransportError(f"Port {self.url} is not open")
        return self._port
