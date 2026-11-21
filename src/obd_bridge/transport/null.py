"""Synthetic transport `NullTransport` for dry-run (spec T3, FR-04).

The module does not import pyserial, not even indirectly. `write` records the
line and prepares a deterministic reply from the table; `read_until` returns
it immediately. NullTransport does not judge lines: the guard runs before the
write.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Final

from obd_bridge.errors import TransportError, TransportTimeout

__all__ = ["NULL_RESPONSES", "NullTransport"]

NULL_RESPONSES: Final = MappingProxyType(
    {
        "ATWS": "\rELM327 v1.3a",
        "ATI": "ELM327 v1.3a",
        "AT@1": "SCANTOOL.NET LLC",
        "STI": "STN2120 v4.5.0",
        "STDI": "STN2120 r1.0",
        "ATRV": "12.6V",
        "STVR": "12.60",
        "ATPPS": "03:19 F  0C:68 N  21:FF F  24:00 F\r25:00 F  26:00 F  2A:04 F",
        "ATDPN": "A6",
        "ATDP": "AUTO, ISO 15765-4 (CAN 11/500)",
        # STN numbers protocols with its own numbering; the value does not affect logic (spec m7).
        "STPR": "33",
        "STPRS": "ISO 15765-4 (CAN 11/500)",
        "STPBRR": "500000",
        "ATCS": "T:00 R:00",
    }
)
"""Synthetic replies without echo and terminator (spec T3); other lines give `OK`."""

_TERMINATOR = b"\r\r>"
_STPX_PREFIX = "STPX"
_DEFAULT_REPLY = "OK"
_STPX_REPLY = "NO DATA"


class NullTransport:
    """Hardware-free transport with replies from `NULL_RESPONSES`.

    Echo is initially on; `ATE0` turns it off, `ATE1` and `ATWS` turn it on.
    Whether a line is echoed depends on the state before it is received (as in
    ELM327), so `ATE0` is still echoed. Every reply ends with `\\r\\r>`. A read
    with no pending reply (including the banner window before the first write)
    raises `TransportTimeout(partial=b"")`.

    Attributes:
        lines: written lines without `\\r`, in write order.
    """

    url: str = "null://"
    can_set_baudrate: bool = False

    def __init__(self) -> None:
        self.lines: list[str] = []
        self.opened = False
        self.closed = False
        self._echo = True
        self._pending = bytearray()

    @property
    def echo(self) -> bool:
        """Current echo state of the synthetic adapter."""
        return self._echo

    def open(self) -> None:
        """Marks the transport as open."""
        self.opened = True
        self.closed = False

    def close(self) -> None:
        """Marks the transport as closed and discards the pending reply."""
        self.closed = True
        self._pending.clear()

    def write(self, data: bytes) -> None:
        """Records every line terminated by `\\r` and prepares a reply."""
        try:
            text = bytes(data).decode("ascii")
        except UnicodeDecodeError as exc:
            raise TransportError(f"NullTransport accepts ASCII only: {bytes(data)!r}") from exc
        for line in text.split("\r"):
            if line:
                self._respond(line)

    def read_until(self, marker: bytes, timeout_s: float) -> bytes:
        """Returns the pending reply or raises `TransportTimeout(partial=b"")`."""
        if not self._pending:
            raise TransportTimeout(partial=b"")
        result = bytes(self._pending)
        self._pending.clear()
        return result

    def reset_input(self) -> None:
        """Discards the pending reply."""
        self._pending.clear()

    def pending_input(self) -> int:
        """Number of bytes of the prepared reply not yet read."""
        return len(self._pending)

    def set_baudrate(self, baud: int) -> None:
        """Changing the baud rate is not supported."""
        raise TransportError(f"Transport {self.url} does not support changing the baud rate to {baud}")

    def _respond(self, line: str) -> None:
        self.lines.append(line)
        command = line.strip().upper()
        reply = self._reply_for(command)
        if self._echo:
            self._pending += line.encode("ascii") + b"\r"
        self._pending += reply.encode("ascii") + _TERMINATOR
        if command == "ATE0":
            self._echo = False
        elif command in ("ATE1", "ATWS"):
            self._echo = True

    @staticmethod
    def _reply_for(command: str) -> str:
        if command == _STPX_PREFIX or command.startswith(_STPX_PREFIX + " "):
            return _STPX_REPLY
        return NULL_RESPONSES.get(command, _DEFAULT_REPLY)
