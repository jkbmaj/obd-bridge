"""L0 byte transport protocol (spec T3).

The module does not import pyserial. It re-exports `TransportError` and
`TransportTimeout` from `obd_bridge.errors` so that higher layers import
transport exceptions from one place.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from obd_bridge.errors import TransportError, TransportTimeout

__all__ = ["ByteTransport", "TransportError", "TransportTimeout"]


@runtime_checkable
class ByteTransport(Protocol):
    """Byte medium between the host and the adapter.

    Attributes:
        url: medium identifier, e.g. `/dev/cu.usbserial-X`, `null://`.
        can_set_baudrate: whether `set_baudrate` is supported.

    `read_until` returns data including the marker; after `timeout_s`
    elapses it raises `TransportTimeout` with the `partial` attribute. I/O
    errors are `TransportError` (code 3).
    """

    url: str
    can_set_baudrate: bool

    def open(self) -> None:
        """Opens the medium."""
        ...

    def close(self) -> None:
        """Closes the medium; calling it on a closed medium has no effect."""
        ...

    def write(self, data: bytes) -> None:
        """Writes bytes; called only from `StnDriver._egress`."""
        ...

    def read_until(self, marker: bytes, timeout_s: float) -> bytes:
        """Reads up to and including the marker, or raises `TransportTimeout`."""
        ...

    def reset_input(self) -> None:
        """Clears the input buffer."""
        ...

    def pending_input(self) -> int:
        """Number of received bytes not yet read (internal and system buffer).

        The driver checks it right before every write: a value greater than 0
        means a reply desync or an adapter reset.
        """
        ...

    def set_baudrate(self, baud: int) -> None:
        """Changes the medium baud rate; unused in this iteration."""
        ...
