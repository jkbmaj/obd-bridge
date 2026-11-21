"""Replaying transport `ReplayTransport` (spec T3, FR-05).

Replays `tx` and `rx` events of the `transport` layer from a JSONL log or from
a list of events. Every write must match the next `tx` event byte for byte,
every read the next `rx` event; a mismatch gives `ReplayMismatch` (code 5).
The module does not import pyserial.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from obd_bridge.errors import ReplayMismatch, TransportError, TransportTimeout
from obd_bridge.traffic_log import EventKind, Layer, read_events, unescape

__all__ = ["ReplayMismatch", "ReplayTransport"]

_REPLAYED_KINDS = frozenset({str(EventKind.TX), str(EventKind.RX)})


class ReplayTransport:
    """Transport that replays `transport` layer traffic from a recorded session.

    Parameters:
        source: path of a JSONL file (read by `read_events` with format
            checks) or a sequence of events as dictionaries.

    `open`, `close` and `reset_input` have no effect. `rx` events before the
    first `tx` (banner) serve the first `read_until` calls.
    """

    can_set_baudrate: bool = False

    def __init__(self, source: Path | str | Iterable[Mapping[str, Any]]) -> None:
        if isinstance(source, (str, Path)):
            self.url = f"replay://{source}"
            events: Iterable[Mapping[str, Any]] = read_events(source)
        else:
            self.url = "replay://events"
            events = source
        indexed = [
            (index, event)
            for index, event in enumerate(events)
            if event.get("layer") == str(Layer.TRANSPORT) and event.get("ev") in _REPLAYED_KINDS
        ]
        indexed.sort(key=lambda item: (_seq_key(item[1], item[0]), item[0]))
        self._events: list[Mapping[str, Any]] = [event for _, event in indexed]
        self._position = 0

    @property
    def remaining(self) -> int:
        """Number of unconsumed `tx` and `rx` events."""
        return len(self._events) - self._position

    def open(self) -> None:
        """No effect."""

    def close(self) -> None:
        """No effect."""

    def reset_input(self) -> None:
        """No effect."""

    def pending_input(self) -> int:
        """Byte count of the next `rx` event with `meta.stale: true` (at least 1), otherwise 0.

        Unread bytes logged before a write are replayed as in the session:
        the driver detects them and consumes them through `read_until`.
        """
        if self._position >= len(self._events):
            return 0
        event = self._events[self._position]
        meta = event.get("meta") or {}
        if event.get("ev") != str(EventKind.RX) or not isinstance(meta, Mapping) or meta.get("stale") is not True:
            return 0
        return max(1, len(unescape(str(event.get("data", "")))))

    def set_baudrate(self, baud: int) -> None:
        """Changing the baud rate is not supported."""
        raise TransportError(f"Transport {self.url} does not support changing the baud rate to {baud}")

    def write(self, data: bytes) -> None:
        """Consumes the next event, which must be a `tx` with identical bytes."""
        actual = bytes(data)
        event = self._peek(actual)
        seq = event.get("seq")
        if event.get("ev") != str(EventKind.TX):
            raise ReplayMismatch(seq, _describe(event), actual)
        expected = unescape(str(event.get("data", "")))
        if expected != actual:
            raise ReplayMismatch(seq, expected, actual)
        self._position += 1

    def read_until(self, marker: bytes, timeout_s: float) -> bytes:
        """Consumes the next `rx` event and returns its bytes.

        An event with `meta.timeout: true` gives `TransportTimeout(partial=<bytes>)`.
        A next `tx` event or the end of events gives `ReplayMismatch`.
        """
        operation = f"read_until({marker!r})"
        event = self._peek(operation)
        if event.get("ev") != str(EventKind.RX):
            raise ReplayMismatch(event.get("seq"), _describe(event), operation)
        data = unescape(str(event.get("data", "")))
        self._position += 1
        meta = event.get("meta") or {}
        if isinstance(meta, Mapping) and meta.get("timeout") is True:
            raise TransportTimeout(partial=data)
        return data

    def _peek(self, actual: bytes | str) -> Mapping[str, Any]:
        if self._position >= len(self._events):
            raise ReplayMismatch(None, None, actual)
        return self._events[self._position]


def _seq_key(event: Mapping[str, Any], index: int) -> int:
    seq = event.get("seq")
    return seq if isinstance(seq, int) and not isinstance(seq, bool) else index


def _describe(event: Mapping[str, Any]) -> str:
    return f"{event.get('ev')} {event.get('data', '')!r}"
