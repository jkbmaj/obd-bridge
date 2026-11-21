"""obd-bridge exception hierarchy (spec T12).

Every class has a class attribute `exit_code`, from which the CLI derives the exit code.
Layer modules re-export the classes they need; NRC and catalog error subclasses
are defined in the modules `uds/client.py` and `vag/catalog.py`.
"""

from __future__ import annotations

import errno as _errno
from typing import ClassVar, Final

__all__ = [
    "AdapterError",
    "AdapterResponseError",
    "CatalogError",
    "LogFormatError",
    "ObdBridgeError",
    "ReadOnlyViolation",
    "ReplayMismatch",
    "ReportInputError",
    "TransportError",
    "TransportTimeout",
    "UdsError",
    "os_errno",
    "os_error_text",
]

_ERRNO_TEXTS: Final[dict[int, str]] = {
    _errno.ENOENT: "file does not exist",
    _errno.EACCES: "permission denied",
    _errno.EPERM: "permission denied",
    _errno.EBUSY: "port in use by another program",
    _errno.EAGAIN: "port in use by another program",
    _errno.EWOULDBLOCK: "port in use by another program",
    _errno.EISDIR: "path points to a directory",
    _errno.ENOTDIR: "a path component is not a directory",
    _errno.ENXIO: "device unavailable or disconnected",
    _errno.ENODEV: "device unavailable or disconnected",
    _errno.EIO: "device input/output error",
    _errno.ENOSPC: "no space left on disk",
    _errno.ECONNREFUSED: "connection refused",
    _errno.ECONNRESET: "connection broken",
    _errno.EPIPE: "connection broken",
    _errno.ETIMEDOUT: "operation timed out",
}
"""Fixed descriptions of system errors by `errno` (instead of the platform `strerror`)."""


def os_errno(exc: BaseException) -> int | None:
    """First `errno` in the exception chain (`exc`, `__cause__`, `__context__`), or None."""
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        number = getattr(current, "errno", None)
        if isinstance(number, int) and not isinstance(number, bool):
            return number
        current = current.__cause__ or current.__context__
    return None


def os_error_text(exc: BaseException) -> str:
    """Description of a system error by exception type and `errno`; without the OS text.

    Order: `errno` from the exception chain (table of fixed descriptions), then
    the type (`FileNotFoundError`, `PermissionError`, `IsADirectoryError`,
    `TimeoutError`, `ValueError`), finally a generic description with the `errno` number.
    """
    number = os_errno(exc)
    if number is not None and number in _ERRNO_TEXTS:
        return _ERRNO_TEXTS[number]
    if isinstance(exc, FileNotFoundError):
        return "file does not exist"
    if isinstance(exc, PermissionError):
        return "permission denied"
    if isinstance(exc, IsADirectoryError):
        return "path points to a directory"
    if isinstance(exc, TimeoutError):
        return "operation timed out"
    if isinstance(exc, ValueError):
        return "invalid port parameters"
    if number is not None:
        return f"system error (errno {number})"
    return "system error without a code (device disconnected or port used by another program)"


class ObdBridgeError(Exception):
    """Base obd-bridge error; exit code 3 by default."""

    exit_code: ClassVar[int] = 3


class ReadOnlyViolation(ObdBridgeError):
    """Rejection by the read-only policy; nothing reaches the transport.

    Attributes:
        layer: decision layer (`uds` or `adapter`).
        rule: rule identifier, e.g. `UDS/sid` or `LINE/allowlist`.
        reason: description of the cause.
        subject: rejected adapter line or UDS payload in hex.
    """

    exit_code: ClassVar[int] = 2

    def __init__(self, layer: str, rule: str, reason: str, subject: str) -> None:
        self.layer = layer
        self.rule = rule
        self.reason = reason
        self.subject = subject
        super().__init__(
            f"Read-only policy violation (layer {layer}, rule {rule}): {reason}; subject: {subject}"
        )


class TransportError(ObdBridgeError):
    """Transport layer (L0) error: port, write or read.

    Attributes:
        os_errno: original `errno` of the system error, or None (goes to
            `meta.errno` of the `error` event in the session log).
    """

    def __init__(self, message: str = "", *, os_errno: int | None = None) -> None:
        self.os_errno = os_errno
        super().__init__(message)


class TransportTimeout(TransportError):
    """Read timeout; `partial` holds the bytes received before the timeout."""

    def __init__(self, partial: bytes = b"", message: str | None = None) -> None:
        self.partial = partial
        super().__init__(
            message or f"Timed out waiting for a reply (received {len(partial)} B)"
        )


class AdapterError(ObdBridgeError):
    """Adapter driver (L1) error, e.g. a disallowed state transition."""


class AdapterResponseError(AdapterError):
    """Adapter reply not usable by the caller.

    The `exchange` attribute holds the parsed exchange (`UdsExchange` from `stn/parser.py`).
    """

    def __init__(self, exchange: object, message: str | None = None) -> None:
        self.exchange = exchange
        super().__init__(message or f"Unexpected adapter reply: {exchange!r}")


class ReplayMismatch(ObdBridgeError):
    """Replayed traffic does not match the JSONL recording; code 5.

    Attributes:
        seq: event number in the log, or None when events ran out.
        expected: expected bytes or a description of the event from the log.
        actual: actual bytes or a description of the caller's operation.
    """

    exit_code: ClassVar[int] = 5

    def __init__(
        self,
        seq: int | None,
        expected: bytes | str | None,
        actual: bytes | str | None,
    ) -> None:
        self.seq = seq
        self.expected = expected
        self.actual = actual
        where = "end of events" if seq is None else f"event seq={seq}"
        super().__init__(
            f"Replay mismatch ({where}): expected {expected!r}, got {actual!r}"
        )


class CatalogError(ObdBridgeError):
    """ECU catalog error (missing file, validation, unknown module); code 64."""

    exit_code: ClassVar[int] = 64


class LogFormatError(ObdBridgeError):
    """Invalid JSONL session log format; code 64."""

    exit_code: ClassVar[int] = 64


class ReportInputError(ObdBridgeError):
    """Invalid input of `obdb report` (probe file or reference file); code 64."""

    exit_code: ClassVar[int] = 64


class UdsError(ObdBridgeError):
    """Base UDS layer error (NRC, no reply, unresolved 0x78); code 3."""
