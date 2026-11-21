"""Session traffic log in JSONL format (spec T6, FR-20).

Every event is one JSON line written to disk immediately (`flush()` after
every line), so the log survives an interrupted session. The file is created
in mode `x`, so an existing log is never overwritten. The module also provides
escaping of `transport` layer bytes and the `read_events` reader used by the
audit and by `ReplayTransport`.
"""

from __future__ import annotations

import json
import re
import subprocess
import time
from collections.abc import Callable, Mapping
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from types import TracebackType
from typing import IO, Any, Self

from obd_bridge.errors import LogFormatError

__all__ = [
    "EventKind",
    "Layer",
    "SCHEMA_VERSION",
    "SessionCommand",
    "TrafficLog",
    "detect_commit",
    "escape",
    "make_session_id",
    "read_events",
    "unescape",
]

SCHEMA_VERSION: int = 1
"""Event schema version (field `v`)."""

GIT_TIMEOUT_S: float = 2.0
"""Timeout of the `git rev-parse HEAD` call in seconds."""

_MAX_COLLISIONS = 1000
_COMMAND_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
_HEX_DIGITS = frozenset("0123456789ABCDEFabcdef")


class SessionCommand(StrEnum):
    """Commands for which a session log is created (part of `session_id`)."""

    PROBE = "probe"
    PROBE_DRY_RUN = "probe-dry-run"


class EventKind(StrEnum):
    """Event kinds (field `ev`)."""

    SESSION_START = "session_start"
    SESSION_END = "session_end"
    TX = "tx"
    RX = "rx"
    UDS = "uds"
    GUARD = "guard"
    STATE = "state"
    MARKER = "marker"
    ERROR = "error"


class Layer(StrEnum):
    """Event layers (field `layer`)."""

    TRANSPORT = "transport"
    ADAPTER = "adapter"
    UDS = "uds"
    APP = "app"


# ---------------------------------------------------------------------------
# Escaping of transport layer bytes


def escape(data: bytes) -> str:
    """Converts bytes to ASCII text reversible by `unescape`.

    Bytes 0x20..0x7E other than `\\` stay unchanged; `\\` becomes `\\\\`, 0x0D
    `\\r`, 0x0A `\\n`, the rest `\\xHH` (upper case).
    """
    parts: list[str] = []
    for byte in data:
        if byte == 0x5C:
            parts.append("\\\\")
        elif byte == 0x0D:
            parts.append("\\r")
        elif byte == 0x0A:
            parts.append("\\n")
        elif 0x20 <= byte <= 0x7E:
            parts.append(chr(byte))
        else:
            parts.append(f"\\x{byte:02X}")
    return "".join(parts)


def unescape(text: str) -> bytes:
    """Reverses `escape`; an invalid sequence raises `LogFormatError`."""
    out = bytearray()
    index = 0
    length = len(text)
    while index < length:
        char = text[index]
        if char != "\\":
            code = ord(char)
            if not 0x20 <= code <= 0x7E:
                raise LogFormatError(f"Disallowed character {char!r} in byte notation (position {index})")
            out.append(code)
            index += 1
            continue
        if index + 1 >= length:
            raise LogFormatError(f"Unterminated escape sequence at end of text (position {index})")
        marker = text[index + 1]
        if marker == "\\":
            out.append(0x5C)
            index += 2
        elif marker == "r":
            out.append(0x0D)
            index += 2
        elif marker == "n":
            out.append(0x0A)
            index += 2
        elif marker == "x":
            digits = text[index + 2 : index + 4]
            if len(digits) != 2 or not set(digits) <= _HEX_DIGITS:
                raise LogFormatError(f"Invalid \\x sequence in byte notation (position {index})")
            out.append(int(digits, 16))
            index += 4
        else:
            raise LogFormatError(f"Unknown escape sequence \\{marker} (position {index})")
    return bytes(out)


# ---------------------------------------------------------------------------
# Session identifier and commit


def _local_now() -> datetime:
    """Current local time with time zone."""
    return datetime.now().astimezone()


def make_session_id(command: str, moment: datetime) -> str:
    """Builds `session_id` in the form `YYYYMMDDTHHMMSS-<command>`.

    The command must consist of lower-case letters, digits and single hyphens,
    so that the identifier is a safe file name; otherwise `ValueError`.
    """
    if not _COMMAND_RE.fullmatch(command):
        raise ValueError(f"Invalid session command name: {command!r}")
    return f"{moment.strftime('%Y%m%dT%H%M%S')}-{command}"


def detect_commit(root: Path) -> str | None:
    """Returns the `git rev-parse HEAD` hash for directory `root`, or None.

    Missing git program, no repository, no commit, exceeding the 2 s limit or
    any other error yields None.
    """
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT_S,
            check=False,
        )
    except (OSError, subprocess.SubprocessError, ValueError):
        return None
    if result.returncode != 0:
        return None
    commit = (result.stdout or "").strip()
    return commit or None


def _guard_to_json(guard: Mapping[str, Any] | None) -> dict[str, Any] | None:
    """Converts a guard decision map to `{decision, rule, reason}`; another type raises `TypeError`.

    All emitting call sites pass a map with the `decision` field (`allowed` or
    `rejected`); a `GuardDecision` object has no such field, so it is not
    accepted in place of a map.
    """
    if guard is None:
        return None
    if not isinstance(guard, Mapping):
        raise TypeError(f"guard must be a mapping or None, got {type(guard).__name__}")
    return {key: guard.get(key) for key in ("decision", "rule", "reason")}


# ---------------------------------------------------------------------------
# TrafficLog


class TrafficLog:
    """Writes session events to the file `data/sessions/<YYYY-MM-DD>/<session_id>.jsonl`.

    Instances are created by `TrafficLog.create`. Every `emit` writes one line
    and calls `flush()`. The log counts `tx` lines of the `adapter` layer, `STPX`
    lines and guard rejections; the counters go to `meta` of the `session_end` event.
    """

    def __init__(
        self,
        handle: IO[str],
        path: Path,
        session_id: str,
        root: Path,
        clock: Callable[[], float],
        now: Callable[[], datetime],
    ) -> None:
        self._handle: IO[str] | None = handle
        self._path = path
        self._session_id = session_id
        self._root = root
        self._clock = clock
        self._now = now
        self._start = clock()
        self._seq = 0
        self._lines_tx = 0
        self._stpx_count = 0
        self._guard_rejections = 0

    @classmethod
    def create(
        cls,
        command: str,
        root: Path = Path("."),
        clock: Callable[[], float] = time.monotonic,
        now: Callable[[], datetime] = _local_now,
    ) -> Self:
        """Creates the directories and a new log file in mode `x`.

        Parameters:
            command: session command (`probe`, `probe-dry-run`).
            root: project directory under which `data/sessions/` is created.
            clock: monotonic clock for the `tm` field.
            now: source of local time with time zone for `session_id`, the date directory and the `tw` field.

        On a file name collision the session identifier gets the suffix `-2`,
        `-3` and so on; the `sid` field of events equals the file name without extension.
        """
        moment = now()
        base_id = make_session_id(str(command), moment)
        directory = Path(root) / "data" / "sessions" / moment.strftime("%Y-%m-%d")
        directory.mkdir(parents=True, exist_ok=True)
        for attempt in range(1, _MAX_COLLISIONS + 1):
            session_id = base_id if attempt == 1 else f"{base_id}-{attempt}"
            path = directory / f"{session_id}.jsonl"
            try:
                handle = path.open("x", encoding="utf-8", newline="\n")
            except FileExistsError:
                continue
            return cls(handle, path, session_id, Path(root), clock, now)
        raise LogFormatError(
            f"Cannot create session log {base_id}: exhausted {_MAX_COLLISIONS} name suffixes"
        )

    @property
    def path(self) -> Path:
        """Path of the JSONL file."""
        return self._path

    @property
    def session_id(self) -> str:
        """Session identifier (field `sid`)."""
        return self._session_id

    @property
    def closed(self) -> bool:
        """Whether the log file has been closed."""
        return self._handle is None

    @property
    def counters(self) -> dict[str, int]:
        """Current counters `lines_tx`, `stpx_count` and `guard_rejections`."""
        return {
            "lines_tx": self._lines_tx,
            "stpx_count": self._stpx_count,
            "guard_rejections": self._guard_rejections,
        }

    def emit(
        self,
        ev: str,
        layer: str,
        data: str = "",
        *,
        ecu: str | None = None,
        guard: Mapping[str, Any] | None = None,
        meta: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Writes one event and returns it as a dict.

        `ev` and `layer` must belong to `EventKind` and `Layer` (otherwise
        `ValueError`). `guard` is a mapping with the fields `decision`, `rule` and
        `reason`, or None (another type: `TypeError`). Writing after the log is closed raises `ValueError`.
        """
        if self._handle is None:
            raise ValueError(f"Session log {self._session_id} is closed")
        kind = EventKind(ev)
        layer_value = Layer(layer)
        event: dict[str, Any] = {
            "v": SCHEMA_VERSION,
            "sid": self._session_id,
            "seq": self._seq,
            "tm": round(self._clock() - self._start, 3),
            "tw": self._now().isoformat(timespec="milliseconds"),
            "ev": str(kind),
            "layer": str(layer_value),
            "ecu": ecu,
            "data": data,
            "guard": _guard_to_json(guard),
            "meta": dict(meta) if meta is not None else {},
        }
        line = json.dumps(event, ensure_ascii=False, separators=(",", ":"))
        self._handle.write(line + "\n")
        self._handle.flush()
        self._seq += 1
        self._count(kind, layer_value, data)
        return event

    def session_start(self, meta: Mapping[str, Any]) -> dict[str, Any]:
        """Writes `session_start` (`app`); a missing `commit` in `meta` is filled in by `detect_commit`."""
        payload = dict(meta)
        if "commit" not in payload:
            payload["commit"] = detect_commit(self._root)
        return self.emit(EventKind.SESSION_START, Layer.APP, meta=payload)

    def session_end(self, meta: Mapping[str, Any] | None = None) -> dict[str, Any]:
        """Writes `session_end` (`app`) with the counters and `duration_s`.

        Values from `meta` (e.g. `atcs`, `run_exit_code`) are added after the
        counters and may explicitly override them.
        """
        payload: dict[str, Any] = {
            **self.counters,
            "duration_s": round(self._clock() - self._start, 3),
        }
        if meta is not None:
            payload.update(meta)
        return self.emit(EventKind.SESSION_END, Layer.APP, meta=payload)

    def close(self) -> None:
        """Closes the file; further calls do nothing."""
        if self._handle is not None:
            self._handle.close()
            self._handle = None

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def _count(self, kind: EventKind, layer: Layer, data: str) -> None:
        """Updates the counters for `session_end`."""
        if kind is EventKind.TX and layer is Layer.ADAPTER:
            self._lines_tx += 1
            if data.lstrip().upper().startswith("STPX"):
                self._stpx_count += 1
        elif kind is EventKind.GUARD:
            self._guard_rejections += 1


# ---------------------------------------------------------------------------
# Reader


def read_events(path: Path | str) -> list[dict[str, Any]]:
    """Loads events from a JSONL file with format checks.

    Invalid JSON, a line that is not an object, a first event other than
    `session_start`, or a `seq` different from the previous one + 1 (the first
    equal to 0) raise `LogFormatError` (code 64) with the line number.
    """
    events: list[dict[str, Any]] = []
    with Path(path).open(encoding="utf-8") as handle:
        for line_no, raw in enumerate(handle, start=1):
            try:
                event = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise LogFormatError(f"{path}: line {line_no}: invalid JSON ({exc.msg})") from exc
            if not isinstance(event, dict):
                raise LogFormatError(f"{path}: line {line_no}: event is not a JSON object")
            if not events and event.get("ev") != EventKind.SESSION_START:
                raise LogFormatError(
                    f"{path}: line {line_no}: first event must be session_start, "
                    f"got {event.get('ev')!r}"
                )
            expected = len(events)
            seq = event.get("seq")
            if isinstance(seq, bool) or seq != expected:
                raise LogFormatError(
                    f"{path}: line {line_no}: expected seq={expected}, got {seq!r}"
                )
            events.append(event)
    if not events:
        raise LogFormatError(f"{path}: line 1: no session_start event (empty file)")
    return events
