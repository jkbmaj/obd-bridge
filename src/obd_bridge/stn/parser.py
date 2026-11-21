"""Reply parser for the STN2120 adapter (`LineParser`, spec T4, FR-11).

Two pure functions:

- `parse_adapter_reply(raw, sent)` for adapter commands (`AT*`, `ST*`),
- `parse_uds_exchange(raw, sent, rx_id)` for `STPX` with `ATH1` and `ATS0`.

Frame format with `ATH1`: 3 hex digits of the sender CAN ID, the PCI byte and
data (1 to 8 bytes in total). The message length always comes from the PCI,
so padding of the last frame is cut off whether or not the adapter prints it.
Frames with a CAN ID other than `rx_id` go to `foreign_frames` and are not
assembled.

The parser raises no exception for any input: every unrecognised fragment
goes to `unparsed_lines`, and the `outcome` field describes the result.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

__all__ = [
    "ADAPTER_ERROR_TOKENS",
    "AdapterReply",
    "CanFrame",
    "ExchangeOutcome",
    "ReplyOutcome",
    "UdsExchange",
    "error_token_of",
    "parse_adapter_reply",
    "parse_uds_exchange",
    "split_lines",
]

ADAPTER_ERROR_TOKENS: tuple[str, ...] = (
    "NO DATA",
    "CAN ERROR",
    "BUS ERROR",
    "BUS BUSY",
    "FC RX TIMEOUT",
    "BUFFER FULL",
    "OUT OF MEMORY",
    "<RX ERROR",
    "DATA ERROR",
    "?",
    "STOPPED",
)
"""Adapter error tokens; whole-line comparison, `<RX ERROR` as a prefix."""

_RX_ERROR_PREFIX = "<RX ERROR"
_NO_DATA = "NO DATA"
_FRAME_RE = re.compile(r"[0-9A-F]{3}(?:[0-9A-F]{2}){1,8}")
_NEGATIVE_SID = 0x7F
_RESPONSE_PENDING = 0x78


class ReplyOutcome(StrEnum):
    """Outcome of a reply to an adapter command."""

    OK = "ok"
    UNSUPPORTED = "unsupported"
    ERROR = "error"
    VALUE = "value"


class ExchangeOutcome(StrEnum):
    """Outcome of a UDS exchange through `STPX`."""

    POSITIVE = "positive"
    NEGATIVE = "negative"
    PENDING_UNRESOLVED = "pending_unresolved"
    NO_DATA = "no_data"
    ADAPTER_ERROR = "adapter_error"
    INCOMPLETE = "incomplete"
    UNPARSED = "unparsed"


@dataclass(frozen=True)
class CanFrame:
    """CAN frame from an adapter line: sender identifier and data bytes (including PCI)."""

    can_id: int
    data: bytes
    line: str


@dataclass(frozen=True)
class AdapterReply:
    """Parsed reply to an adapter command.

    Attributes:
        lines: non-empty reply lines without the echo.
        echo: whether the first line was an echo of the sent command.
        outcome: `ok`, `unsupported`, `error` or `value`.
        error_token: first recognised adapter error token or `None`.
    """

    lines: tuple[str, ...]
    echo: bool
    outcome: ReplyOutcome
    error_token: str | None

    @property
    def text(self) -> str:
        """Reply lines joined with a newline character (e.g. `ELM327 v1.3a`)."""
        return "\n".join(self.lines)


@dataclass(frozen=True)
class UdsExchange:
    """Parsed UDS exchange (`STPX`) with one ECU.

    Attributes:
        line: the sent `STPX` line.
        raw: raw adapter reply bytes.
        lines: non-empty reply lines without the echo.
        echo: whether the first line was an echo of the sent line.
        frames: frames with a CAN ID equal to `rx_id`, in receive order.
        foreign_frames: frames with another CAN ID, skipped during assembly.
        unparsed_lines: lines that are neither a frame nor an error token.
        messages: assembled UDS messages (including `7F xx 78`).
        pending_count: number of `7F xx 78` messages.
        outcome: outcome according to the T4 rules.
        final: final message (the first one other than `7F xx 78`) or `None`.
        nrc: NRC code of a negative response or `None`.
        error_token: first recognised adapter error token or `None`.
        elapsed_ms: time from write to `>` measured by the driver, or `None`.
    """

    line: str
    raw: bytes
    lines: tuple[str, ...]
    echo: bool
    frames: tuple[CanFrame, ...]
    foreign_frames: tuple[CanFrame, ...]
    unparsed_lines: tuple[str, ...]
    messages: tuple[bytes, ...]
    pending_count: int
    outcome: ExchangeOutcome
    final: bytes | None
    nrc: int | None
    error_token: str | None
    elapsed_ms: float | None = None


def split_lines(raw: bytes, sent: str) -> tuple[tuple[str, ...], bool]:
    """Decodes the reply and returns `(lines, echo)`.

    ASCII decoding with `errors="replace"`, removal of the trailing `>`, split
    on `\\r` and `\\n`, `strip()` and removal of empty lines. A first line
    equal to `sent` is removed as the echo.
    """
    text = bytes(raw).decode("ascii", errors="replace")
    text = text.rstrip()
    if text.endswith(">"):
        text = text[:-1]
    lines = [part.strip() for part in re.split(r"[\r\n]", text)]
    lines = [line for line in lines if line]
    echo = bool(lines) and lines[0] == sent
    if echo:
        lines = lines[1:]
    return tuple(lines), echo


def error_token_of(line: str) -> str | None:
    """Returns the adapter error token for a line or `None`."""
    if line.startswith(_RX_ERROR_PREFIX):
        return _RX_ERROR_PREFIX
    if line in ADAPTER_ERROR_TOKENS:
        return line
    return None


def parse_adapter_reply(raw: bytes, sent: str) -> AdapterReply:
    """Parses the reply to an adapter command (`AT*`, `ST*`).

    `ok`: the only line is `OK`; `unsupported`: the only line is `?`;
    `error`: any line is an error token; `value`: all other cases (including
    an empty reply).
    """
    lines, echo = split_lines(raw, sent)
    token = next((t for t in map(error_token_of, lines) if t is not None), None)
    if lines == ("OK",):
        outcome = ReplyOutcome.OK
    elif lines == ("?",):
        outcome = ReplyOutcome.UNSUPPORTED
    elif token is not None:
        outcome = ReplyOutcome.ERROR
    else:
        outcome = ReplyOutcome.VALUE
    return AdapterReply(lines=lines, echo=echo, outcome=outcome, error_token=token)


def _parse_frame(line: str) -> CanFrame | None:
    compact = line.replace(" ", "")
    if not _FRAME_RE.fullmatch(compact):
        return None
    return CanFrame(can_id=int(compact[:3], 16), data=bytes.fromhex(compact[3:]), line=line)


class _Assembler:
    """Assembly of ISO-TP messages from SF, FF and CF frames of one sender."""

    def __init__(self) -> None:
        self.messages: list[bytes] = []
        self.unparsed: list[str] = []
        self.incomplete = False
        self._buffer: bytearray | None = None
        self._expected = 0
        self._next_seq = 0

    def _abandon(self) -> None:
        if self._buffer is not None:
            self.incomplete = True
        self._buffer = None

    def _complete_if_ready(self) -> None:
        if self._buffer is not None and len(self._buffer) >= self._expected:
            self.messages.append(bytes(self._buffer[: self._expected]))
            self._buffer = None

    def feed(self, frame: CanFrame) -> None:
        data = frame.data
        pci = data[0] >> 4
        if pci == 0x0:
            length = data[0] & 0x0F
            if length == 0 or length > len(data) - 1:
                self.unparsed.append(frame.line)
                return
            self._abandon()
            self.messages.append(data[1 : 1 + length])
        elif pci == 0x1:
            if len(data) < 2:
                self.unparsed.append(frame.line)
                return
            length = ((data[0] & 0x0F) << 8) | data[1]
            if length == 0:
                self.unparsed.append(frame.line)
                return
            self._abandon()
            self._buffer = bytearray(data[2:])
            self._expected = length
            self._next_seq = 1
            self._complete_if_ready()
        elif pci == 0x2:
            if self._buffer is None:
                self.incomplete = True
                return
            if data[0] & 0x0F != self._next_seq:
                self._abandon()
                return
            self._buffer += data[1:]
            self._next_seq = (self._next_seq + 1) % 16
            self._complete_if_ready()
        else:
            self.unparsed.append(frame.line)

    def finish(self) -> None:
        self._abandon()


def _is_pending(message: bytes) -> bool:
    return len(message) == 3 and message[0] == _NEGATIVE_SID and message[2] == _RESPONSE_PENDING


def parse_uds_exchange(
    raw: bytes, sent: str, rx_id: int, *, elapsed_ms: float | None = None
) -> UdsExchange:
    """Parses the adapter reply to an `STPX` line for receiver `rx_id`.

    `outcome` rules (first match wins): a final message gives `positive` or
    `negative`; only `7F xx 78` messages give `pending_unresolved`; the
    `NO DATA` token gives `no_data`; any other token gives `adapter_error`;
    an incomplete message gives `incomplete`; all other cases give `unparsed`.
    """
    lines, echo = split_lines(raw, sent)
    frames: list[CanFrame] = []
    foreign: list[CanFrame] = []
    unparsed: list[str] = []
    tokens: list[str] = []
    assembler = _Assembler()

    for line in lines:
        token = error_token_of(line)
        if token is not None:
            tokens.append(token)
            continue
        frame = _parse_frame(line)
        if frame is None:
            unparsed.append(line)
        elif frame.can_id != rx_id:
            foreign.append(frame)
        else:
            frames.append(frame)
            assembler.feed(frame)
    assembler.finish()
    unparsed.extend(assembler.unparsed)

    messages = tuple(assembler.messages)
    pending_count = sum(1 for message in messages if _is_pending(message))
    final = next((message for message in messages if not _is_pending(message)), None)
    error_token = tokens[0] if tokens else None
    nrc: int | None = None

    if final is not None:
        if final[0] == _NEGATIVE_SID:
            outcome = ExchangeOutcome.NEGATIVE
            nrc = final[2] if len(final) >= 3 else None
        else:
            outcome = ExchangeOutcome.POSITIVE
    elif pending_count:
        outcome = ExchangeOutcome.PENDING_UNRESOLVED
    elif _NO_DATA in tokens:
        outcome = ExchangeOutcome.NO_DATA
    elif tokens:
        outcome = ExchangeOutcome.ADAPTER_ERROR
    elif assembler.incomplete:
        outcome = ExchangeOutcome.INCOMPLETE
    else:
        outcome = ExchangeOutcome.UNPARSED

    return UdsExchange(
        line=sent,
        raw=bytes(raw),
        lines=lines,
        echo=echo,
        frames=tuple(frames),
        foreign_frames=tuple(foreign),
        unparsed_lines=tuple(unparsed),
        messages=messages,
        pending_count=pending_count,
        outcome=outcome,
        final=final,
        nrc=nrc,
        error_token=error_token,
        elapsed_ms=elapsed_ms,
    )
