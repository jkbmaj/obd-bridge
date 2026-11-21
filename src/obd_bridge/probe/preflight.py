"""Preflight for the live probe `obdb probe --execute` (spec T9 "Preflight", audit M3).

The checklist goes to stderr before the port is opened and before the JSONL
log is created. The operator's answer is read by our own code from `stdin`
(no `typer.confirm` or `click.prompt`), so `EOFError` and `KeyboardInterrupt`
are caught here and do not reach click as `Abort`.

Every refusal ends with a `PreflightAborted` exception (code 1); the caller
then creates no files and does not open the transport.
"""

from __future__ import annotations

import sys
from enum import StrEnum
from typing import ClassVar, Final, Protocol

from obd_bridge.errors import ObdBridgeError

__all__ = [
    "ACCEPTED_ANSWERS",
    "MESSAGE_ABORTED",
    "MESSAGE_NO_TTY",
    "MESSAGE_YES_FLAG",
    "PROMPT",
    "PreflightAborted",
    "PreflightMode",
    "checklist_text",
    "confirm",
]

ACCEPTED_ANSWERS: Final[frozenset[str]] = frozenset({"y", "yes"})
"""Confirming answers (case-insensitive comparison)."""

PROMPT: Final[str] = "Are all conditions met? [y/N]: "
"""Question after the checklist (interactive mode)."""

MESSAGE_ABORTED: Final[str] = "Probe aborted by the operator."
"""Refusal message: answer other than `y`/`yes`, empty, EOF or Ctrl-C."""

MESSAGE_NO_TTY: Final[str] = "No interactive terminal: confirm the checklist with the --yes flag."
"""Refusal message: `stdin` is not a TTY and `--yes` is missing."""

MESSAGE_YES_FLAG: Final[str] = "Confirmed with the --yes flag."
"""Message after the checklist with `--yes`."""


class PreflightMode(StrEnum):
    """How the checklist was confirmed (`session_start.meta.preflight`)."""

    INTERACTIVE = "interactive"
    YES_FLAG = "yes-flag"
    NOT_APPLICABLE = "n/a"


class PreflightAborted(ObdBridgeError):
    """Refusal in preflight (also EOF, Ctrl-C and no TTY without `--yes`); code 1."""

    exit_code: ClassVar[int] = 1


class _Reader(Protocol):
    def readline(self) -> str: ...


class _Writer(Protocol):
    def write(self, text: str, /) -> object: ...


def checklist_text(url: str) -> str:
    """T9 checklist text without the final question; `url` is the adapter port."""
    return "\n".join(
        (
            "Checklist before the live probe:",
            "  1. Selector lever in P.",
            "  2. Parking brake applied.",
            "  3. Ignition on; engine off or started before the probe "
            "(do not start the engine during the probe).",
            "  4. OBDeleven and other tools disconnected from the OBD port.",
            "  5. Battery charged; the probe only warns at voltage below 12.4 V "
            "(engine off) or 13.2 V (engine running), it does not stop.",
            f"  6. Adapter connected to the OBD port and to port {url}.",
            "The probe sends only read requests (0x22, 0x19) and flow control frames on the CAN bus.",
        )
    )


def _is_tty(stream: object) -> bool:
    isatty = getattr(stream, "isatty", None)
    if not callable(isatty):
        return False
    try:
        return bool(isatty())
    except (OSError, ValueError):
        return False


def _flush(stream: object) -> None:
    flush = getattr(stream, "flush", None)
    if callable(flush):
        flush()


def confirm(
    stdin: _Reader | None = None,
    stderr: _Writer | None = None,
    yes: bool = False,
    url: str = "",
) -> str:
    """Print the checklist and return the confirmation mode (`interactive` or `yes-flag`).

    Parameters:
        stdin: source of the operator's answer (default `sys.stdin`).
        stderr: stream for the checklist and messages (default `sys.stderr`).
        yes: confirmation with the `--yes` flag (no question and no TTY check).
        url: adapter port in item 6 of the checklist.

    Raises:
        PreflightAborted: answer other than `y`/`yes`, empty, EOF, Ctrl-C
            or `stdin` without a TTY when `--yes` is missing (code 1).
    """
    source = sys.stdin if stdin is None else stdin
    out = sys.stderr if stderr is None else stderr
    out.write(checklist_text(url) + "\n")
    if yes:
        out.write(MESSAGE_YES_FLAG + "\n")
        _flush(out)
        return PreflightMode.YES_FLAG.value
    if not _is_tty(source):
        _flush(out)
        raise PreflightAborted(MESSAGE_NO_TTY)
    out.write(PROMPT)
    _flush(out)
    try:
        answer = source.readline()
    except (EOFError, KeyboardInterrupt):
        out.write("\n")
        raise PreflightAborted(MESSAGE_ABORTED) from None
    if not answer:  # EOF: `readline` returns an empty string without a newline
        out.write("\n")
        raise PreflightAborted(MESSAGE_ABORTED)
    if answer.strip().lower() not in ACCEPTED_ANSWERS:
        raise PreflightAborted(MESSAGE_ABORTED)
    return PreflightMode.INTERACTIVE.value
