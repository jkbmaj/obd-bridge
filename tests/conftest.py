"""Shared fixtures of the obd-bridge tests.

FR-06 safety net: no test may open a device under `/dev/*`. An autouse
fixture replaces `serial.serial_for_url` and the `open` method of
`serial.Serial`, so an attempt to open a port under `/dev/` fails the test
before pyserial touches the operating system. The same fixture replaces
`serial.tools.list_ports.comports`, so no test enumerates the USB devices of
the machine it runs on; tests of adapter detection install their own fake.

The module also provides the golden transcript loader (`load_transcript`,
spec T4) and the scripted test transport `ScriptedTransport` for tests of the
driver and higher layers (fixtures `load_transcript` and `scripted_transport`).
"""

from __future__ import annotations

import shutil
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
import serial
import serial.tools.list_ports

from obd_bridge.errors import TransportError, TransportTimeout

REPO_ROOT: Path = Path(__file__).resolve().parent.parent
"""Repository root directory (parent of the `tests/` directory)."""

_CATALOG_RELATIVE = Path("defs") / "ecu-catalog.yaml"

MOCK_DIR: Path = REPO_ROOT / "tests" / "fixtures" / "mock"
"""Synthetic test data that replaces the local, unpublished `defs/` and `docs/`.

The files lie directly in `MOCK_DIR`: subdirectories named `defs/` or `docs/`
would match the unanchored rules in `.gitignore` and never reach the repository.
"""

MOCK_CATALOG: Path = MOCK_DIR / "ecu-catalog.yaml"
"""Mock ECU catalog (schema `obdb.ecu-catalog/1`) used by all tests."""

MOCK_MODULES_DOC: Path = MOCK_DIR / "moduly-obdeleven.md"
"""Mock module table matching `MOCK_CATALOG`."""

MOCK_DIDS_DOC: Path = MOCK_DIR / "dids-obdeleven.md"
"""Mock DID sections (section `## 01` lists the engine NOx DIDs)."""

PRIVATE_CATALOG: Path = REPO_ROOT / _CATALOG_RELATIVE
"""Local, unpublished module catalog; checked only by `test_private_data.py`."""

PRIVATE_MODULES_DOC: Path = REPO_ROOT / "docs" / "moduly-obdeleven.md"
"""Local, unpublished module table; checked only by `test_private_data.py`."""

PRIVATE_DIDS_DOC: Path = REPO_ROOT / "docs" / "dids-obdeleven.md"
"""Local, unpublished DID document; checked only by `test_private_data.py`."""


def _refuse_dev(value: object, where: str) -> None:
    """Aborts the test when a path or URL points to a device under `/dev/`."""
    if isinstance(value, str) and "/dev/" in value:
        pytest.fail(
            f"Test tried to open device {value!r} via {where}; "
            "tests must not use /dev/* (FR-06)",
            pytrace=True,
        )


@pytest.fixture(autouse=True)
def _block_dev_serial(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Blocks opening `/dev/*` ports through pyserial in every test."""
    original_for_url = serial.serial_for_url
    original_open = serial.Serial.open

    def guarded_serial_for_url(url: Any, *args: Any, **kwargs: Any) -> Any:
        _refuse_dev(url, "serial.serial_for_url")
        return original_for_url(url, *args, **kwargs)

    def guarded_open(self: Any) -> Any:
        _refuse_dev(getattr(self, "port", None), "serial.Serial.open")
        _refuse_dev(getattr(self, "portstr", None), "serial.Serial.open")
        return original_open(self)

    def refused_comports(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("Test tried to enumerate host serial ports; replace comports in the test (FR-06)")

    monkeypatch.setattr(serial, "serial_for_url", guarded_serial_for_url)
    monkeypatch.setattr(serial.Serial, "open", guarded_open)
    monkeypatch.setattr(serial.tools.list_ports, "comports", refused_comports)
    yield


@pytest.fixture
def project_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Temporary project directory as the current working directory.

    Copies the mock catalog `MOCK_CATALOG` to `defs/ecu-catalog.yaml`, so that
    code resolving runtime paths relative to the working directory works
    unchanged, and `data/sessions/` and `data/probes/` files are created
    outside the repository.
    """
    destination = tmp_path / _CATALOG_RELATIVE
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(MOCK_CATALOG, destination)
    monkeypatch.chdir(tmp_path)
    return tmp_path


TRANSCRIPTS_DIR: Path = REPO_ROOT / "tests" / "fixtures" / "transcripts"
"""Directory of golden adapter transcripts (spec T4)."""

_OUTCOME_ALIASES = {"nrc": "negative"}
"""Outcome aliases in the `=` line; the example `= nrc 7F2231` from spec T4 means `negative`."""


@dataclass(frozen=True)
class ScriptStep:
    """One step of the transport script.

    Attributes:
        kind: `write` (expected host write), `read` (adapter reply) or `stale`
            (unread bytes: `pending_input` reports their count, `read_until`
            returns them, `reset_input` discards them).
        data: expected write bytes or bytes returned by `read_until`.
        timeout: for `read`: `read_until` raises `TransportTimeout(partial=data)`.
    """

    kind: str
    data: bytes
    timeout: bool = False


class ScriptedTransport:
    """Scripted test transport compatible with the `ByteTransport` protocol (spec T3).

    The script is a queue of `write` and `read` steps in wire order. A write
    different from the expected one, or a read where a write is expected,
    fails the test. The `writes` register holds the written bytes, and
    `read_timeouts` the `timeout_s` values of consecutive `read_until` calls.
    """

    url: str = "scripted://"
    can_set_baudrate: bool = False

    def __init__(self, steps: list[ScriptStep] | None = None) -> None:
        self.steps: list[ScriptStep] = list(steps or [])
        self.writes: list[bytes] = []
        self.read_timeouts: list[float] = []
        self.opened = False
        self.closed = False
        self.reset_count = 0
        self._position = 0

    def banner(self, data: bytes | str | None) -> ScriptedTransport:
        """Adds a banner window; `None` yields `TransportTimeout(partial=b"")`."""
        if data is None:
            self.steps.append(ScriptStep("read", b"", timeout=True))
        else:
            self.steps.append(ScriptStep("read", _as_bytes(data)))
        return self

    def stale(self, data: bytes | str) -> ScriptedTransport:
        """Adds unread bytes: reported by `pending_input`, returned by `read_until`, discarded by `reset_input`."""
        self.steps.append(ScriptStep("stale", _as_bytes(data)))
        return self

    def read(self, reply: bytes | str, *, timeout: bool = False) -> ScriptedTransport:
        """Adds a read only (e.g. the rest of a reply after the deadline was extended)."""
        self.steps.append(ScriptStep("read", _as_bytes(reply), timeout=timeout))
        return self

    def expect(
        self, line: str, reply: bytes | str, *, timeout: bool = False
    ) -> ScriptedTransport:
        """Adds the expected write `line + "\\r"` and the adapter reply."""
        self.steps.append(ScriptStep("write", line.encode("ascii") + b"\r"))
        self.steps.append(ScriptStep("read", _as_bytes(reply), timeout=timeout))
        return self

    @property
    def remaining(self) -> int:
        """Number of unconsumed script steps."""
        return len(self.steps) - self._position

    @property
    def written_lines(self) -> list[str]:
        """Written lines without the trailing `\\r`."""
        return [data.decode("ascii", errors="replace").removesuffix("\r") for data in self.writes]

    def open(self) -> None:
        """Marks the transport as open."""
        self.opened = True

    def close(self) -> None:
        """Marks the transport as closed."""
        self.closed = True

    def reset_input(self) -> None:
        """Counts input buffer reset calls and discards unread bytes (`stale`)."""
        self.reset_count += 1
        while self._position < len(self.steps) and self.steps[self._position].kind == "stale":
            self._position += 1

    def set_baudrate(self, baud: int) -> None:
        """Changing the baud rate is not supported by the test transport."""
        raise TransportError(f"ScriptedTransport does not support changing the baud rate to {baud}")

    def pending_input(self) -> int:
        """Number of unread bytes: a `stale` step at the head of the queue, otherwise 0 (not consumed)."""
        if self._position < len(self.steps) and self.steps[self._position].kind == "stale":
            return len(self.steps[self._position].data)
        return 0

    def write(self, data: bytes) -> None:
        """Records the write and compares it with the next script step."""
        self.writes.append(bytes(data))
        step = self._next("write", data)
        if step.data != data:
            pytest.fail(
                f"ScriptedTransport: expected write {step.data!r}, got {bytes(data)!r}"
            )

    def read_until(self, marker: bytes, timeout_s: float) -> bytes:
        """Returns the reply from the next step or raises `TransportTimeout`."""
        self.read_timeouts.append(timeout_s)
        if self._position < len(self.steps) and self.steps[self._position].kind == "stale":
            # Unread bytes: up to and including the marker (the rest stays), without a marker a timeout with `partial`.
            data = self.steps[self._position].data
            index = data.find(marker)
            if index < 0:
                self._position += 1
                raise TransportTimeout(partial=data)
            end = index + len(marker)
            if end < len(data):
                self.steps[self._position] = ScriptStep("stale", data[end:])
            else:
                self._position += 1
            return data[:end]
        step = self._next("read", marker)
        if step.timeout:
            raise TransportTimeout(partial=step.data)
        return step.data

    def _next(self, kind: str, actual: bytes) -> ScriptStep:
        if self._position >= len(self.steps):
            pytest.fail(f"ScriptedTransport: end of script, unexpected operation {kind} {actual!r}")
        step = self.steps[self._position]
        if step.kind != kind:
            pytest.fail(
                f"ScriptedTransport: expected operation {step.kind} ({step.data!r}), "
                f"got {kind} ({bytes(actual)!r})"
            )
        self._position += 1
        return step


def _as_bytes(data: bytes | str) -> bytes:
    return data if isinstance(data, bytes) else data.encode("ascii")


@dataclass(frozen=True)
class Transcript:
    """Golden adapter transcript loaded from a `tests/fixtures/transcripts/*.txt` file.

    Attributes:
        name: file name without extension.
        description: content of the `# description:` comment.
        meta: metadata from `@key: value` lines.
        exchanges: pairs (host line, raw adapter bytes) in wire order.
        expected: expected result `(outcome, rest)`, rest empty when absent.
    """

    name: str
    description: str
    meta: dict[str, str]
    exchanges: tuple[tuple[str, bytes], ...]
    expected: tuple[str, str]
    timed_out: bool = False
    steps: tuple[ScriptStep, ...] = field(default=())

    @property
    def kind(self) -> str:
        """`adapter` for adapter commands, `uds` for `STPX` (default)."""
        return self.meta.get("kind", "uds")

    @property
    def rx_id(self) -> int | None:
        """Reply CAN ID from `@rx_id`, or `None`."""
        value = self.meta.get("rx_id")
        return int(value, 16) if value else None

    @property
    def sent(self) -> str:
        """Host line of the first exchange."""
        return self.exchanges[0][0]

    @property
    def raw(self) -> bytes:
        """Raw adapter bytes of the first exchange."""
        return self.exchanges[0][1]

    def as_parser_input(self) -> tuple[str, bytes, int | None, tuple[str, str]]:
        """Returns `(sent, raw_bytes, rx_id, expected)` for the parser."""
        return self.sent, self.raw, self.rx_id, self.expected

    def to_transport(
        self, *, with_banner: bool = False, banner: bytes | str | None = None
    ) -> ScriptedTransport:
        """Builds a `ScriptedTransport` that replays the transcript exchanges.

        With `with_banner=True` the script starts with a banner window; the
        default `banner=None` means a timeout without data (like `NullTransport`).
        """
        transport = ScriptedTransport()
        if with_banner:
            transport.banner(banner)
        transport.steps.extend(self.steps)
        return transport


def load_transcript(path: Path | str) -> Transcript:
    """Loads a golden transcript according to the format from spec T4.

    Lines: `#` comment (`# description:` is kept), `@key: value` metadata,
    `> line` host write (`line + "\\r"`), `< text` adapter output
    (`text + "\\r"`, a bare `<` gives `\\r`), `<>` prompt `>`,
    `= outcome [rest]` expected result. Output without a trailing `<>` before
    the next write or the end of file is a timeout with partial data.
    """
    path = Path(path)
    description = ""
    meta: dict[str, str] = {}
    expected: tuple[str, str] | None = None
    steps: list[ScriptStep] = []
    exchanges: list[tuple[str, bytes]] = []
    current_line: str | None = None
    buffer = bytearray()
    timed_out = False

    def flush(prompt: bool) -> None:
        nonlocal buffer, current_line, timed_out
        if current_line is None:
            if buffer:
                raise ValueError(f"{path.name}: adapter output before the first host write")
            return
        steps.append(ScriptStep("read", bytes(buffer), timeout=not prompt))
        exchanges.append((current_line, bytes(buffer)))
        timed_out = timed_out or not prompt
        buffer = bytearray()
        current_line = None

    for number, text in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not text.strip():
            continue
        if text.startswith("#"):
            body = text[1:].strip()
            if body.startswith("description:"):
                description = body.removeprefix("description:").strip()
            continue
        if text.startswith("@"):
            key, _, value = text[1:].partition(":")
            meta[key.strip()] = value.strip()
        elif text.startswith(">"):
            if current_line is not None:
                flush(prompt=False)
            current_line = text[1:].strip()
            steps.append(ScriptStep("write", current_line.encode("ascii") + b"\r"))
        elif text == "<>":
            buffer += b">"
            flush(prompt=True)
        elif text.startswith("<"):
            if current_line is None:
                raise ValueError(f"{path.name}:{number}: adapter output without a host write")
            buffer += text[1:].removeprefix(" ").encode("ascii") + b"\r"
        elif text.startswith("="):
            outcome, _, rest = text[1:].strip().partition(" ")
            expected = (_OUTCOME_ALIASES.get(outcome, outcome), rest.strip())
        else:
            raise ValueError(f"{path.name}:{number}: unknown line format {text!r}")
    if current_line is not None:
        flush(prompt=False)
    if not exchanges:
        raise ValueError(f"{path.name}: transcript without an exchange")
    if expected is None:
        raise ValueError(f"{path.name}: no `=` line with the expected result")
    return Transcript(
        name=path.stem,
        description=description,
        meta=meta,
        exchanges=tuple(exchanges),
        expected=expected,
        timed_out=timed_out,
        steps=tuple(steps),
    )


@pytest.fixture(name="load_transcript")
def load_transcript_fixture() -> Callable[[Path | str], Transcript]:
    """Provides the transcript loader; a name without `/` is looked up in `TRANSCRIPTS_DIR`."""

    def loader(path: Path | str) -> Transcript:
        candidate = Path(path)
        if not candidate.suffix and len(candidate.parts) == 1:
            candidate = TRANSCRIPTS_DIR / f"{candidate.name}.txt"
        return load_transcript(candidate)

    return loader


@pytest.fixture
def scripted_transport() -> type[ScriptedTransport]:
    """Provides the `ScriptedTransport` class without importing from `conftest`."""
    return ScriptedTransport
