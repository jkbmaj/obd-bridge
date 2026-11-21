"""Adapter profile stored in an `obdb.probe/1` probe file (spec T8, T9; FR-22).

The profile is built from the `adapter`, `commands`, `fc_strategy`,
`nrc78_mode` and `timing` blocks of the probe file. The probe always starts
without a profile (`identify(None)`); `AdapterProfile.load_latest` serves
later live commands and tests. A single bad file never stops the search: it
is skipped with a warning in `logging`.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, cast, get_args

from obd_bridge.errors import ObdBridgeError, os_error_text
from obd_bridge.stn.state import FcStrategy
from obd_bridge.yamlio import load_yaml

__all__ = [
    "DEFAULT_PROBES_DIR",
    "PROBE_GLOB",
    "PROBE_SCHEMA",
    "AdapterProfile",
    "CommandStatus",
    "Nrc78Mode",
    "ProfileError",
]

logger = logging.getLogger(__name__)

PROBE_SCHEMA = "obdb.probe/1"
"""Schema identifier of the probe file."""

DEFAULT_PROBES_DIR = Path("data/probes")
"""Default directory of probe files, relative to the working directory."""

PROBE_GLOB = "*/*-probe*.yaml"
"""Pattern of probe files `<YYYY-MM-DD>/<session_id>.yaml` relative to the probes directory."""

CommandStatus = Literal["ok", "unsupported", "untested"]
"""Result of checking a single adapter command in the probe."""

Nrc78Mode = Literal["same_command", "needs_r2", "unknown"]
"""Adapter behaviour on an NRC 0x78 reply (response pending)."""

_COMMAND_STATUSES: frozenset[str] = frozenset(get_args(CommandStatus))
_NRC78_MODES: frozenset[str] = frozenset(get_args(Nrc78Mode))


class ProfileError(ObdBridgeError):
    """The probe file cannot serve as an adapter profile (format, schema, fields)."""


@dataclass(frozen=True)
class AdapterProfile:
    """Adapter profile read from a probe file.

    Attributes:
        sti: `STI` reply (firmware version), e.g. `STN2120 v4.5.0`.
        stdi: `STDI` reply (hardware version), e.g. `STN2120 r1.0`.
        commands: result of checking adapter commands (`ok`, `unsupported`, `untested`).
        fc_strategy: established Flow Control strategy, or `None` when the probe did not establish one.
        nrc78_mode: behaviour on NRC 0x78 (`same_command`, `needs_r2`, `unknown`).
        timing: timing statistics, e.g. `{"stpx_22f187_ms": {"n": 100, "p50": 33.0, ...}}`.
        source: path of the probe file the profile was built from.
    """

    sti: str
    stdi: str
    commands: dict[str, CommandStatus]
    fc_strategy: FcStrategy | None
    nrc78_mode: Nrc78Mode
    timing: dict[str, dict[str, Any]]
    source: str

    @classmethod
    def from_probe_file(cls, path: Path) -> AdapterProfile:
        """Loads a profile from a probe file through `yamlio.load_yaml`.

        Checked: YAML validity, `schema` equal to `obdb.probe/1`, and the types
        and values of the profile fields. The `mode` field and the match of
        `sti`/`stdi` with the adapter are checked by `load_latest`.
        `fc_strategy: null` gives a profile with `None`.

        Raises:
            ProfileError: the file does not parse or does not meet the schema.
        """
        return cls._from_document(Path(path), _load_document(Path(path)))

    @classmethod
    def load_latest(
        cls, sti: str, stdi: str, probes_dir: Path = DEFAULT_PROBES_DIR
    ) -> AdapterProfile | None:
        """Returns the profile from the newest matching probe file, or `None`.

        Rule (spec T8):
        1. Candidates: `probes_dir/*/*-probe*.yaml` (`<session_id>.yaml`, also
           with a collision suffix, e.g. `20261120T081500-probe-2.yaml`).
        2. A file is skipped with a warning when it does not parse, `schema`
           is not `obdb.probe/1`, `mode` is not `live`, `adapter.sti` differs
           from `sti`, `adapter.stdi` differs from `stdi`, or `fc_strategy` is null.
        3. Choice: the greatest `started_at` (ISO 8601 string with a time zone,
           parsed by `datetime.fromisoformat`); a tie goes to the greater file name.
        4. No candidates: `None`.

        The method raises no exception because of a single bad file.
        """
        best: tuple[datetime, str, str, AdapterProfile] | None = None
        for path in sorted(Path(probes_dir).glob(PROBE_GLOB)):
            if not path.is_file():
                continue
            try:
                document = _load_document(path)
                started_at = _started_at(document)
                profile = cls._from_document(path, document)
                mode = document.get("mode")
                if mode != "live":
                    raise ProfileError(f"mode {mode!r} instead of 'live'")
                if profile.sti != sti:
                    raise ProfileError(f"adapter.sti {profile.sti!r} differs from {sti!r}")
                if profile.stdi != stdi:
                    raise ProfileError(f"adapter.stdi {profile.stdi!r} differs from {stdi!r}")
                if profile.fc_strategy is None:
                    raise ProfileError("fc_strategy is null")
            except ProfileError as exc:
                logger.warning("Skipped probe file %s: %s", path, exc)
                continue
            key = (started_at, path.name, str(path), profile)
            if best is None or key[:3] > best[:3]:
                best = key
        return None if best is None else best[3]

    @classmethod
    def _from_document(cls, path: Path, document: dict[str, Any]) -> AdapterProfile:
        """Builds the profile from a parsed probe document after validating the fields."""
        schema = document.get("schema")
        if schema != PROBE_SCHEMA:
            raise ProfileError(f"schema {schema!r} instead of {PROBE_SCHEMA!r}")

        adapter = document.get("adapter")
        if not isinstance(adapter, dict):
            raise ProfileError("missing 'adapter' map")
        sti = adapter.get("sti")
        stdi = adapter.get("stdi")
        if not isinstance(sti, str) or not isinstance(stdi, str):
            raise ProfileError("fields 'adapter.sti' and 'adapter.stdi' must be strings")

        commands = document.get("commands")
        if not isinstance(commands, dict):
            raise ProfileError("missing 'commands' map")
        for name, status in commands.items():
            if not isinstance(name, str) or status not in _COMMAND_STATUSES:
                raise ProfileError(f"invalid 'commands' entry: {name!r}: {status!r}")

        if "fc_strategy" not in document:
            raise ProfileError("missing 'fc_strategy' field")
        raw_fc = document["fc_strategy"]
        fc_strategy: FcStrategy | None
        if raw_fc is None:
            fc_strategy = None
        else:
            try:
                fc_strategy = FcStrategy(raw_fc)
            except ValueError:
                raise ProfileError(f"unknown fc_strategy strategy {raw_fc!r}") from None

        nrc78_mode = document.get("nrc78_mode")
        if nrc78_mode not in _NRC78_MODES:
            raise ProfileError(f"invalid nrc78_mode {nrc78_mode!r}")

        timing = document.get("timing")
        if not isinstance(timing, dict) or not all(
            isinstance(name, str) and isinstance(stats, dict) for name, stats in timing.items()
        ):
            raise ProfileError("field 'timing' must be a map of names to statistics maps")

        return cls(
            sti=sti,
            stdi=stdi,
            commands=cast(dict[str, CommandStatus], dict(commands)),
            fc_strategy=fc_strategy,
            nrc78_mode=cast(Nrc78Mode, nrc78_mode),
            timing={name: dict(stats) for name, stats in timing.items()},
            source=str(path),
        )


def _load_document(path: Path) -> dict[str, Any]:
    """Loads the probe file as a map; turns every read error into `ProfileError`."""
    try:
        document = load_yaml(path)
    except OSError as exc:
        raise ProfileError(f"cannot read file ({os_error_text(exc)})") from exc
    except UnicodeDecodeError as exc:
        raise ProfileError("file is not UTF-8 text") from exc
    except Exception as exc:  # ruamel raises various syntax and construction error classes
        raise ProfileError(f"invalid YAML{_yaml_position(exc)}") from exc
    if not isinstance(document, dict):
        raise ProfileError("YAML document is not a map")
    return document


def _yaml_position(exc: BaseException) -> str:
    """Position of a ruamel error as " (line L, column C)" or empty text; without the ruamel description."""
    mark = getattr(exc, "problem_mark", None) or getattr(exc, "context_mark", None)
    line = getattr(mark, "line", None)
    column = getattr(mark, "column", None)
    if isinstance(line, int) and isinstance(column, int):
        return f" (line {line + 1}, column {column + 1})"
    return ""


def _started_at(document: dict[str, Any]) -> datetime:
    """Returns `started_at` as a time-zone-aware `datetime`.

    The field must be a quoted string; ruamel turns an unquoted value into a
    `datetime` with no time zone guarantee, so it is rejected. The required
    time zone prevents comparing naive times with aware ones.
    """
    raw = document.get("started_at")
    if not isinstance(raw, str):
        kind = type(raw).__name__
        raise ProfileError(f"started_at must be a quoted string, got {kind}")
    try:
        moment = datetime.fromisoformat(raw)
    except ValueError:
        raise ProfileError(f"started_at {raw!r} is not an ISO 8601 date") from None
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ProfileError(f"started_at {raw!r} has no time zone")
    return moment
