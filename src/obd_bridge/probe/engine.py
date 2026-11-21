"""Engine state in the `obdb probe` probe (package D): RPM, samples and warnings.

Before every module step (stages B to D) and once in stage E the runner takes
a sample: voltage from `ATRV` and engine 01 RPM via the `22 F40C` read
(OBD PID 0C through ReadDataByIdentifier, the same shape as the `22 F4xx`
bitmaps in step 18). The module contains only pure functions and data types;
it performs no I/O.

The probe does not read the start-stop setting (DID unknown); it only detects
the effect, that is a change of engine state between samples.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final

__all__ = [
    "RUNNING_MIN_RPM",
    "SAMPLE_MARKER",
    "WARNING_CHARGING_LOW",
    "WARNING_ENGINE_EVENT",
    "WARNING_ENGINE_UNAVAILABLE",
    "WARNING_NO_RUNNING",
    "WARNING_VOLTAGE_LOW",
    "WARNING_VOLTAGE_UNREADABLE",
    "EngineSample",
    "EngineState",
    "ProbeWarning",
    "decode_rpm",
    "engine_event_text",
    "engine_state",
    "state_changed",
]

RUNNING_MIN_RPM: Final[float] = 400.0
"""RPM from which the engine is considered running (`running`)."""

SAMPLE_MARKER: Final[str] = "engine_sample"
"""Kind of the engine state sample marker in JSONL (`meta.kind`); sample lines belong to the step in `meta.step`."""

WARNING_VOLTAGE_LOW: Final[str] = "voltage_low"
"""Voltage below `VOLTAGE_MIN_V` with the engine off or in an unknown state."""

WARNING_VOLTAGE_UNREADABLE: Final[str] = "voltage_unreadable"
"""Unreadable `ATRV` response in step 5."""

WARNING_CHARGING_LOW: Final[str] = "charging_low"
"""Voltage below `CHARGING_MIN_V` with the engine running (the alternator may not be charging)."""

WARNING_ENGINE_EVENT: Final[str] = "engine_event"
"""Engine state change during a module step."""

WARNING_NO_RUNNING: Final[str] = "engine_no_running"
"""No module measurement with the engine running after a state change."""

WARNING_ENGINE_UNAVAILABLE: Final[str] = "engine_unavailable"
"""Engine state detection inactive: no RPM in all samples or failed engine FC configuration."""


class EngineState(StrEnum):
    """Engine state from an RPM sample."""

    RUNNING = "running"
    OFF = "off"
    CRANKING = "cranking"
    UNKNOWN = "unknown"


def decode_rpm(data: bytes | None) -> float | None:
    """RPM from the response data `62 F4 0C A B`: (A*256+B)/4; fewer than 2 bytes gives None."""
    if data is None or len(data) < 2:
        return None
    return (data[0] * 256 + data[1]) / 4


def engine_state(rpm: float | None) -> EngineState:
    """`running` from 400 rpm, `off` at 0, `cranking` in between, `unknown` without a reading."""
    if rpm is None:
        return EngineState.UNKNOWN
    if rpm >= RUNNING_MIN_RPM:
        return EngineState.RUNNING
    if rpm == 0:
        return EngineState.OFF
    return EngineState.CRANKING


def state_changed(before: EngineState, after: EngineState) -> bool:
    """State change between two known samples; `unknown` on either side is not a change."""
    return before != after and EngineState.UNKNOWN not in (before, after)


def engine_event_text(before: EngineState, after: EngineState) -> str:
    """Label for a step entry, e.g. `engine state change: running -> off`."""
    return f"engine state change: {before.value} -> {after.value}"


@dataclass(frozen=True)
class EngineSample:
    """Engine state sample.

    Attributes:
        step: step before which the sample was taken (26: stage E sample).
        after_repeat: number of the repeated step when the sample closes a repeat, otherwise None.
        voltage_v: voltage from `ATRV` or None (unreadable, error).
        rpm: engine 01 RPM or None (NRC, NO DATA, error).
        state: engine state (`EngineState`).
    """

    step: int
    after_repeat: int | None
    voltage_v: float | None
    rpm: float | None
    state: EngineState

    def as_dict(self) -> dict[str, Any]:
        """Entry of the `engine.samples` list in the probe file."""
        return {
            "step": self.step,
            "after_repeat": self.after_repeat,
            "voltage_v": self.voltage_v,
            "rpm": self.rpm,
            "state": self.state.value,
        }


@dataclass(frozen=True)
class ProbeWarning:
    """Probe warning without a stop (voltage, engine state).

    Attributes:
        kind: kind (`WARNING_*`); step: step at which it was detected; message: text in English.
    """

    kind: str
    step: int
    message: str

    def as_dict(self) -> dict[str, Any]:
        """Entry of the `warnings` list in the probe file."""
        return {"kind": self.kind, "step": self.step, "message": self.message}
