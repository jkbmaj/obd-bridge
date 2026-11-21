"""Adapter driver states and Flow Control strategies (spec T4).

The module imports nothing from `obd_bridge`, so the read-only policy
(`policy/decision.py`) and the driver (`stn/driver.py`) share these types
without an import cycle. `stn/driver.py` re-exports both classes.
"""

from __future__ import annotations

from enum import StrEnum

__all__ = ["DriverState", "FcStrategy"]


class DriverState(StrEnum):
    """State of the `StnDriver` state machine (no BAUD_HANDSHAKE in this iteration).

    Values:
        CLOSED: port closed, no line can be sent.
        RAW: port open, adapter not yet formatted or identified.
        READY: adapter identified, CAN protocol closed.
        PROTOCOL_OPEN: protocol 33 open, target not fully configured.
        TARGET_SELECTED: target configured, `STPX` requests allowed.
    """

    CLOSED = "CLOSED"
    RAW = "RAW"
    READY = "READY"
    PROTOCOL_OPEN = "PROTOCOL_OPEN"
    TARGET_SELECTED = "TARGET_SELECTED"


class FcStrategy(StrEnum):
    """Flow Control configuration strategy in `select_target`.

    Values:
        ST_PAIRS: `STCFCPA<tx>,<rx>` and `STFFCA<rx>,7FF`.
        ST_PAIRS_LEGACY: legacy names `STCAFCP<tx>,<rx>` and `STFAFC<rx>,7FF`.
        ELM_FALLBACK: `ATFCSH<tx>`, `ATFCSD300000` and `ATFCSM1`.
    """

    ST_PAIRS = "st_pairs"
    ST_PAIRS_LEGACY = "st_pairs_legacy"
    ELM_FALLBACK = "elm_fallback"
