"""Read-only policy: UDS guard, adapter line guard and adapter configuration model (spec T2).

`ReadOnlyPolicy` is the single decision point for the driver, the UDS client
and the audit. The constructor accepts only the ECU catalog; there is no
parameter, environment variable or option that disables the guard (FR-17). The
policy has no access to the log: `guard` events are emitted by the caller.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Final

from obd_bridge.errors import ReadOnlyViolation
from obd_bridge.policy.adapter_guard import AdapterCommandGuard
from obd_bridge.policy.adapter_model import (
    AdapterConfigModel,
    reply_ok_for,
    reset_evidence,
    stale_input_tolerated,
)
from obd_bridge.policy.decision import GuardContext, GuardDecision
from obd_bridge.policy.uds_guard import UdsGuard
from obd_bridge.vag.catalog import EcuCatalog

__all__ = [
    "LAYER_ADAPTER",
    "LAYER_UDS",
    "AdapterConfigModel",
    "GuardContext",
    "GuardDecision",
    "ReadOnlyPolicy",
    "reply_ok_for",
    "reset_evidence",
    "stale_input_tolerated",
]

LAYER_UDS: Final[str] = "uds"
"""Violation layer for a UDS payload (`ReadOnlyUdsClient._checked`)."""

LAYER_ADAPTER: Final[str] = "adapter"
"""Violation layer for an adapter line (`StnDriver._egress`)."""


class ReadOnlyPolicy:
    """Read-only policy facade combining `UdsGuard` and `AdapterCommandGuard`.

    The catalog passed to the constructor takes precedence: `check_line`
    evaluates the addressee only against it, also when `ctx.catalog` is a
    different object.
    """

    def __init__(self, catalog: EcuCatalog) -> None:
        if not isinstance(catalog, EcuCatalog):
            raise TypeError(f"ReadOnlyPolicy requires EcuCatalog, got {type(catalog).__name__}")
        self._catalog = catalog
        self._uds_guard = UdsGuard()
        self._line_guard = AdapterCommandGuard()

    @property
    def catalog(self) -> EcuCatalog:
        """ECU catalog against which the policy checks addressees."""
        return self._catalog

    def check_uds(self, payload: bytes) -> GuardDecision:
        """Evaluates a UDS or OBD request payload (SID at position 0)."""
        return self._uds_guard.check(payload)

    def check_line(self, line: str, ctx: GuardContext) -> GuardDecision:
        """Evaluates an adapter line (without terminator) in context `ctx`."""
        if not isinstance(ctx, GuardContext):
            raise TypeError(f"Guard context must be GuardContext, got {type(ctx).__name__}")
        if ctx.catalog is not self._catalog:
            ctx = replace(ctx, catalog=self._catalog)
        return self._line_guard.check(line, ctx)

    def enforce_uds(self, payload: bytes) -> None:
        """Raises `ReadOnlyViolation` (layer `uds`) when the payload is rejected."""
        decision = self.check_uds(payload)
        if not decision.allowed:
            raise ReadOnlyViolation(
                LAYER_UDS, decision.rule, decision.reason or "", bytes(payload).hex().upper()
            )

    def enforce_line(self, line: str, ctx: GuardContext) -> None:
        """Raises `ReadOnlyViolation` (layer `adapter`) when the line is rejected."""
        decision = self.check_line(line, ctx)
        if not decision.allowed:
            raise ReadOnlyViolation(LAYER_ADAPTER, decision.rule, decision.reason or "", line)
