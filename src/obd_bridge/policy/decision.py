"""Decision and context types of the read-only policy (spec T2).

The module does not import the `ReadOnlyPolicy` facade, so the UDS guard and
the adapter line guard share types without an import cycle. `DriverState`
comes from `stn/state.py`, which does not depend on the policy.
"""

from __future__ import annotations

from dataclasses import dataclass

from obd_bridge.policy.adapter_model import AdapterConfigModel
from obd_bridge.stn.state import DriverState
from obd_bridge.vag.catalog import EcuCatalog, EcuTarget

__all__ = ["GuardContext", "GuardDecision"]


@dataclass(frozen=True)
class GuardDecision:
    """Result of a guard's evaluation of a request.

    Attributes:
        allowed: True when the request may reach the transport.
        rule: rule identifier; on acceptance the rule of the matched entry
            (e.g. `UDS/0x22`), on rejection the rejection rule (e.g. `UDS/sid`).
        reason: description of the cause, only on rejection.
        uds_rule: UdsGuard rule when the line guard rejects `STPX` with rule
            `LINE/uds`; None in all other cases.
    """

    allowed: bool
    rule: str
    reason: str | None
    uds_rule: str | None = None

    @classmethod
    def allow(cls, rule: str) -> GuardDecision:
        """Returns an accepting decision for rule `rule`."""
        return cls(allowed=True, rule=rule, reason=None)

    @classmethod
    def reject(cls, rule: str, reason: str, uds_rule: str | None = None) -> GuardDecision:
        """Returns a rejecting decision with rule `rule` and reason `reason`."""
        return cls(allowed=False, rule=rule, reason=reason, uds_rule=uds_rule)


@dataclass(frozen=True)
class GuardContext:
    """Context for evaluating an adapter line (immutable snapshot).

    Attributes:
        state: current driver state.
        target: current target, or None when no target is selected.
        catalog: ECU catalog (addressee allowlist).
        adapter: adapter configuration model built from lines that got `OK`.

    Raises:
        TypeError: a field has an invalid type; the context is then not created,
            so the guard never evaluates a line based on incomplete data.
    """

    state: DriverState
    target: EcuTarget | None
    catalog: EcuCatalog
    adapter: AdapterConfigModel

    def __post_init__(self) -> None:
        if not isinstance(self.state, DriverState):
            raise TypeError(f"GuardContext.state must be DriverState, got {self.state!r}")
        if self.target is not None and not isinstance(self.target, EcuTarget):
            raise TypeError(f"GuardContext.target must be EcuTarget or None, got {self.target!r}")
        if not isinstance(self.catalog, EcuCatalog):
            raise TypeError(f"GuardContext.catalog must be EcuCatalog, got {type(self.catalog).__name__}")
        if not isinstance(self.adapter, AdapterConfigModel):
            raise TypeError(
                f"GuardContext.adapter must be AdapterConfigModel, got {type(self.adapter).__name__}"
            )
