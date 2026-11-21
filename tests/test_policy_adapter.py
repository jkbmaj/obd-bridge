"""Tests of the adapter line policy: allowlist, canonical form, addressee, configuration model (FR-13, FR-14, FR-16).

Vectors come from the `lines` and `blacklist` sections of `tests/fixtures/guard_vectors.json`.
A vector without an `adapter` field is evaluated with a model consistent with the
target (helper `consistent_model`); a vector with an `adapter` field starts from an
empty model and applies the given lines with an `OK` reply.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from conftest import MOCK_CATALOG
from obd_bridge.errors import ReadOnlyViolation
from obd_bridge.policy import GuardContext, GuardDecision, ReadOnlyPolicy
from obd_bridge.policy.adapter_guard import ALLOWLIST, AdapterCommandGuard
from obd_bridge.policy.adapter_model import AdapterConfigModel, reply_ok_for
from obd_bridge.stn.parser import parse_adapter_reply
from obd_bridge.stn.state import DriverState
from obd_bridge.vag.catalog import EcuCatalog, EcuTarget

REPO_ROOT: Path = Path(__file__).resolve().parent.parent
VECTORS_PATH: Path = REPO_ROOT / "tests" / "fixtures" / "guard_vectors.json"
CATALOG: EcuCatalog = EcuCatalog.load(MOCK_CATALOG)
POLICY = ReadOnlyPolicy(CATALOG)
GUARD = AdapterCommandGuard()

ACTIVE_STATES: tuple[DriverState, ...] = (
    DriverState.RAW,
    DriverState.READY,
    DriverState.PROTOCOL_OPEN,
    DriverState.TARGET_SELECTED,
)
CLEANUP_COMMANDS: tuple[str, ...] = ("ATAR", "STCFCPC", "STFAC", "STFPC", "STFFCC", "STFBC", "STFCP")
REQUIRED_BLACKLIST: tuple[str, ...] = ("ATCAF0", "ATFCSD021101", "ATFCSD0414FFFFFF", "ATZ", "STBR38400")


def _load_vectors() -> dict[str, Any]:
    with VECTORS_PATH.open(encoding="utf-8") as handle:
        return json.load(handle)


VECTORS: dict[str, Any] = _load_vectors()
LINE_VECTORS: list[dict[str, Any]] = list(VECTORS["lines"])
ALLOW_VECTORS = [v for v in LINE_VECTORS if v["expect"] == "allow"]
REJECT_VECTORS = [v for v in LINE_VECTORS if v["expect"] == "reject"]


def apply_lines(lines: list[str], model: AdapterConfigModel | None = None) -> AdapterConfigModel:
    """Applies lines with an `OK` reply to the model (empty by default)."""
    result = model if model is not None else AdapterConfigModel()
    for line in lines:
        result = result.apply(line, True)
    return result


def consistent_lines(target: EcuTarget | None) -> list[str]:
    """Lines of an adapter configuration consistent with the target (T4 sequences, `st_pairs` strategy)."""
    lines = ["ATWS", "ATE0", "ATL0", "ATS0", "ATH1", "STI"]
    if target is None:
        return lines
    tx, rx = f"{target.tx_id:03X}", f"{target.rx_id:03X}"
    lines += ["STP33", "ATCAF1", "ATCFC1", "ATFCSM0", "ATAL", "ATAT1", "STPTO300", f"ATSH{tx}", f"ATCRA{rx}"]
    if target.fc_mode == "pair":
        lines += [f"STCFCPA{tx},{rx}", f"STFFCA{rx},7FF"]
    return lines


def consistent_model(target: EcuTarget | None) -> AdapterConfigModel:
    """Configuration model consistent with the target, used when the `adapter` field is absent."""
    return apply_lines(consistent_lines(target))


def _target(address: str | None) -> EcuTarget | None:
    return None if address is None else CATALOG.get(address)


def context_for(vector: dict[str, Any]) -> GuardContext:
    """Builds the `GuardContext` of a vector."""
    target = _target(vector["target"])
    if "adapter" in vector:
        model = apply_lines(list(vector["adapter"]))
    else:
        model = consistent_model(target)
    return GuardContext(
        state=DriverState(vector["state"]), target=target, catalog=CATALOG, adapter=model
    )


def _ctx(state: DriverState, target: EcuTarget | None, model: AdapterConfigModel | None = None) -> GuardContext:
    return GuardContext(
        state=state,
        target=target,
        catalog=CATALOG,
        adapter=model if model is not None else consistent_model(target),
    )


def _assert_reason(decision: GuardDecision) -> None:
    assert isinstance(decision.reason, str) and decision.reason.strip()
    # Messages without em dashes and en dashes as punctuation (FR-29).
    assert "\u2014" not in decision.reason and "\u2013" not in decision.reason


def test_allow_vector_per_entry() -> None:
    """The allowlist has 50 entries, each has an `allow` vector, every `allow` vector passes."""
    rules = [entry.rule for entry in ALLOWLIST]
    assert len(ALLOWLIST) == 50
    assert len(set(rules)) == 50, "allowlist rules must be unique"
    assert isinstance(ALLOWLIST, tuple)

    covered = {v["rule"] for v in ALLOW_VECTORS}
    missing = sorted(set(rules) - covered)
    assert not missing, f"allowlist entries without an allow vector: {missing}"
    assert covered <= set(rules)

    for vector in ALLOW_VECTORS:
        line = vector["line"]
        matches = [entry.rule for entry in ALLOWLIST if entry.pattern.fullmatch(line)]
        assert matches == [vector["rule"]], f"{vector['id']}: the line must match exactly one entry"
        decision = POLICY.check_line(line, context_for(vector))
        assert decision == GuardDecision.allow(vector["rule"]), vector["id"]
        POLICY.enforce_line(line, context_for(vector))


def _category_counts() -> dict[str, int]:
    counts: dict[str, int] = {}
    for vector in REJECT_VECTORS:
        prefix = vector["id"].split("-", 1)[0]
        counts[prefix] = counts.get(prefix, 0) + 1
    return counts


def test_reject_vector_minimums() -> None:
    """T2 minimum set: state 14, canonical 15, addressee 12, model 6."""
    counts = _category_counts()
    assert counts.get("state", 0) >= 14
    assert counts.get("canon", 0) >= 15
    assert counts.get("addr", 0) >= 12
    assert counts.get("model", 0) >= 6
    assert all(v["rule"] == "LINE/adapter-config" for v in REJECT_VECTORS if v["id"].startswith("model-"))
    assert all(v["rule"] == "LINE/state" for v in REJECT_VECTORS if v["id"].startswith("state-"))


@pytest.mark.parametrize("vector", REJECT_VECTORS, ids=lambda v: v["id"])
def test_reject_vectors(vector: dict[str, Any]) -> None:
    """Every `reject` vector yields exactly the expected rule and `uds_rule`; `enforce_line` raises."""
    line = vector["line"]
    decision = POLICY.check_line(line, context_for(vector))
    assert decision.allowed is False
    assert decision.rule == vector["rule"]
    assert decision.uds_rule == vector.get("uds_rule")
    _assert_reason(decision)

    with pytest.raises(ReadOnlyViolation) as raised:
        POLICY.enforce_line(line, context_for(vector))
    violation = raised.value
    assert violation.layer == "adapter"
    assert violation.rule == vector["rule"]
    assert violation.subject == line
    assert violation.exit_code == 2


def test_blacklist_all_states() -> None:
    """Every blacklist item is rejected in R, Y, P, T, with and without a target."""
    blacklist: list[str] = list(VECTORS["blacklist"])
    for required in REQUIRED_BLACKLIST:
        assert required in blacklist
    assert len(blacklist) >= 61
    targets: list[EcuTarget | None] = [None, CATALOG.get("19"), CATALOG.get("01")]
    for item in blacklist:
        assert not any(entry.pattern.fullmatch(item) for entry in ALLOWLIST), item
        for state in ACTIVE_STATES:
            for target in targets:
                decision = POLICY.check_line(item, _ctx(state, target))
                assert decision.allowed is False, (item, state, target)
                assert decision.rule.startswith("LINE/")


def test_cleanup_only_ready() -> None:
    """Filter and pair clearing commands only in READY (audit M1)."""
    gateway = CATALOG.get("19")
    for command in CLEANUP_COMMANDS:
        assert POLICY.check_line(command, _ctx(DriverState.READY, None)).allowed, command
        for state in (DriverState.PROTOCOL_OPEN, DriverState.TARGET_SELECTED):
            for target in (None, gateway):
                decision = POLICY.check_line(command, _ctx(state, target))
                assert decision.allowed is False
                assert decision.rule == "LINE/state", (command, state)
        assert POLICY.check_line(command, _ctx(DriverState.RAW, None)).rule == "LINE/state"


def test_fcsm1_requires_model() -> None:
    """`ATFCSM1` requires `ATFCSH<target tx>` and `ATFCSD300000` (audit C1, m13)."""
    gateway = CATALOG.get("19")
    base = ["STP33", "ATCAF1", "ATSH710", "ATCRA77A"]
    cases = {
        "without ATFCSH": (base + ["ATFCSD300000"], False),
        "ATFCSH of another module": (base + ["ATFCSH713", "ATFCSD300000"], False),
        "without ATFCSD300000": (base + ["ATFCSH710"], False),
        "ATFCSD overwritten": (base + ["ATFCSH710", "ATFCSD300000", "ATFCSD021101"], False),
        "full model": (base + ["ATFCSH710", "ATFCSD300000"], True),
    }
    for name, (lines, allowed) in cases.items():
        model = apply_lines(lines)
        decision = POLICY.check_line("ATFCSM1", _ctx(DriverState.PROTOCOL_OPEN, gateway, model))
        assert decision.allowed is allowed, name
        if not allowed:
            assert decision.rule == "LINE/adapter-config", name
            assert model.check_fcsm1(gateway) is not None
        else:
            assert model.check_fcsm1(gateway) is None
    # ATFCSM0 does not depend on the model.
    assert POLICY.check_line("ATFCSM0", _ctx(DriverState.PROTOCOL_OPEN, gateway, AdapterConfigModel())).allowed
    # Without a target ATFCSM1 is always rejected.
    full = apply_lines(base + ["ATFCSH710", "ATFCSD300000"])
    decision = POLICY.check_line("ATFCSM1", _ctx(DriverState.READY, None, full))
    assert decision.rule == "LINE/adapter-config"


_CONFIGURED = ["ATWS", "ATE0", "ATL0", "ATS0", "ATH1", "STI", "STP33", "ATCAF1", "ATFCSM1",
               "ATFCSH710", "ATFCSD300000", "ATSH710", "ATCRA77A", "STCFCPA710,77A", "STFFCA77A,7FF"]

# (description, setup lines, line, reply_ok, field, expected value)
MODEL_CASES: list[tuple[str, list[str], str, bool, str, Any]] = [
    ("formatted-set", ["ATE0", "ATL0", "ATS0"], "ATH1", True, "formatted", True),
    ("formatted-partial", ["ATE0", "ATL0"], "ATH1", True, "formatted", False),
    ("formatted-no-ok", ["ATE0", "ATL0", "ATS0"], "ATH1", False, "formatted", False),
    ("formatted-ath0", ["ATE0", "ATL0", "ATS0", "ATH1"], "ATH0", True, "formatted", False),
    ("formatted-reset", ["ATE0", "ATL0", "ATS0", "ATH1"], "ATWS", True, "formatted", False),
    ("identified-set", [], "STI", True, "identified", True),
    ("identified-no-ok", [], "STI", False, "identified", False),
    ("identified-reset", ["STI"], "ATWS", True, "identified", False),
    ("protocol-set", [], "STP33", True, "protocol_open", True),
    ("protocol-no-ok", [], "STP33", False, "protocol_open", False),
    ("protocol-stpc", ["STP33"], "STPC", True, "protocol_open", False),
    ("protocol-other", ["STP33"], "STP34", True, "protocol_open", False),
    ("protocol-reset", ["STP33"], "ATWS", True, "protocol_open", False),
    ("caf1-set", ["STP33"], "ATCAF1", True, "caf1", True),
    ("caf1-no-ok", ["STP33"], "ATCAF1", False, "caf1", False),
    ("caf1-stp33", ["STP33", "ATCAF1"], "STP33", True, "caf1", False),
    ("caf1-caf0", ["STP33", "ATCAF1"], "ATCAF0", True, "caf1", False),
    ("caf1-reset", ["STP33", "ATCAF1"], "ATWS", True, "caf1", False),
    ("fcsm-0", [], "ATFCSM0", True, "fcsm", 0),
    ("fcsm-1", [], "ATFCSM1", True, "fcsm", 1),
    ("fcsm-no-ok", ["ATFCSM0"], "ATFCSM1", False, "fcsm", 0),
    ("fcsm-reset", ["ATFCSM0"], "ATWS", True, "fcsm", None),
    ("fcsh-set", [], "ATFCSH710", True, "fcsh", 0x710),
    ("fcsh-no-ok", [], "ATFCSH710", False, "fcsh", None),
    ("fcsh-reset", ["ATFCSH710"], "ATWS", True, "fcsh", None),
    ("fcsd-set", [], "ATFCSD300000", True, "fcsd", "300000"),
    ("fcsd-other", ["ATFCSD300000"], "ATFCSD021101", True, "fcsd", "021101"),
    ("fcsd-reset", ["ATFCSD300000"], "ATWS", True, "fcsd", None),
    ("header-set", [], "ATSH710", True, "header", 0x710),
    ("header-no-ok", ["ATSH710"], "ATSH713", False, "header", 0x710),
    ("header-reset", ["ATSH710"], "ATWS", True, "header", None),
    ("cra-set", [], "ATCRA77A", True, "cra", 0x77A),
    ("cra-stp33", ["ATCRA77A"], "STP33", True, "cra", None),
    ("cra-atar", ["ATCRA77A"], "ATAR", True, "cra", None),
    ("cra-reset", ["ATCRA77A"], "ATWS", True, "cra", None),
    ("pairs-stcfcpa", [], "STCFCPA710,77A", True, "pairs", frozenset({(0x710, 0x77A)})),
    ("pairs-stcafcp", [], "STCAFCP713,77D", True, "pairs", frozenset({(0x713, 0x77D)})),
    ("pairs-no-ok", [], "STCFCPA710,77A", False, "pairs", frozenset()),
    ("pairs-clear", ["STCFCPA710,77A"], "STCFCPC", True, "pairs", frozenset()),
    ("pairs-reset", ["STCFCPA710,77A"], "ATWS", True, "pairs", frozenset()),
    ("filters-stffca", [], "STFFCA77A,7FF", True, "fc_filters", frozenset({0x77A})),
    ("filters-stfafc", [], "STFAFC77D,7FF", True, "fc_filters", frozenset({0x77D})),
    ("filters-no-ok", [], "STFFCA77A,7FF", False, "fc_filters", frozenset()),
    ("filters-stffcc", ["STFFCA77A,7FF"], "STFFCC", True, "fc_filters", frozenset()),
    ("filters-atar", ["STFFCA77A,7FF"], "ATAR", True, "fc_filters", frozenset()),
    ("filters-reset", ["STFFCA77A,7FF"], "ATWS", True, "fc_filters", frozenset()),
    ("query-no-change", _CONFIGURED, "ATRV", True, "pairs", frozenset({(0x710, 0x77A)})),
]


@pytest.mark.parametrize(
    ("setup", "line", "reply_ok", "field", "expected"),
    [case[1:] for case in MODEL_CASES],
    ids=[case[0] for case in MODEL_CASES],
)
def test_adapter_model_apply(setup: list[str], line: str, reply_ok: bool, field: str, expected: Any) -> None:
    """Setting and resetting model fields; setting only with `reply_ok`."""
    before = apply_lines(setup)
    after = before.apply(line, reply_ok)
    assert getattr(after, field) == expected
    # Immutable value: `apply` does not modify the source model.
    assert before == apply_lines(setup)
    if not reply_ok and line not in {"ATWS", "STPC", "STCFCPC", "STFFCC", "ATAR"}:
        assert after == before


def test_reply_ok_for() -> None:
    """`reply_ok_for`: `STN...` for `STI`, `ELM327` for `ATWS`, `OK` for the others."""
    assert reply_ok_for("STI", parse_adapter_reply(b"STN2120 v4.5.0\r\r>", "STI")) is True
    assert reply_ok_for("STI", parse_adapter_reply(b"ELM327 v1.3a\r\r>", "STI")) is False
    assert reply_ok_for("STI", parse_adapter_reply(b"?\r\r>", "STI")) is False
    assert reply_ok_for("STI", parse_adapter_reply(b"OK\r\r>", "STI")) is False
    assert reply_ok_for("ATWS", parse_adapter_reply(b"\r\rELM327 v1.3a\r\r>", "ATWS")) is True
    assert reply_ok_for("ATWS", parse_adapter_reply(b"?\r\r>", "ATWS")) is False
    assert reply_ok_for("ATE0", parse_adapter_reply(b"ATE0\rOK\r\r>", "ATE0")) is True
    assert reply_ok_for("STCFCPA710,77A", parse_adapter_reply(b"?\r\r>", "STCFCPA710,77A")) is False
    assert reply_ok_for("ATSH710", parse_adapter_reply(b"CAN ERROR\r\r>", "ATSH710")) is False
    model = AdapterConfigModel().apply("STI", reply_ok_for("STI", parse_adapter_reply(b"STN2120 v4.5.0\r\r>", "STI")))
    assert model.identified is True


def test_7df_always_rejected() -> None:
    """`ATSH7DF` and `STPX H:7DF,...` rejected in every state and with every target (FR-14)."""
    targets: list[EcuTarget | None] = [None, *CATALOG.all_uds()]
    lines = ("ATSH7DF", "STPX H:7DF,D:0100,R:1", "ATCRA7DF", "ATFCSH7DF", "STCFCPA7DF,7E8")
    for state in DriverState:
        for target in targets:
            for line in lines:
                decision = POLICY.check_line(line, _ctx(state, target))
                assert decision.allowed is False, (line, state, target)
                expected = "LINE/address" if state in {DriverState.PROTOCOL_OPEN, DriverState.TARGET_SELECTED} else "LINE/state"
                if line.startswith("STPX") and state is not DriverState.TARGET_SELECTED:
                    expected = "LINE/state"
                assert decision.rule == expected, (line, state, target)
    # The guard used without the facade gives the same result.
    gateway = CATALOG.get("19")
    assert GUARD.check("ATSH7DF", _ctx(DriverState.PROTOCOL_OPEN, gateway)).rule == "LINE/address"
