"""Tests of the UDS policy (`UdsGuard`): `uds` vectors, SID enumeration and record 0xFF (FR-12, FR-16)."""

from __future__ import annotations

import inspect
import json
from pathlib import Path
from typing import Any

import pytest

from obd_bridge.policy.decision import GuardDecision
from obd_bridge.policy.uds_guard import (
    ALLOWED_RULES,
    ALLOWED_SIDS,
    RULE_EMPTY,
    RULE_RECORD_FF,
    RULE_SHAPE,
    RULE_SID,
    UdsGuard,
)

VECTORS_PATH: Path = Path(__file__).resolve().parent / "fixtures" / "guard_vectors.json"

# SIDs explicitly listed in spec T2 as rejected (`UDS/sid`); each must have a `reject` vector.
BLOCKED_SIDS: tuple[int, ...] = (
    0x10, 0x3E, 0x04, 0x11, 0x14, 0x23, 0x27, 0x28, 0x2A, 0x2C, 0x2E, 0x2F,
    0x31, 0x34, 0x35, 0x36, 0x37, 0x3D, 0x85, 0x87,
)

# Rejected payloads listed in the T2 minimum set with the expected rule.
REQUIRED_REJECTS: dict[str, str] = {
    "1001": RULE_SID,
    "1003": RULE_SID,
    "3E00": RULE_SID,
    "3E80": RULE_SID,
    "1982": RULE_SHAPE,
    "1904123456FF": RULE_RECORD_FF,
    "1906123456FF": RULE_RECORD_FF,
    "22F1": RULE_SHAPE,
    "22F187F1": RULE_SHAPE,
    "22F187F190F18CF19E": RULE_SHAPE,
    "": RULE_EMPTY,
}

# SIDs from the UdsGuard table (spec T2, FR-12).
TABLE_SIDS: frozenset[int] = frozenset({0x22, 0x19, 0x01, 0x03, 0x06, 0x07, 0x09, 0x0A})


def _load_vectors() -> dict[str, Any]:
    """Loads the guard vector file."""
    with VECTORS_PATH.open(encoding="utf-8") as handle:
        return json.load(handle)


def _uds_vectors() -> list[dict[str, Any]]:
    """Returns the `uds` section of the vector file."""
    return list(_load_vectors()["uds"])


GUARD = UdsGuard()


@pytest.mark.parametrize("vector", _uds_vectors(), ids=lambda v: v["id"])
def test_uds_vectors(vector: dict[str, Any]) -> None:
    """Every `uds` vector yields the expected decision and exactly the expected rule."""
    payload_hex: str = vector["payload"]
    assert payload_hex == payload_hex.upper(), "payload in upper-case hex"
    decision = GUARD.check(bytes.fromhex(payload_hex))

    assert isinstance(decision, GuardDecision)
    assert decision.allowed is (vector["expect"] == "allow")
    assert decision.rule == vector["rule"]
    assert decision.uds_rule is None
    if decision.allowed:
        assert decision.reason is None
    else:
        assert isinstance(decision.reason, str) and decision.reason.strip()
        # Messages without em dashes and en dashes as punctuation (FR-29).
        assert "\u2014" not in decision.reason and "\u2013" not in decision.reason


def _enumeration_payloads(sid: int) -> list[bytes]:
    """Payloads of length 1..8 for a SID: fill 0x00, 0xFF and the pattern F1 87 ..."""
    payloads: list[bytes] = []
    for length in range(1, 9):
        tail = length - 1
        payloads.append(bytes([sid]) + b"\x00" * tail)
        payloads.append(bytes([sid]) + b"\xff" * tail)
        pattern = (b"\xf1\x87" * 4)[:tail]
        payloads.append(bytes([sid]) + pattern)
    return payloads


def test_sid_enumeration() -> None:
    """SIDs 0x00..0xFF with lengths 1..8: only SIDs from the UdsGuard table are accepted."""
    assert ALLOWED_SIDS == TABLE_SIDS
    accepted: set[int] = set()
    for sid in range(0x100):
        for payload in _enumeration_payloads(sid):
            decision = GUARD.check(payload)
            if decision.allowed:
                accepted.add(sid)
                assert sid in TABLE_SIDS, f"accepted SID outside the table: {payload.hex()}"
                assert decision.rule in ALLOWED_RULES
            elif sid not in TABLE_SIDS:
                assert decision.rule == RULE_SID, payload.hex()
            else:
                assert decision.rule in {RULE_SHAPE, RULE_RECORD_FF}, payload.hex()

    assert accepted <= TABLE_SIDS
    # Fills 0x00, 0xFF and F1 are not allowed subfunctions of 0x19, so 0x19 does not
    # occur in the enumeration; the other SIDs from the table have at least one shape.
    assert accepted == TABLE_SIDS - {0x19}


def test_record_ff_rejected() -> None:
    """Record 0xFF in 0x19 04 and 0x19 06 and subfunctions with bit 0x80 are rejected."""
    for sub in (0x04, 0x06):
        rejected = GUARD.check(bytes([0x19, sub, 0x12, 0x34, 0x56, 0xFF]))
        assert not rejected.allowed
        assert rejected.rule == RULE_RECORD_FF
        allowed = GUARD.check(bytes([0x19, sub, 0x12, 0x34, 0x56, 0x01]))
        assert allowed.allowed
        assert allowed.rule == f"UDS/0x19/{sub:02X}"

    # Bit suppressPosRsp (0x80) in the subfunction: rejected for every subfunction from the table.
    for payload in (
        bytes.fromhex("1984123456FF"),
        bytes.fromhex("198412345601"),
        bytes.fromhex("1982FF"),
        bytes.fromhex("198108"),
        bytes.fromhex("1983"),
        bytes.fromhex("198A"),
        bytes.fromhex("1986123456FF"),
    ):
        decision = GUARD.check(payload)
        assert not decision.allowed, payload.hex()
        assert decision.rule == RULE_SHAPE, payload.hex()


def test_minimum_vector_set() -> None:
    """T2 minimum set of UDS vectors: at least 15 allow and 30 reject covering the table."""
    data = _load_vectors()
    assert data["schema"] == "obdb.guard-vectors/1"
    # Sections filled in by the adapter line layer must exist in the file.
    assert isinstance(data["lines"], list)
    assert isinstance(data["blacklist"], list)

    vectors = data["uds"]
    ids = [v["id"] for v in vectors]
    assert len(ids) == len(set(ids)), "vector identifiers must be unique"
    assert all(v["expect"] in {"allow", "reject"} for v in vectors)

    allows = [v for v in vectors if v["expect"] == "allow"]
    rejects = [v for v in vectors if v["expect"] == "reject"]
    assert len(allows) >= 15
    assert len(rejects) >= 30

    # Every row of the UdsGuard table has at least one `allow` vector.
    assert {v["rule"] for v in allows} == set(ALLOWED_RULES)
    assert len(ALLOWED_RULES) == 13

    # Every blocked SID from the T2 list has a `reject` vector with rule `UDS/sid`.
    rejected_sids = {
        bytes.fromhex(v["payload"])[0] for v in rejects if v["rule"] == RULE_SID and v["payload"]
    }
    missing = [f"0x{sid:02X}" for sid in BLOCKED_SIDS if sid not in rejected_sids]
    assert not missing, f"no reject vectors for SIDs: {missing}"

    # Items listed explicitly in the minimum set.
    by_payload = {v["payload"]: v for v in rejects}
    for payload_hex, rule in REQUIRED_REJECTS.items():
        assert payload_hex in by_payload, f"no reject vector {payload_hex!r}"
        assert by_payload[payload_hex]["rule"] == rule


def test_guard_has_no_options() -> None:
    """UdsGuard accepts no configuration parameters; the decision is immutable (FR-17)."""
    assert inspect.signature(UdsGuard).parameters == {}
    assert list(inspect.signature(UdsGuard.check).parameters) == ["self", "payload"]

    decision = GUARD.check(bytes.fromhex("22F187"))
    with pytest.raises(AttributeError):
        decision.allowed = False  # type: ignore[misc]
    with pytest.raises(TypeError):
        GUARD.check("22F187")  # type: ignore[arg-type]
