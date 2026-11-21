"""Tests of the ECU catalog: mock catalog file, `rx` rules, T7 validation and API (FR-21).

The tests use the synthetic catalog and module table from `tests/fixtures/mock/`;
`test_private_data.py` repeats the file checks against the local, unpublished
`defs/ecu-catalog.yaml` and `docs/moduly-obdeleven.md`.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from conftest import MOCK_CATALOG, MOCK_MODULES_DOC
from obd_bridge.errors import CatalogError
from obd_bridge.vag.catalog import (
    EcuCatalog,
    EcuTarget,
    NotAddressable,
    UnknownModule,
)

_ROW = re.compile(r"^\|\s*([0-9A-F]{2})\s*\|\s*([^|]+?)\s*\|")


def _obdeleven_modules(path: Path = MOCK_MODULES_DOC) -> dict[str, str]:
    """Returns a map from VAG address to name from the module table in `path`."""
    modules: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = _ROW.match(line)
        if match:
            modules[match.group(1)] = match.group(2)
    return modules


# Minimal valid catalog; validation cases replace text fragments in it.
_BASE_CATALOG = """\
schema: obdb.ecu-catalog/1
reply_offset: "06A"
default_timeout_ms: 300
sources:
  can_ids: "test"
modules:
  - address: "01"
    name: Engine
    protocol: uds
    tx: "7E0"
    rx: "7E8"
    fc: auto
    confidence: high
  - address: "19"
    name: Gateway
    protocol: uds
    tx: "710"
    fc: pair
    timeout_ms: 1500
    confidence: high
  - address: "05"
    name: Keyless System
    protocol: tp20
    confidence: medium
  - address: "06"
    name: Passenger Seat
    protocol: unknown
    confidence: low
"""

_EXTRA_UDS = """\
  - address: "{address}"
    name: Extra
    protocol: uds
    tx: "{tx}"
    fc: pair
    confidence: low
"""


def _write_catalog(directory: Path, text: str) -> Path:
    path = directory / "ecu-catalog.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def _replace_once(text: str, old: str, new: str) -> str:
    assert text.count(old) == 1, f"fragment {old!r} must occur exactly once"
    return text.replace(old, new)


def test_load_mock_catalog() -> None:
    catalog = EcuCatalog.load(MOCK_CATALOG)
    entries = catalog.entries()
    assert len(entries) == 14
    counts: dict[str, int] = {}
    for entry in entries:
        counts[entry.protocol] = counts.get(entry.protocol, 0) + 1
    assert counts == {"uds": 9, "tp20": 2, "kwp": 1, "unknown": 2}
    assert len(catalog.all_uds()) == 9
    assert all(entry.target is not None for entry in entries if entry.protocol == "uds")
    assert all(entry.target is None for entry in entries if entry.protocol != "uds")
    assert 0x7DF not in catalog.tx_ids() | catalog.rx_ids()
    assert catalog.get("6C").tx_id == 0x751
    assert {entry.address: entry.confidence for entry in entries}["6C"] == "low"
    for absent in ("0E", "10", "44", "56", "65", "82"):
        with pytest.raises(UnknownModule):
            catalog.get(absent)


def test_matches_obdeleven_doc() -> None:
    expected = _obdeleven_modules()
    assert len(expected) == 14
    catalog = EcuCatalog.load(MOCK_CATALOG)
    actual = {entry.address: entry.name for entry in catalog.entries()}
    assert actual == expected


def check_rx_rules(catalog: EcuCatalog) -> None:
    """`rx` rules and the OBD pair and gateway targets shared by the mock and the local catalog."""
    for target in catalog.all_uds():
        if target.fc_mode == "pair":
            assert target.rx_id == target.tx_id + 0x6A, target.vag_address
        else:
            assert target.vag_address in {"01", "02"}
            assert target.rx_id == target.tx_id + 8
    assert catalog.get("01") == EcuTarget("01", 0x7E0, 0x7E8, "auto", "uds", 300)
    assert catalog.get("02") == EcuTarget("02", 0x7E1, 0x7E9, "auto", "uds", 300)
    assert catalog.get("19") == EcuTarget("19", 0x710, 0x77A, "pair", "uds", 1500)
    assert catalog.get("03").timeout_ms == 300
    assert {t.timeout_ms for t in catalog.all_uds() if t.vag_address != "19"} == {300}


def test_rx_rules() -> None:
    check_rx_rules(EcuCatalog.load(MOCK_CATALOG))


_BEFORE_05 = "  - address: \"05\"\n"
_GATEWAY_TX = "    tx: \"710\"\n    fc: pair\n"


@pytest.mark.parametrize(
    ("old", "new", "match"),
    [
        pytest.param(
            _BEFORE_05, _EXTRA_UDS.format(address="07", tx="710") + _BEFORE_05,
            "tx 710 duplicated", id="duplicate-tx",
        ),
        pytest.param(
            _BEFORE_05, _EXTRA_UDS.format(address="07", tx="77E") + _BEFORE_05,
            "rx 7E8 duplicated", id="duplicate-rx",
        ),
        pytest.param(
            _BEFORE_05, _EXTRA_UDS.format(address="07", tx="77A") + _BEFORE_05,
            "tx 77A is also the rx", id="tx-equals-other-rx",
        ),
        pytest.param(
            _BEFORE_05, _EXTRA_UDS.format(address="19", tx="720") + _BEFORE_05,
            "duplicate address", id="duplicate-address",
        ),
        pytest.param("    tx: \"710\"\n", "    tx: \"7DF\"\n", "7DF", id="tx-7DF"),
        pytest.param("address: \"19\"", "address: 19", "quoted string", id="address-unquoted"),
        pytest.param("    tx: \"710\"\n", "    tx: 710\n", "quoted string", id="tx-number"),
        pytest.param(
            "    protocol: tp20\n", "    protocol: tp20\n    tx: \"720\"\n",
            "does not allow fields: tx", id="tx-with-tp20",
        ),
        pytest.param(
            "    protocol: unknown\n", "    protocol: unknown\n    timeout_ms: 500\n",
            "does not allow fields: timeout_ms", id="timeout-with-unknown",
        ),
        pytest.param(
            "    confidence: low\n", "    confidence: low\n    color: red\n",
            "unknown keys: color", id="unknown-module-key",
        ),
        pytest.param("sources:\n", "extra: 1\nsources:\n", "unknown keys: extra", id="unknown-top-key"),
        pytest.param("obdb.ecu-catalog/1", "obdb.ecu-catalog/2", "unsupported schema", id="wrong-schema"),
        pytest.param(_GATEWAY_TX, "    tx: \"710\"\n    fc: auto\n", "7E0..7E7", id="fc-auto-outside-7E0"),
        pytest.param("    rx: \"7E8\"\n", "    rx: \"7E9\"\n", "rx = tx \\+ 8", id="fc-auto-wrong-rx"),
        pytest.param(
            _GATEWAY_TX, "    tx: \"710\"\n    rx: \"77B\"\n    fc: pair\n",
            "rx = tx \\+ 0x6A", id="explicit-rx-mismatch",
        ),
        pytest.param("    tx: \"710\"\n", "    tx: \"6FF\"\n", "out of range", id="tx-out-of-range"),
        pytest.param("    tx: \"710\"\n", "    tx: \"71g\"\n", "3 upper-case hex digits", id="tx-not-hex"),
        pytest.param(_GATEWAY_TX, "    tx: \"710\"\n", "fc is required", id="missing-fc-with-tx"),
        pytest.param("    timeout_ms: 1500\n", "    timeout_ms: 0\n", "1..5000", id="timeout-zero"),
        pytest.param("address: \"06\"", "address: \"6\"", "2 upper-case hex digits", id="address-bad-format"),
        pytest.param("protocol: unknown", "protocol: can", "unknown value", id="unknown-protocol"),
        pytest.param("reply_offset: \"06A\"", "reply_offset: \"008\"", "reply_offset", id="wrong-reply-offset"),
    ],
)
def test_validation_rejects(tmp_path: Path, old: str, new: str, match: str) -> None:
    # Control: the base catalog and an explicit `rx` consistent with the rule are valid.
    assert EcuCatalog.load(_write_catalog(tmp_path, _BASE_CATALOG)).get("19").rx_id == 0x77A
    explicit_rx = _replace_once(_BASE_CATALOG, _GATEWAY_TX, "    tx: \"710\"\n    rx: \"77A\"\n    fc: pair\n")
    assert EcuCatalog.load(_write_catalog(tmp_path, explicit_rx)).get("19").rx_id == 0x77A
    path = _write_catalog(tmp_path, _replace_once(_BASE_CATALOG, old, new))
    with pytest.raises(CatalogError, match=match) as caught:
        EcuCatalog.load(path)
    assert caught.value.exit_code == 64


def test_missing_and_malformed_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    with pytest.raises(CatalogError) as caught:
        EcuCatalog.load()
    assert str(caught.value) == (
        "defs/ecu-catalog.yaml not found. Run obdb from the project directory."
    )
    broken = _write_catalog(tmp_path, "schema: [unclosed\n")
    with pytest.raises(CatalogError):
        EcuCatalog.load(broken)


def test_get_errors() -> None:
    catalog = EcuCatalog.load(MOCK_CATALOG)
    with pytest.raises(UnknownModule) as unknown:
        catalog.get("FF")
    assert isinstance(unknown.value, CatalogError)
    assert unknown.value.exit_code == 64
    for address in ("05", "47", "06", "85"):
        with pytest.raises(NotAddressable) as caught:
            catalog.get(address)
        assert isinstance(caught.value, CatalogError)
        assert caught.value.address == address


def test_id_sets() -> None:
    catalog = EcuCatalog.load(MOCK_CATALOG)
    tx_ids = catalog.tx_ids()
    rx_ids = catalog.rx_ids()
    assert isinstance(tx_ids, frozenset) and isinstance(rx_ids, frozenset)
    assert len(tx_ids) == 9 and len(rx_ids) == 9
    assert tx_ids.isdisjoint(rx_ids)
    assert {0x7E0, 0x7E1, 0x710} <= tx_ids
    assert {0x7E8, 0x7E9, 0x77A} <= rx_ids
    assert catalog.pair_of(0x710) == (0x710, 0x77A)
    assert catalog.pair_of(0x7E1) == (0x7E1, 0x7E9)
    assert catalog.pair_of(0x77A) is None
    assert catalog.pair_of(0x7DF) is None
