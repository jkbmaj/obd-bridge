"""Checks of the local, unpublished data files (`defs/ecu-catalog.yaml`, `docs/`).

The rest of the suite runs on the synthetic data from `tests/fixtures/mock/`.
These tests repeat the file checks against the real module catalog and the
OBDeleven documents. The directories `defs/` and `docs/` are not part of the
repository, so on a clean clone every test here is skipped with a reason.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from conftest import (
    PRIVATE_CATALOG,
    PRIVATE_DIDS_DOC,
    PRIVATE_MODULES_DOC,
)
from obd_bridge.probe.plan import NOX_DIDS, build_steps, plan_totals
from obd_bridge.vag.catalog import EcuCatalog, NotAddressable, UnknownModule
from test_catalog import _obdeleven_modules, check_rx_rules
from test_probe_plan import _doc_nox_dids


def _requires(*paths: Path) -> pytest.MarkDecorator:
    missing = [str(path.relative_to(path.parents[1])) for path in paths if not path.is_file()]
    return pytest.mark.skipif(
        bool(missing),
        reason=f"local private data not present: {', '.join(missing)} (not part of the repository)",
    )


requires_catalog = _requires(PRIVATE_CATALOG)
requires_catalog_and_modules_doc = _requires(PRIVATE_CATALOG, PRIVATE_MODULES_DOC)
requires_dids_doc = _requires(PRIVATE_DIDS_DOC)


@requires_catalog
def test_private_catalog_loads() -> None:
    """Structural invariants only; the published test does not reveal the catalog contents."""
    catalog = EcuCatalog.load(PRIVATE_CATALOG)
    entries = catalog.entries()
    assert entries
    uds = [entry for entry in entries if entry.protocol == "uds"]
    assert len(catalog.all_uds()) == len(uds)
    assert len(catalog.tx_ids()) == len(uds) and len(catalog.rx_ids()) == len(uds)
    assert catalog.tx_ids().isdisjoint(catalog.rx_ids())
    assert all(entry.target is not None for entry in uds)
    assert all(entry.target is None for entry in entries if entry.protocol != "uds")
    assert 0x7DF not in catalog.tx_ids() | catalog.rx_ids()
    for entry in entries:
        if entry.protocol == "uds":
            assert catalog.get(entry.address) is not None
        else:
            with pytest.raises(NotAddressable):
                catalog.get(entry.address)
    known = {entry.address for entry in entries}
    absent = next(f"{value:02X}" for value in range(256) if f"{value:02X}" not in known)
    with pytest.raises(UnknownModule):
        catalog.get(absent)


@requires_catalog_and_modules_doc
def test_private_catalog_matches_obdeleven_doc() -> None:
    expected = _obdeleven_modules(PRIVATE_MODULES_DOC)
    assert expected
    catalog = EcuCatalog.load(PRIVATE_CATALOG)
    actual = {entry.address: entry.name for entry in catalog.entries()}
    assert actual == expected


@requires_catalog
def test_private_catalog_rx_rules() -> None:
    check_rx_rules(EcuCatalog.load(PRIVATE_CATALOG))


@requires_catalog
def test_private_catalog_builds_probe_plan() -> None:
    """The probe plan built from the local catalog has the same shape as the one built from the mock."""
    totals = plan_totals(build_steps(EcuCatalog.load(PRIVATE_CATALOG)))
    assert (totals.steps, totals.lines, totals.stpx) == (25, 335, 211)


@requires_dids_doc
def test_private_nox_dids_match_doc() -> None:
    doc = _doc_nox_dids(PRIVATE_DIDS_DOC)
    assert len(doc) == 26
    assert list(NOX_DIDS) == doc
