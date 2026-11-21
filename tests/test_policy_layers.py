"""Cross-cutting tests of the read-only policy layers.

No guard switch (FR-17) and the same UDS vectors in both guard layers
(FR-15, FR-16): `ReadOnlyUdsClient._checked` (layer `uds`) and
`StnDriver.transact` (layer `adapter`). The driver runs on a synthetic
transport with a write register; no test touches a port.
"""

from __future__ import annotations

import inspect
import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from udsoncan.client import Client

from conftest import MOCK_CATALOG
from obd_bridge.errors import ReadOnlyViolation
from obd_bridge.policy import ReadOnlyPolicy
from obd_bridge.policy.adapter_guard import AdapterCommandGuard
from obd_bridge.policy.uds_guard import UdsGuard
from obd_bridge.stn.driver import DriverState, StnDriver
from obd_bridge.traffic_log import TrafficLog, read_events
from obd_bridge.transport.null import NullTransport
from obd_bridge.uds.client import ReadOnlyUdsClient
from obd_bridge.uds.connection import ElmUdsConnection
from obd_bridge.vag.catalog import EcuCatalog

REPO_ROOT: Path = Path(__file__).resolve().parent.parent
SRC_DIR: Path = REPO_ROOT / "src" / "obd_bridge"
CATALOG: EcuCatalog = EcuCatalog.load(MOCK_CATALOG)
VECTORS: dict[str, Any] = json.loads(
    (REPO_ROOT / "tests" / "fixtures" / "guard_vectors.json").read_text(encoding="utf-8")
)
REJECT_VECTORS: list[dict[str, Any]] = [v for v in VECTORS["uds"] if v["expect"] == "reject"]

# Patterns forbidden in the sources: reading environment variables and guard switch names.
FORBIDDEN_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"os\.environ"),
    re.compile(r"\bgetenv\b"),
    re.compile(r"\benviron\b"),
    re.compile(r"(?i)(no|disable|skip|bypass|without|unsafe)[-_]?(guard|policy)"),
    re.compile(r"(?i)(guard|policy)[-_]?(off|disabled?|bypass|override)\b"),
    re.compile(r"(?i)--(unsafe|allow-write|force-write|no-guard)\b"),
)


def test_no_guard_switch() -> None:
    """The `ReadOnlyPolicy` constructor accepts only the catalog; the sources have no guard switch."""
    params = list(inspect.signature(ReadOnlyPolicy.__init__).parameters)
    assert params == ["self", "catalog"]
    assert list(inspect.signature(UdsGuard).parameters) == []
    assert list(inspect.signature(AdapterCommandGuard).parameters) == []

    sources = sorted(SRC_DIR.rglob("*.py"))
    assert sources, "no package sources"
    offenders: list[str] = []
    for path in sources:
        text = path.read_text(encoding="utf-8")
        for number, line in enumerate(text.splitlines(), start=1):
            for pattern in FORBIDDEN_PATTERNS:
                if pattern.search(line):
                    offenders.append(f"{path.relative_to(SRC_DIR)}:{number}: {line.strip()}")
    assert not offenders, "forbidden constructs (FR-17):\n" + "\n".join(offenders)



# -- FR-16: the same UDS vectors in both layers -----------------------------------


class RecordingTransport(NullTransport):
    """`NullTransport` with a register of all written bytes."""

    def __init__(self) -> None:
        super().__init__()
        self.writes: list[bytes] = []

    def write(self, data: bytes) -> None:
        self.writes.append(bytes(data))
        super().write(data)


@pytest.fixture
def gateway(project_dir: Path) -> Iterator[tuple[StnDriver, RecordingTransport, TrafficLog]]:
    """Driver in state TARGET_SELECTED (target 19) on a recording transport."""
    log = TrafficLog.create("probe-dry-run", root=project_dir)
    log.session_start({"commit": None})
    transport = RecordingTransport()
    driver = StnDriver(transport, ReadOnlyPolicy(CATALOG), log, clock=lambda: 0.0, sleep=lambda _: None)
    driver.open()
    driver.warm_start()
    driver.set_format()
    driver.identify(None)
    driver.open_protocol()
    driver.select_target(CATALOG.get("19"))
    assert driver.state is DriverState.TARGET_SELECTED
    yield driver, transport, log
    log.close()


def test_uds_vectors_via_client(
    gateway: tuple[StnDriver, RecordingTransport, TrafficLog], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every `reject` vector: `ReadOnlyViolation` in `_checked` before udsoncan and the driver."""
    driver, transport, log = gateway
    calls: list[str] = []

    def spy(name: str) -> Any:
        def record(*_: Any, **__: Any) -> None:
            calls.append(name)
            raise AssertionError(f"rejected payload reached {name}")

        return record

    monkeypatch.setattr(Client, "send_request", spy("Client.send_request"))
    monkeypatch.setattr(ElmUdsConnection, "send", spy("ElmUdsConnection.send"))
    monkeypatch.setattr(driver, "transact", spy("StnDriver.transact"))
    client = ReadOnlyUdsClient(ElmUdsConnection(driver), ReadOnlyPolicy(CATALOG))
    writes_before = len(transport.writes)
    guards_before = len([e for e in read_events(log.path) if e["ev"] == "guard"])
    assert REJECT_VECTORS

    for vector in REJECT_VECTORS:
        payload = bytes.fromhex(vector["payload"])
        with pytest.raises(ReadOnlyViolation) as caught:
            client._checked(payload)
        assert caught.value.layer == "uds", vector["id"]
        assert caught.value.rule == vector["rule"], vector["id"]
        assert caught.value.exit_code == 2

    assert calls == []
    assert len(transport.writes) == writes_before
    events = read_events(log.path)
    guards = [e for e in events if e["ev"] == "guard"][guards_before:]
    expected = [("uds", v["payload"].upper()) for v in REJECT_VECTORS]
    assert [(e["layer"], e["data"]) for e in guards] == expected
    assert all(e["guard"]["decision"] == "rejected" for e in guards)
    assert [e["guard"]["rule"] for e in guards] == [v["rule"] for v in REJECT_VECTORS]
    assert all(e["ecu"] == "19" for e in guards)
    assert not [e for e in events if e["ev"] == "uds"]


def test_uds_vectors_via_driver(gateway: tuple[StnDriver, RecordingTransport, TrafficLog]) -> None:
    """The same vectors as the `D:` field through `StnDriver.transact`: zero bytes in the transport."""
    driver, transport, log = gateway
    writes_before = len(transport.writes)
    guards_before = len([e for e in read_events(log.path) if e["ev"] == "guard"])

    for vector in REJECT_VECTORS:
        with pytest.raises(ReadOnlyViolation) as caught:
            driver.transact(bytes.fromhex(vector["payload"]))
        assert caught.value.layer == "adapter", vector["id"]
        assert caught.value.subject.startswith("STPX "), vector["id"]

    assert len(transport.writes) == writes_before
    guards = [e for e in read_events(log.path) if e["ev"] == "guard"][guards_before:]
    assert len(guards) == len(REJECT_VECTORS)
    assert all(e["layer"] == "adapter" and e["guard"]["decision"] == "rejected" for e in guards)
    # A `D:` field of length 1..8 B is evaluated by UdsGuard (`LINE/uds` with `uds_rule`); an empty
    # payload and a payload longer than 8 B are already rejected by the allowlist syntax (`LINE/no-match`).
    expected = [
        ("LINE/uds", v["rule"]) if 1 <= len(v["payload"]) // 2 <= 8 else ("LINE/no-match", None)
        for v in REJECT_VECTORS
    ]
    assert [(e["guard"]["rule"], e["meta"].get("uds_rule")) for e in guards] == expected
    assert all(f"D:{v['payload'].upper()}," in e["data"] for v, e in zip(REJECT_VECTORS, guards, strict=True))
    assert driver.state is DriverState.TARGET_SELECTED
