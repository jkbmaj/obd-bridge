"""Tests of the L1 driver `StnDriver` (spec T4, FR-07 to FR-10).

Every test uses `ScriptedTransport` (a queue of writes and replies in wire
order) and a real `TrafficLog` in a temporary project directory. The clock
and `sleep` are fake, so the rate limit does not slow the tests down.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from conftest import MOCK_CATALOG
from obd_bridge.errors import AdapterError, ReadOnlyViolation, TransportTimeout
from obd_bridge.policy import ReadOnlyPolicy
from obd_bridge.stn.driver import (
    FORMAT_LINES,
    NRC78_TOTAL_LIMIT_S,
    OPEN_PROTOCOL_LINES,
    RULE_ADAPTER_RESET,
    RULE_FC_UNAVAILABLE,
    RULE_PENDING,
    STPX_DRAIN_TIMEOUT_S,
    AdapterQuery,
    DriverError,
    DriverState,
    FcAttempt,
    FcStrategy,
    ProbeCommand,
    StnDriver,
    StpxTimeout,
    stpx_line,
    stpx_uart_timeout_s,
    target_select_lines,
)
from obd_bridge.stn.parser import ExchangeOutcome
from obd_bridge.stn.profile import AdapterProfile
from obd_bridge.traffic_log import TrafficLog, read_events
from obd_bridge.vag.catalog import EcuCatalog

CATALOG: EcuCatalog = EcuCatalog.load(MOCK_CATALOG)
GATEWAY = CATALOG.get("19")
ENGINE = CATALOG.get("01")
GEARBOX = CATALOG.get("02")

OK = "OK\r\r>"
QM = "?\r\r>"
NO_DATA = "NO DATA\r\r>"
GW_F187 = "77A100E62F187344730\r77A2139303734363841\r77A2220000000000000\r\r>"


class FakeClock:
    """Monotonic clock driven by the test; `sleep` advances the time."""

    def __init__(self) -> None:
        self.now = 100.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


@pytest.fixture
def log(project_dir: Path) -> Iterator[TrafficLog]:
    traffic = TrafficLog.create("probe", root=project_dir)
    traffic.session_start({"commit": None})
    yield traffic
    traffic.close()


@pytest.fixture
def make_driver(
    log: TrafficLog, scripted_transport: type
) -> Callable[..., tuple[StnDriver, Any, FakeClock]]:
    def factory() -> tuple[StnDriver, Any, FakeClock]:
        clock = FakeClock()
        transport = scripted_transport()
        driver = StnDriver(transport, ReadOnlyPolicy(CATALOG), log, clock=clock, sleep=clock.sleep)
        return driver, transport, clock

    return factory


def events(log: TrafficLog, ev: str | None = None, layer: str | None = None) -> list[dict[str, Any]]:
    found = read_events(log.path)
    return [e for e in found if (ev is None or e["ev"] == ev) and (layer is None or e["layer"] == layer)]


def transitions(log: TrafficLog) -> list[tuple[str, str | None, str, str | None]]:
    return [
        (e["meta"]["prev_state"], e["meta"]["prev_target"], e["meta"]["state"], e["meta"]["target"])
        for e in events(log, "state")
    ]


def script_init(transport: Any) -> None:
    transport.banner(None)
    transport.expect("ATWS", "ATWS\r\rELM327 v1.3a\r\r>")
    for line in FORMAT_LINES:
        transport.expect(line, OK)
    transport.expect("STI", "STN2120 v4.5.0\r\r>")
    transport.expect("STDI", "STN2120 r1.0\r\r>")


def script_protocol(transport: Any) -> None:
    for line in OPEN_PROTOCOL_LINES:
        transport.expect(line, OK)


def script_select(transport: Any, lines: tuple[str, ...]) -> None:
    for line in lines:
        transport.expect(line, OK)


def run_init(driver: StnDriver, profile: AdapterProfile | None = None) -> None:
    driver.open()
    driver.warm_start()
    driver.set_format()
    driver.identify(profile)


def bring_to(make_driver: Callable[..., Any], stage: str) -> tuple[StnDriver, Any, FakeClock]:
    """Driver in the RAW, READY, PROTOCOL_OPEN or TARGET_SELECTED state (target 19, `st_pairs`)."""
    driver, transport, clock = make_driver()
    if stage == "RAW":
        transport.banner(None)
        driver.open()
        return driver, transport, clock
    script_init(transport)
    if stage in ("PROTOCOL_OPEN", "TARGET_SELECTED"):
        script_protocol(transport)
    if stage == "TARGET_SELECTED":
        script_select(transport, target_select_lines(GATEWAY, FcStrategy.ST_PAIRS))
    run_init(driver)
    if stage in ("PROTOCOL_OPEN", "TARGET_SELECTED"):
        driver.open_protocol()
    if stage == "TARGET_SELECTED":
        driver.select_target(GATEWAY)
    assert driver.state is DriverState(stage)
    assert transport.remaining == 0
    return driver, transport, clock


def profile_with(strategy: FcStrategy | None) -> AdapterProfile:
    return AdapterProfile(
        sti="STN2120 v4.5.0",
        stdi="STN2120 r1.0",
        commands={},
        fc_strategy=strategy,
        nrc78_mode="unknown",
        timing={},
        source="test",
    )


# ---------------------------------------------------------------------------


def test_init_sequences(make_driver: Callable[..., Any], log: TrafficLog) -> None:
    assert FORMAT_LINES == ("ATE0", "ATL0", "ATS0", "ATH1")
    assert OPEN_PROTOCOL_LINES == ("STP33", "ATCAF1", "ATCFC1", "ATFCSM0", "ATAL", "ATAT1", "STPTO300")

    driver, transport, _ = make_driver()
    script_init(transport)
    script_protocol(transport)

    assert driver.open() is None
    assert driver.state is DriverState.RAW
    assert transport.opened and transport.reset_count == 1
    assert transport.read_timeouts == [1.0]
    reply = driver.warm_start()
    assert "ELM327 v1.3a" in reply.lines
    assert len(driver.set_format()) == 4
    info = driver.identify(None)
    assert (info.sti, info.stdi, info.elm) == ("STN2120 v4.5.0", "STN2120 r1.0", "ELM327 v1.3a")
    assert info.banner is None
    assert driver.state is DriverState.READY
    driver.open_protocol()
    assert driver.state is DriverState.PROTOCOL_OPEN

    assert transport.written_lines == ["ATWS", *FORMAT_LINES, "STI", "STDI", *OPEN_PROTOCOL_LINES]
    assert transport.read_timeouts[1] == 5.0
    assert set(transport.read_timeouts[2:]) == {2.0}
    assert transitions(log) == [
        ("CLOSED", None, "RAW", None),
        ("RAW", None, "READY", None),
        ("READY", None, "PROTOCOL_OPEN", None),
    ]
    banner_rx = events(log, "rx", "transport")[0]
    assert banner_rx["data"] == "" and banner_rx["meta"]["timeout"] is True
    first_state = next(i for i, e in enumerate(events(log)) if e["ev"] == "state")
    first_tx = next(i for i, e in enumerate(events(log)) if e["ev"] == "tx")
    assert first_state < first_tx

    # identify without warm_start and set_format: AdapterError without writing bytes.
    other, other_transport, _ = make_driver()
    other_transport.banner("ELM327 v1.3a\r\r>")
    assert other.open() == "ELM327 v1.3a"
    with pytest.raises(AdapterError):
        other.identify()
    assert other_transport.writes == []
    assert other.state is DriverState.RAW


@pytest.mark.parametrize(
    ("stage", "call", "error"),
    [
        ("RAW", lambda d: d.open_protocol(), AdapterError),
        ("RAW", lambda d: d.probe_command(ProbeCommand.STCSEGR0), AdapterError),
        ("PROTOCOL_OPEN", lambda d: d.probe_command(ProbeCommand.STFFCC), AdapterError),
        ("PROTOCOL_OPEN", lambda d: d.transact(b"\x22\xf1\x87"), AdapterError),
        ("READY", lambda d: d.transact(b"\x22\xf1\x87"), AdapterError),
        ("PROTOCOL_OPEN", lambda d: d.set_rx_segmentation(True), AdapterError),
        ("READY", lambda d: d.select_target(GATEWAY), AdapterError),
        ("READY", lambda d: d.query("ATZ"), TypeError),
        ("TARGET_SELECTED", lambda d: d.transact("22F187"), TypeError),
    ],
    ids=[
        "open_protocol-RAW",
        "probe_command-RAW",
        "probe_command-P",
        "transact-P",
        "transact-READY",
        "set_rx_segmentation-P",
        "select_target-READY",
        "query-str",
        "transact-str",
    ],
)
def test_forbidden_transitions(
    make_driver: Callable[..., Any],
    stage: str,
    call: Callable[[StnDriver], Any],
    error: type[Exception],
) -> None:
    driver, transport, _ = bring_to(make_driver, stage)
    writes_before = len(transport.writes)
    with pytest.raises(error):
        call(driver)
    assert len(transport.writes) == writes_before
    assert driver.state is DriverState(stage)


FC_CASES: list[dict[str, Any]] = [
    {
        "id": "st_pairs",
        "profile": None,
        "fc": [("STCFCPA710,77A", OK), ("STFFCA77A,7FF", OK)],
        "strategy": FcStrategy.ST_PAIRS,
        "error": None,
    },
    {
        "id": "legacy-after-qm",
        "profile": None,
        "fc": [("STCFCPA710,77A", QM), ("STCAFCP710,77A", OK), ("STFAFC77A,7FF", OK)],
        "strategy": FcStrategy.ST_PAIRS_LEGACY,
        "error": None,
    },
    {
        "id": "elm-after-qm",
        "profile": None,
        "fc": [
            ("STCFCPA710,77A", OK),
            ("STFFCA77A,7FF", QM),
            ("STCAFCP710,77A", QM),
            ("ATFCSH710", OK),
            ("ATFCSD300000", OK),
            ("ATFCSM1", OK),
        ],
        "strategy": FcStrategy.ELM_FALLBACK,
        "error": None,
    },
    {
        "id": "all-qm",
        "profile": None,
        "fc": [("STCFCPA710,77A", QM), ("STCAFCP710,77A", QM), ("ATFCSH710", QM)],
        "strategy": None,
        "error": RULE_FC_UNAVAILABLE,
    },
    {
        "id": "profile-first",
        "profile": FcStrategy.ST_PAIRS_LEGACY,
        "fc": [("STCAFCP710,77A", OK), ("STFAFC77A,7FF", OK)],
        "strategy": FcStrategy.ST_PAIRS_LEGACY,
        "error": None,
    },
    {
        "id": "profile-elm-then-pairs",
        "profile": FcStrategy.ELM_FALLBACK,
        "fc": [("ATFCSH710", QM), ("STCFCPA710,77A", OK), ("STFFCA77A,7FF", OK)],
        "strategy": FcStrategy.ST_PAIRS,
        "error": None,
    },
    {
        # Established strategy: `?` for the next target gives an error without trying other strategies.
        "id": "established-no-retry",
        "profile": None,
        "fc": [("STCFCPA710,77A", OK), ("STFFCA77A,7FF", OK)],
        "strategy": FcStrategy.ST_PAIRS,
        "error": None,
        "then": [("ATSH7E1", OK), ("ATCRA7E9", OK), ("STCFCPA7E1,7E9", QM)],
    },
]


@pytest.mark.parametrize("case", FC_CASES, ids=[c["id"] for c in FC_CASES])
def test_fc_strategy_selection(
    make_driver: Callable[..., Any], log: TrafficLog, case: dict[str, Any]
) -> None:
    driver, transport, _ = make_driver()
    script_init(transport)
    script_protocol(transport)
    transport.expect("ATSH710", OK).expect("ATCRA77A", OK)
    for line, reply in case["fc"]:
        transport.expect(line, reply)
    profile = profile_with(case["profile"]) if case["profile"] is not None else None
    run_init(driver, profile)
    driver.open_protocol()

    if case["error"] is None:
        driver.select_target(GATEWAY)
        assert driver.state is DriverState.TARGET_SELECTED
        assert driver.fc_applied is True
    else:
        with pytest.raises(DriverError) as caught:
            driver.select_target(GATEWAY)
        assert caught.value.rule == case["error"]
        assert driver.state is DriverState.PROTOCOL_OPEN
        assert driver.target == GATEWAY
        assert driver.fc_applied is False
        with pytest.raises(AdapterError):
            driver.transact(b"\x22\xf1\x87")
    fc_steps = list(case["fc"])
    if "then" in case:
        for line, reply in case["then"]:
            transport.expect(line, reply)
        with pytest.raises(DriverError) as again:
            driver.select_target(GEARBOX)
        assert again.value.rule != RULE_FC_UNAVAILABLE
        assert transport.written_lines[-3:] == [line for line, _ in case["then"]]
        assert driver.state is DriverState.PROTOCOL_OPEN and driver.target == GEARBOX
        fc_steps.append(case["then"][-1])
    assert transport.remaining == 0
    assert driver.fc_strategy == case["strategy"]
    expected_attempts = [(line, "unsupported" if reply == QM else "ok") for line, reply in fc_steps]
    assert [(a.line, a.result) for a in driver.fc_attempts] == expected_attempts
    assert all(isinstance(a, FcAttempt) for a in driver.fc_attempts)
    assert {a.target for a in driver.fc_attempts[: len(case["fc"])]} == {"19"}
    # The pair always before the filter.
    lines = transport.written_lines
    for pair, flt in (("STCFCPA710,77A", "STFFCA77A,7FF"), ("STCAFCP710,77A", "STFAFC77A,7FF")):
        if flt in lines:
            assert pair in lines and lines.index(pair) < lines.index(flt)


def test_fc_rules_per_target(make_driver: Callable[..., Any], log: TrafficLog) -> None:
    driver, transport, _ = make_driver()
    script_init(transport)
    script_protocol(transport)
    sequence = [
        (ENGINE, ("ATSH7E0", "ATCRA7E8")),
        (GATEWAY, ("ATSH710", "ATCRA77A", "STCFCPA710,77A", "STFFCA77A,7FF")),
        (ENGINE, ("ATSH7E0", "ATCRA7E8", "STCFCPA7E0,7E8", "STFFCA7E8,7FF")),
        (GATEWAY, ("ATSH710", "ATCRA77A")),
    ]
    for _, lines in sequence:
        script_select(transport, lines)
    run_init(driver)
    driver.open_protocol()
    for target, lines in sequence:
        expected = target_select_lines(target, FcStrategy.ST_PAIRS, driver.fc_applied, driver.fc_configured)
        assert expected == lines
        before = len(transport.writes)
        driver.select_target(target)
        assert tuple(transport.written_lines[before:]) == lines
        assert driver.state is DriverState.TARGET_SELECTED and driver.target == target
    assert transport.remaining == 0
    assert driver.fc_configured == {0x710, 0x7E0}
    assert transitions(log)[3:] == [
        ("PROTOCOL_OPEN", None, "PROTOCOL_OPEN", "01"),
        ("PROTOCOL_OPEN", "01", "TARGET_SELECTED", "01"),
        ("TARGET_SELECTED", "01", "PROTOCOL_OPEN", "19"),
        ("PROTOCOL_OPEN", "19", "TARGET_SELECTED", "19"),
        ("TARGET_SELECTED", "19", "PROTOCOL_OPEN", "01"),
        ("PROTOCOL_OPEN", "01", "TARGET_SELECTED", "01"),
        ("TARGET_SELECTED", "01", "PROTOCOL_OPEN", "19"),
        ("PROTOCOL_OPEN", "19", "TARGET_SELECTED", "19"),
    ]

    # elm_fallback: the full set of FC lines on every select_target.
    elm, elm_transport, _ = make_driver()
    script_init(elm_transport)
    script_protocol(elm_transport)
    elm_sequence = [
        (GATEWAY, ("ATSH710", "ATCRA77A", "ATFCSH710", "ATFCSD300000", "ATFCSM1")),
        (GATEWAY, ("ATSH710", "ATCRA77A", "ATFCSH710", "ATFCSD300000", "ATFCSM1")),
        (ENGINE, ("ATSH7E0", "ATCRA7E8", "ATFCSH7E0", "ATFCSD300000", "ATFCSM1")),
    ]
    for _, lines in elm_sequence:
        script_select(elm_transport, lines)
    run_init(elm, profile_with(FcStrategy.ELM_FALLBACK))
    elm.open_protocol()
    for target, lines in elm_sequence:
        before = len(elm_transport.writes)
        elm.select_target(target)
        assert tuple(elm_transport.written_lines[before:]) == lines
    assert elm.fc_strategy is FcStrategy.ELM_FALLBACK
    assert elm.fc_configured == frozenset()
    assert elm_transport.remaining == 0


def test_transact_line_and_timeout(make_driver: Callable[..., Any], log: TrafficLog) -> None:
    assert stpx_line(GATEWAY, b"\x22\xf1\x87") == "STPX H:710,D:22F187,R:1,T:1500"
    assert stpx_line(GATEWAY, b"\x22\xf1\x87", 300) == "STPX H:710,D:22F187,R:1"
    assert stpx_line(ENGINE, b"\x22\xf1\x87") == "STPX H:7E0,D:22F187,R:1"
    assert stpx_line(ENGINE, b"\x19\x02\xff", 5000) == "STPX H:7E0,D:1902FF,R:1,T:5000"
    assert stpx_uart_timeout_s(300) == pytest.approx(5.8)
    assert stpx_uart_timeout_s(1500) == pytest.approx(7.0)
    assert stpx_uart_timeout_s(5000) == pytest.approx(10.5)

    driver, transport, _ = bring_to(make_driver, "TARGET_SELECTED")
    transport.expect("STPX H:710,D:22F187,R:1,T:1500", GW_F187)
    transport.expect("STPX H:710,D:22F187,R:1", NO_DATA)
    transport.expect(
        "STPX H:710,D:22F1A3,R:1,T:5000",
        "7E80662F1A3010203\r77A0662F1A348303155\r\r>",
    )
    reads_before = len(transport.read_timeouts)
    writes_before = len(transport.writes)

    positive = driver.transact(b"\x22\xf1\x87")
    assert positive.outcome is ExchangeOutcome.POSITIVE
    assert positive.final == bytes.fromhex("62F1873447303930373436384120")
    no_data = driver.transact(b"\x22\xf1\x87", timeout_ms=300)
    assert no_data.outcome is ExchangeOutcome.NO_DATA
    foreign = driver.transact(b"\x22\xf1\xa3", timeout_ms=5000)
    assert foreign.outcome is ExchangeOutcome.POSITIVE and len(foreign.foreign_frames) == 1

    # One write call per transact (no retries, also on NO DATA).
    assert len(transport.writes) - writes_before == 3
    assert transport.read_timeouts[reads_before:] == pytest.approx([7.0, 5.8, 10.5])
    assert transport.remaining == 0

    adapter_rx = [e for e in events(log, "rx", "adapter") if e["data"].startswith(("7E8", "77A0662"))]
    assert [e["meta"].get("foreign", False) for e in adapter_rx] == [True, False]
    stpx_tx = [e for e in events(log, "tx", "adapter") if e["data"].startswith("STPX")]
    assert [e["guard"]["decision"] for e in stpx_tx] == ["allowed"] * 3
    assert {e["ecu"] for e in stpx_tx} == {"19"}


def test_elapsed_ms_resolution(make_driver: Callable[..., Any], log: TrafficLog) -> None:
    """`elapsed_ms` has 0.1 ms resolution in the exchange, in the driver and in the `rx` event (spec T9)."""
    driver, transport, clock = bring_to(make_driver, "TARGET_SELECTED")
    transport.expect("STPX H:710,D:22F187,R:1,T:1500", GW_F187)
    original_read = transport.read_until

    def slow_read(marker: bytes, timeout_s: float) -> bytes:
        clock.now += 0.03424  # 34.24 ms from write to `>`
        return original_read(marker, timeout_s)

    transport.read_until = slow_read
    exchange = driver.transact(b"\x22\xf1\x87")
    assert exchange.elapsed_ms == pytest.approx(34.2)
    assert isinstance(exchange.elapsed_ms, float)
    assert driver.last_elapsed_ms == exchange.elapsed_ms
    rx = events(log, "rx", "transport")[-1]
    assert rx["meta"]["elapsed_ms"] == pytest.approx(34.2)


def test_rate_limit(make_driver: Callable[..., Any]) -> None:
    driver, transport, clock = make_driver()
    script_init(transport)
    prompt_times: list[float] = []
    write_times: list[float] = []
    original_read = transport.read_until
    original_write = transport.write

    def read_until(marker: bytes, timeout_s: float) -> bytes:
        try:
            return original_read(marker, timeout_s)
        finally:
            prompt_times.append(clock.now)

    def write(data: bytes) -> None:
        write_times.append(clock.now)
        original_write(data)

    transport.read_until = read_until
    transport.write = write
    driver.open()
    driver.warm_start()  # ATWS right after the banner window: the full 10 ms
    clock.now += 0.004  # 4 ms gap: ATE0 still waits 6 ms
    driver.set_format()
    clock.now += 0.050  # 50 ms gap: STI without waiting
    driver.identify()

    assert len(write_times) == 7
    # prompt_times[0] is the end of the banner window; write i follows read i.
    for index, written in enumerate(write_times):
        assert written - prompt_times[index] >= 0.010 - 1e-9
    assert clock.sleeps == pytest.approx([0.010, 0.006, 0.010, 0.010, 0.010, 0.010])


def _interrupt_next_read(transport: Any) -> None:
    """The next `read_until` raises `KeyboardInterrupt` without consuming a script step."""
    original = transport.read_until
    armed = [True]

    def read_until(marker: bytes, timeout_s: float) -> bytes:
        if armed[0]:
            armed[0] = False
            transport.read_timeouts.append(timeout_s)
            raise KeyboardInterrupt
        return original(marker, timeout_s)

    transport.read_until = read_until


STPX_5000 = "STPX H:710,D:22F187,R:1,T:5000"


@pytest.mark.parametrize(
    "scenario",
    [
        "stpc-RAW",
        "stpc-READY",
        "stpc-PROTOCOL_OPEN",
        "stpc-TARGET_SELECTED",
        "after-transport-error",
        "transport-timeout",
        "drain-ok",
        "drain-failed",
    ],
)
def test_close_semantics(make_driver: Callable[..., Any], log: TrafficLog, scenario: str) -> None:
    if scenario.startswith("stpc-"):
        stage = scenario.removeprefix("stpc-")
        driver, transport, _ = bring_to(make_driver, stage)
        stpc = stage in ("PROTOCOL_OPEN", "TARGET_SELECTED")
        if stpc:
            transport.expect("STPC", OK)
        before = len(transport.writes)
        driver.close()
        assert transport.written_lines[before:] == (["STPC"] if stpc else [])
    elif scenario == "after-transport-error":
        driver, transport, _ = bring_to(make_driver, "TARGET_SELECTED")
        before = len(transport.writes)
        driver.close(after_transport_error=True)
        assert len(transport.writes) == before
    elif scenario == "transport-timeout":
        driver, transport, _ = bring_to(make_driver, "TARGET_SELECTED")
        transport.expect("STPX H:710,D:22F187,R:1,T:1500", "77A100E", timeout=True)
        transport.read(b"", timeout=True)  # finishing the read up to `>` without success
        with pytest.raises(TransportTimeout):
            driver.transact(b"\x22\xf1\x87")
        timeout_rx = events(log, "rx", "transport")[-2]
        assert timeout_rx["meta"]["timeout"] is True and timeout_rx["data"] == "77A100E"
        assert events(log, "rx", "transport")[-1]["meta"].get("drain") is True
        assert events(log, "error", "transport")
        assert driver.transport_failed is True
        before = len(transport.writes)
        driver.close()  # transport error in the session: no line even without the flag
        assert len(transport.writes) == before
    elif scenario == "drain-ok":
        driver, transport, _ = bring_to(make_driver, "TARGET_SELECTED")
        transport.expect(STPX_5000, NO_DATA).expect("STPC", OK)
        _interrupt_next_read(transport)
        with pytest.raises(KeyboardInterrupt):
            driver.transact(b"\x22\xf1\x87", timeout_ms=5000)
        driver.close()
        # Interrupted read, finish with the timeout of the current command, then STPC.
        assert transport.read_timeouts[-3:] == pytest.approx([10.5, 10.5, 2.0])
        assert transport.written_lines[-2:] == [STPX_5000, "STPC"]
        assert events(log, "rx", "transport")[-2]["meta"].get("drain") is True
    else:
        driver, transport, _ = bring_to(make_driver, "TARGET_SELECTED")
        transport.expect(STPX_5000, b"", timeout=True)
        _interrupt_next_read(transport)
        with pytest.raises(KeyboardInterrupt):
            driver.transact(b"\x22\xf1\x87", timeout_ms=5000)
        driver.close()
        assert transport.read_timeouts[-2:] == pytest.approx([10.5, 10.5])
        assert transport.written_lines[-1] == STPX_5000  # no STPC
    assert transport.remaining == 0
    assert transport.closed and driver.state is DriverState.CLOSED
    assert transitions(log)[-1][2:] == ("CLOSED", None)


def test_model_and_guard_on_egress(make_driver: Callable[..., Any], log: TrafficLog) -> None:
    # Model updated only after OK.
    driver, transport, _ = make_driver()
    transport.banner(None)
    transport.expect("ATWS", "ATWS\r\rELM327 v1.3a\r\r>")
    transport.expect("ATE0", "ATE0\rOK\r\r>")
    transport.expect("ATL0", QM)
    driver.open()
    driver.warm_start()
    with pytest.raises(DriverError):
        driver.set_format()
    assert driver.adapter.format_ok == frozenset({"ATE0"})
    assert transport.remaining == 0

    selected, sel_transport, _ = bring_to(make_driver, "TARGET_SELECTED")
    model = selected.adapter
    assert (model.protocol_open, model.caf1, model.fcsm) == (True, True, 0)
    assert (model.header, model.cra) == (0x710, 0x77A)
    assert (0x710, 0x77A) in model.pairs and 0x77A in model.fc_filters
    assert model.check_stpx(GATEWAY) is None

    # Line rejected by the guard: ReadOnlyViolation, guard event, zero bytes.
    guard_before = len(events(log, "guard"))
    writes_before = len(sel_transport.writes)
    with pytest.raises(ReadOnlyViolation) as caught:
        selected.transact(b"\x2e\xf1\x87\x00")
    assert caught.value.layer == "adapter" and caught.value.rule == "LINE/uds"
    with pytest.raises(ReadOnlyViolation) as empty:
        selected.transact(b"")
    assert empty.value.rule == "LINE/no-match"
    assert len(sel_transport.writes) == writes_before
    guards = events(log, "guard")[guard_before:]
    assert [g["layer"] for g in guards] == ["adapter", "adapter"]
    assert guards[0]["data"] == "STPX H:710,D:2EF18700,R:1,T:1500"
    assert guards[0]["guard"]["decision"] == "rejected" and guards[0]["guard"]["rule"] == "LINE/uds"
    assert not any(e["data"].startswith("STPX H:710,D:2E") for e in events(log, "tx"))
    assert selected.adapter is model

    # Queries from the closed set go through the guard and return the reply.
    sel_transport.expect("ATRV", "12.6V\r\r>").expect("ATCS", "T:00 R:00\r\r>")
    status = selected.read_status()
    assert status.voltage_v == pytest.approx(12.6) and status.can_status == "T:00 R:00"
    sel_transport.expect("ATI", "ELM327 v1.3a\r\r>")
    assert selected.query(AdapterQuery.ATI).text == "ELM327 v1.3a"
    assert sel_transport.remaining == 0


# ---------------------------------------------------------------------------
# Fixes after verification: adapter reset, pending reply, 7F xx 78

STPX_GW = "STPX H:710,D:22F187,R:1,T:1500"
PENDING_78 = "77A037F1978AAAAAAAA\r"


@pytest.mark.parametrize(
    "scenario",
    ["echo-after-ate0", "elm-banner", "lv-reset", "searching", "stale-bytes"],
)
def test_adapter_reset_blocks_egress(
    make_driver: Callable[..., Any], log: TrafficLog, scenario: str
) -> None:
    driver, transport, _ = bring_to(make_driver, "TARGET_SELECTED")
    assert driver.adapter.check_stpx(GATEWAY) is None
    if scenario == "stale-bytes":
        transport.stale(b"OK\r\r>")
    else:
        reply = {
            "echo-after-ate0": f"{STPX_GW}\rNO DATA\r\r>",
            "elm-banner": "\r\rELM327 v1.3a\r\r>",
            "lv-reset": "LV RESET\r\r>",
            "searching": "SEARCHING...\rUNABLE TO CONNECT\r\r>",
        }[scenario]
        transport.expect(STPX_GW, reply)
    writes_before = len(transport.writes)

    with pytest.raises(DriverError) as caught:
        driver.transact(b"\x22\xf1\x87")
    assert caught.value.rule == RULE_ADAPTER_RESET
    assert driver.adapter_reset is not None
    expected_writes = 0 if scenario == "stale-bytes" else 1
    assert len(transport.writes) - writes_before == expected_writes
    # The guard model returns to the post-reset state: STPX fails the model condition.
    assert driver.adapter.check_stpx(GATEWAY) is not None
    errors = [e for e in events(log, "error") if e["meta"].get("rule") == RULE_ADAPTER_RESET]
    assert errors and "reset" in errors[0]["data"].lower()

    # Every further line except on close is rejected without a write.
    writes_after = len(transport.writes)
    for call in (lambda: driver.transact(b"\x22\xf1\x87"), lambda: driver.query(AdapterQuery.ATRV)):
        with pytest.raises(DriverError) as blocked:
            call()
        assert blocked.value.rule == RULE_ADAPTER_RESET
    assert len(transport.writes) == writes_after

    transport.expect("STPC", OK)
    reply_stpc = driver.close()
    assert transport.written_lines[-1] == "STPC"
    assert reply_stpc is not None and reply_stpc.text == "OK"
    assert transport.remaining == 0


def test_pending_reply_set_before_write(make_driver: Callable[..., Any], log: TrafficLog) -> None:
    driver, transport, _ = bring_to(make_driver, "TARGET_SELECTED")
    transport.expect(STPX_5000, NO_DATA).expect("STPC", OK)
    original_write = transport.write

    def interrupted_write(data: bytes) -> None:
        original_write(data)  # the bytes reached the adapter, interruption during flush()
        raise KeyboardInterrupt

    transport.write = interrupted_write
    with pytest.raises(KeyboardInterrupt):
        driver.transact(b"\x22\xf1\x87", timeout_ms=5000)
    transport.write = original_write

    # Reply not read: every new line is rejected without a write.
    writes_before = len(transport.writes)
    with pytest.raises(DriverError) as caught:
        driver.query(AdapterQuery.ATRV)
    assert caught.value.rule == RULE_PENDING
    assert len(transport.writes) == writes_before

    # Close first finishes the read up to `>`, and only then sends STPC.
    driver.close()
    assert transport.read_timeouts[-2:] == pytest.approx([10.5, 2.0])
    assert transport.written_lines[-2:] == [STPX_5000, "STPC"]
    assert transport.remaining == 0


def test_finish_pending_after_interrupt(make_driver: Callable[..., Any]) -> None:
    driver, transport, _ = bring_to(make_driver, "TARGET_SELECTED")
    transport.expect(STPX_5000, NO_DATA)
    _interrupt_next_read(transport)
    with pytest.raises(KeyboardInterrupt):
        driver.transact(b"\x22\xf1\x87", timeout_ms=5000)
    assert driver.finish_pending() is True
    assert driver.finish_pending() is True  # no pending reply: no read
    transport.expect("ATRV", "12.6V\r\r>").expect("ATCS", "T:00 R:00\r\r>")
    assert driver.read_status().voltage_v == pytest.approx(12.6)
    assert transport.remaining == 0


def test_nrc78_extends_read_deadline(make_driver: Callable[..., Any], log: TrafficLog) -> None:
    driver, transport, _ = bring_to(make_driver, "TARGET_SELECTED")
    transport.expect(STPX_GW, PENDING_78, timeout=True)
    transport.read(PENDING_78, timeout=True)
    transport.read(GW_F187)
    writes_before = len(transport.writes)
    reads_before = len(transport.read_timeouts)

    exchange = driver.transact(b"\x22\xf1\x87")

    assert exchange.outcome is ExchangeOutcome.POSITIVE and exchange.pending_count == 2
    assert len(transport.writes) - writes_before == 1  # no request retry
    assert transport.read_timeouts[reads_before:] == pytest.approx([7.0, 7.0, 7.0])
    rx = events(log, "rx", "transport")[-3:]
    assert [e["meta"].get("nrc78_extend", False) for e in rx] == [True, True, False]
    assert driver.transport_failed is False
    assert transport.remaining == 0


def test_nrc78_total_limit_then_drain(make_driver: Callable[..., Any], log: TrafficLog) -> None:
    driver, transport, _ = bring_to(make_driver, "TARGET_SELECTED")
    transport.expect(STPX_GW, PENDING_78, timeout=True)
    for _ in range(4):
        transport.read(PENDING_78, timeout=True)
    transport.read("NO DATA\r\r>")  # finish up to `>` after the final timeout
    transport.expect("STPC", OK)
    reads_before = len(transport.read_timeouts)

    with pytest.raises(StpxTimeout) as caught:
        driver.transact(b"\x22\xf1\x87")

    windows = transport.read_timeouts[reads_before:-1]
    assert windows == pytest.approx([7.0, 7.0, 7.0, 7.0, 2.0])
    assert sum(windows) == pytest.approx(NRC78_TOTAL_LIMIT_S)
    assert transport.read_timeouts[-1] == pytest.approx(STPX_DRAIN_TIMEOUT_S)
    exchange = caught.value.exchange
    assert exchange.pending_count == 5 and caught.value.drained is True
    assert exchange.lines[-1] == "NO DATA"
    # Adapter is back at the prompt: the session is not damaged, STPC goes out on close.
    assert driver.transport_failed is False
    driver.close()
    assert transport.written_lines[-1] == "STPC"
    assert transport.remaining == 0


def test_stpx_timeout_drain_failed(make_driver: Callable[..., Any]) -> None:
    driver, transport, _ = bring_to(make_driver, "TARGET_SELECTED")
    transport.expect(STPX_GW, PENDING_78, timeout=True)
    transport.read(b"", timeout=True)  # no new 7F xx 78: final timeout
    transport.read(b"", timeout=True)  # finish without a prompt
    with pytest.raises(StpxTimeout) as caught:
        driver.transact(b"\x22\xf1\x87")
    assert caught.value.drained is False and caught.value.exchange.pending_count == 1
    assert driver.transport_failed is True
    before = len(transport.writes)
    assert driver.close() is None
    assert len(transport.writes) == before
    assert transport.remaining == 0


# ---------------------------------------------------------------------------
# Package C: shared finishing path, content of unread bytes, ATWS in RAW

STALE_FRAME = "77A0462F18741AAAAAA\r"
LATE_BANNER = "\r\rELM327 v1.3a\r\r>"


def test_stpx_timeout_drain_goes_through_receive(
    make_driver: Callable[..., Any], log: TrafficLog, monkeypatch: pytest.MonkeyPatch
) -> None:
    """C1: finishing after the final timeout updates the model from the whole reply, like `_receive`."""
    import obd_bridge.stn.driver as driver_module

    driver, transport, _ = bring_to(make_driver, "TARGET_SELECTED")
    transport.expect(STPX_GW, PENDING_78, timeout=True)
    transport.read(b"", timeout=True)  # no new 7F xx 78: final timeout
    transport.read("NO DATA\r\r>")  # finish up to `>`
    seen: list[tuple[str, tuple[str, ...]]] = []
    original = driver_module.reply_ok_for

    def recording(line: str, reply: Any) -> bool:
        seen.append((line, reply.lines))
        return original(line, reply)

    monkeypatch.setattr(driver_module, "reply_ok_for", recording)
    with pytest.raises(StpxTimeout) as caught:
        driver.transact(b"\x22\xf1\x87")

    assert caught.value.drained is True and caught.value.exchange.pending_count == 1
    # Model updated once, from the lines of the whole reply (before the timeout and from the finish).
    assert seen == [(STPX_GW, (PENDING_78.strip(), "NO DATA"))]
    assert driver.pending_line is None and driver.last_elapsed_ms is not None
    drain = events(log, "rx", "transport")[-1]
    assert drain["meta"].get("drain") is True and "timeout" not in drain["meta"]
    adapter_rx = [e["data"] for e in events(log, "rx", "adapter")][-2:]
    assert adapter_rx == [PENDING_78.strip(), "NO DATA"]
    assert driver.transport_failed is False


def test_stpx_timeout_drain_reset_evidence(make_driver: Callable[..., Any], log: TrafficLog) -> None:
    """C1: a banner in the finished read detects a reset through the same path as a normal reply."""
    driver, transport, _ = bring_to(make_driver, "TARGET_SELECTED")
    transport.expect(STPX_GW, PENDING_78, timeout=True)
    transport.read(b"", timeout=True)
    transport.read(LATE_BANNER)
    with pytest.raises(DriverError) as caught:
        driver.transact(b"\x22\xf1\x87")
    assert caught.value.rule == RULE_ADAPTER_RESET
    assert driver.adapter_reset is not None and "banner" in driver.adapter_reset
    assert driver.adapter.check_stpx(GATEWAY) is not None
    assert driver.pending_line is None and driver.transport_failed is False
    transport.expect("STPC", OK)
    driver.close()
    assert transport.written_lines[-1] == "STPC" and transport.remaining == 0


def test_stale_input_logged_before_block(make_driver: Callable[..., Any], log: TrafficLog) -> None:
    """C2: the content of unread bytes goes to JSONL as `rx` with `meta.stale` before the session block."""
    driver, transport, _ = bring_to(make_driver, "TARGET_SELECTED")
    transport.stale(STALE_FRAME)
    writes_before = len(transport.writes)
    with pytest.raises(DriverError) as caught:
        driver.transact(b"\x22\xf1\x87")
    assert caught.value.rule == RULE_ADAPTER_RESET
    assert len(transport.writes) == writes_before
    found = read_events(log.path)
    stale = [e for e in found if e["ev"] == "rx" and (e.get("meta") or {}).get("stale") is True]
    assert len(stale) == 1 and stale[0]["layer"] == "transport"
    assert "77A0462F18741" in stale[0]["data"] and stale[0]["meta"].get("timeout") is True
    reset_error = next(e for e in found if e["ev"] == "error" and e["meta"].get("rule") == RULE_ADAPTER_RESET)
    assert stale[0]["seq"] < reset_error["seq"]
    assert f"{len(STALE_FRAME)} B of unread data" in reset_error["data"]

    transport.expect("STPC", OK)
    assert driver.close() is not None
    assert transport.written_lines[-1] == "STPC" and transport.remaining == 0


def test_stale_input_split_at_prompt(make_driver: Callable[..., Any], log: TrafficLog) -> None:
    """C2: bytes with `>` in the middle give successive `rx` events with `meta.stale` until the buffer is empty."""
    driver, transport, _ = bring_to(make_driver, "TARGET_SELECTED")
    transport.stale("STOPPED\r\r>" + STALE_FRAME)
    with pytest.raises(DriverError):
        driver.transact(b"\x22\xf1\x87")
    stale = [e for e in events(log, "rx", "transport") if e["meta"].get("stale")]
    assert [e["data"] for e in stale] == ["STOPPED\\r\\r>", STALE_FRAME.replace("\r", "\\r")]
    assert transport.remaining == 0


def test_stale_input_before_atws_in_raw(make_driver: Callable[..., Any], log: TrafficLog) -> None:
    """C3: a late banner before `ATWS` in RAW is logged and discarded, warm start works."""
    driver, transport, _ = make_driver()
    transport.banner(None)
    driver.open()
    # The banner arrives after the banner window and after `reset_input` in `open()`.
    transport.stale(LATE_BANNER)
    transport.expect("ATWS", "ATWS\r\rELM327 v1.3a\r\r>")
    for line in FORMAT_LINES:
        transport.expect(line, OK)
    resets_before = transport.reset_count

    driver.warm_start()
    driver.set_format()

    assert driver.adapter_reset is None
    assert transport.reset_count == resets_before + 1
    found = read_events(log.path)
    stale = [e for e in found if e["ev"] == "rx" and (e.get("meta") or {}).get("stale") is True]
    assert [e["data"] for e in stale] == ["\\r\\rELM327 v1.3a\\r\\r>"]
    atws_tx = next(e for e in found if e["ev"] == "tx" and e["layer"] == "adapter" and e["data"] == "ATWS")
    assert stale[0]["seq"] < atws_tx["seq"]
    notice = [e for e in found if e["ev"] == "error" and "discarded" in e["data"]]
    assert len(notice) == 1 and "ATWS" in notice[0]["data"]
    assert not any(e["ev"] == "error" and e["meta"].get("rule") == RULE_ADAPTER_RESET for e in found)
    assert transport.remaining == 0


def test_stale_input_before_other_raw_line_blocks(make_driver: Callable[..., Any], log: TrafficLog) -> None:
    """C3: unread bytes before a line other than `ATWS` in RAW still block the session."""
    driver, transport, _ = make_driver()
    transport.banner(None)
    transport.expect("ATWS", "ATWS\r\rELM327 v1.3a\r\r>")
    transport.stale("ATWS\r\r\rELM327 v1.3a\r\r>")
    driver.open()
    driver.warm_start()
    with pytest.raises(DriverError) as caught:
        driver.set_format()
    assert caught.value.rule == RULE_ADAPTER_RESET and caught.value.line == "ATE0"
    assert transport.written_lines == ["ATWS"]
    stale = [e for e in events(log, "rx", "transport") if e["meta"].get("stale")]
    assert len(stale) == 1 and "ELM327" in stale[0]["data"]
    assert driver.close() is None  # RAW: no STPC
    assert transport.written_lines == ["ATWS"]


def test_replay_reproduces_stale_atws(
    make_driver: Callable[..., Any], log: TrafficLog, project_dir: Path
) -> None:
    """C3: `ReplayTransport` replays a session with a late banner before `ATWS` without a desync."""
    from obd_bridge.transport.replay import ReplayTransport

    driver, transport, _ = make_driver()
    transport.banner(None)
    driver.open()
    transport.stale(LATE_BANNER)
    transport.expect("ATWS", "ATWS\r\rELM327 v1.3a\r\r>")
    driver.warm_start()
    driver.close()
    replay = ReplayTransport(read_events(log.path))
    replay_log = TrafficLog.create("probe", root=project_dir / "replay")
    replay_log.session_start({"commit": None})
    clock = FakeClock()
    try:
        again = StnDriver(replay, ReadOnlyPolicy(CATALOG), replay_log, clock=clock, sleep=clock.sleep)
        again.open()
        again.warm_start()
        again.close()
    finally:
        replay_log.close()
    assert replay.remaining == 0
    stale = [e for e in read_events(replay_log.path) if e["ev"] == "rx" and (e.get("meta") or {}).get("stale")]
    assert len(stale) == 1
