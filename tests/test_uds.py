"""Tests of the UDS layers: L2 `ElmUdsConnection` (spec T5, FR-18) and L3 `ReadOnlyUdsClient` (FR-19).

Both sections use a fake driver: `transact` returns a prepared `UdsExchange`
without a transport, so the tests touch neither the adapter nor a port.
The L3 section adds an event-recording log to the fake (`RecordingLog`).
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

import pytest
import udsoncan
from udsoncan.client import Client
from udsoncan.exceptions import TimeoutException
from udsoncan.services import ReadDataByIdentifier

from conftest import MOCK_CATALOG
from obd_bridge.errors import AdapterResponseError, ReadOnlyViolation, TransportError, UdsError
from obd_bridge.policy import ReadOnlyPolicy
from obd_bridge.stn.parser import ExchangeOutcome, UdsExchange
from obd_bridge.uds.client import (
    CheckedResponse,
    DidResponse,
    DidStatus,
    DtcRecord,
    DtcReportType,
    NoResponse,
    NrcBusyRepeatRequest,
    NrcConditionsNotCorrect,
    NrcIncorrectLength,
    NrcRequestOutOfRange,
    NrcSecurityAccessDenied,
    NrcServiceNotSupported,
    NrcServiceNotSupportedInActiveSession,
    NrcSubFunctionNotSupported,
    NrcSubFunctionNotSupportedInActiveSession,
    ReadOnlyUdsClient,
    ResponsePendingUnresolved,
    UdsNegativeResponse,
    UnexpectedResponse,
)
from obd_bridge.uds.connection import UDS_CLIENT_CONFIG, ElmUdsConnection, RawDidCodec
from obd_bridge.vag.catalog import EcuCatalog

# -- fake driver (L2 section) -------------------------------------------------

DID_F187 = 0xF187
REQ_F187 = bytes.fromhex("22F187")
POS_F187 = bytes.fromhex("62F187") + b"4G0907468A"
PENDING_22 = bytes.fromhex("7F2278")
NEG_22_31 = bytes.fromhex("7F2231")


def make_exchange(
    outcome: ExchangeOutcome,
    messages: tuple[bytes, ...] = (),
    *,
    nrc: int | None = None,
    error_token: str | None = None,
) -> UdsExchange:
    """UDS exchange with the given outcome; `final` is the first message other than 78."""
    final = next((m for m in messages if m[:1] != b"\x7f" or m[2:3] != b"\x78"), None)
    return UdsExchange(
        line="STPX H:7E1,D:22F187,R:1",
        raw=b"",
        lines=(),
        echo=False,
        frames=(),
        foreign_frames=(),
        unparsed_lines=(),
        messages=messages,
        pending_count=sum(1 for m in messages if m[:1] == b"\x7f" and m[2:3] == b"\x78"),
        outcome=outcome,
        final=final,
        nrc=nrc,
        error_token=error_token,
    )


@dataclass(frozen=True)
class FakeTarget:
    """Minimal driver target: only the VAG address used in the connection name."""

    vag_address: str = "19"


@dataclass
class FakeDriver:
    """Fake `StnDriver`: `transact` returns consecutive prepared exchanges.

    `delay_s` simulates a blocking `STPX` (time waiting for `>`).
    `calls` records the payloads in call order.
    """

    exchanges: list[UdsExchange | Exception]
    delay_s: float = 0.0
    target: FakeTarget | None = field(default_factory=FakeTarget)
    calls: list[bytes] = field(default_factory=list)
    opened: int = 0
    closed: int = 0
    log: Any = None

    def transact(self, payload: bytes, timeout_ms: int | None = None) -> UdsExchange:
        self.calls.append(bytes(payload))
        if self.delay_s:
            time.sleep(self.delay_s)
        item = self.exchanges.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    def open(self) -> None:
        """Call counter; the L2 connection must not open the driver."""
        self.opened += 1

    def close(self) -> None:
        """Call counter; the L2 connection must not close the driver."""
        self.closed += 1


@pytest.fixture
def make_connection() -> Callable[..., tuple[ElmUdsConnection, FakeDriver]]:
    def factory(*exchanges: UdsExchange, delay_s: float = 0.0) -> tuple[ElmUdsConnection, FakeDriver]:
        driver = FakeDriver(list(exchanges), delay_s=delay_s)
        conn = ElmUdsConnection(driver)  # type: ignore[arg-type]
        conn.open()
        return conn, driver

    return factory


def drain(conn: ElmUdsConnection) -> list[bytes]:
    """All items of the receive queue until `TimeoutException`."""
    frames: list[bytes] = []
    while True:
        try:
            frames.append(conn.wait_frame(exception=True))  # type: ignore[arg-type]
        except TimeoutException:
            return frames


# -- L2: ElmUdsConnection ------------------------------------------------------


@pytest.mark.parametrize(
    ("outcome", "messages", "nrc", "expected"),
    [
        pytest.param(
            ExchangeOutcome.POSITIVE,
            (PENDING_22, POS_F187),
            None,
            [PENDING_22, POS_F187],
            id="positive",
        ),
        pytest.param(
            ExchangeOutcome.NEGATIVE,
            (PENDING_22, PENDING_22, NEG_22_31),
            0x31,
            [PENDING_22, PENDING_22, NEG_22_31],
            id="negative",
        ),
        pytest.param(
            ExchangeOutcome.PENDING_UNRESOLVED,
            (PENDING_22, PENDING_22),
            0x78,
            [PENDING_22, PENDING_22],
            id="pending_unresolved",
        ),
        pytest.param(ExchangeOutcome.NO_DATA, (), None, [], id="no_data"),
    ],
)
def test_send_queues_messages(
    make_connection: Callable[..., tuple[ElmUdsConnection, FakeDriver]],
    outcome: ExchangeOutcome,
    messages: tuple[bytes, ...],
    nrc: int | None,
    expected: list[bytes],
) -> None:
    exchange = make_exchange(outcome, messages, nrc=nrc)
    conn, driver = make_connection(exchange)

    conn.send(REQ_F187)

    assert driver.calls == [REQ_F187]
    assert conn.last_exchange is exchange
    assert drain(conn) == expected


@pytest.mark.parametrize(
    ("outcome", "token"),
    [
        pytest.param(ExchangeOutcome.ADAPTER_ERROR, "CAN ERROR", id="adapter_error"),
        pytest.param(ExchangeOutcome.INCOMPLETE, None, id="incomplete"),
        pytest.param(ExchangeOutcome.UNPARSED, None, id="unparsed"),
    ],
)
def test_send_adapter_errors(
    make_connection: Callable[..., tuple[ElmUdsConnection, FakeDriver]],
    outcome: ExchangeOutcome,
    token: str | None,
) -> None:
    exchange = make_exchange(outcome, (POS_F187[:4],), error_token=token)
    conn, _ = make_connection(exchange)

    with pytest.raises(AdapterResponseError) as caught:
        conn.send(REQ_F187)

    assert caught.value.exchange is exchange
    assert caught.value.exit_code == 3
    assert conn.last_exchange is exchange
    assert drain(conn) == []


def test_wait_frame_and_empty_queue(
    make_connection: Callable[..., tuple[ElmUdsConnection, FakeDriver]],
) -> None:
    exchange = make_exchange(ExchangeOutcome.POSITIVE, (PENDING_22, POS_F187))
    conn, driver = make_connection(exchange)
    assert conn.name == "ElmUdsConnection[19]"
    assert conn.is_open()

    started = time.monotonic()
    with pytest.raises(TimeoutException):
        conn.specific_wait_frame(timeout=5.0)
    assert time.monotonic() - started < 0.5

    conn.send(REQ_F187)
    conn.empty_rxqueue()
    with pytest.raises(TimeoutException):
        conn.specific_wait_frame()

    conn.close()
    assert not conn.is_open()
    assert driver.opened == 0
    assert driver.closed == 0
    with pytest.raises(RuntimeError):
        conn.send(REQ_F187)
    assert driver.calls == [REQ_F187]


def test_blocking_send_with_client(
    make_connection: Callable[..., tuple[ElmUdsConnection, FakeDriver]],
) -> None:
    assert UDS_CLIENT_CONFIG["p2_timeout"] == 1.0
    assert UDS_CLIENT_CONFIG["data_identifiers"] == {"default": RawDidCodec}
    assert "ignore_all_zero_dtc" not in UDS_CLIENT_CONFIG

    exchange = make_exchange(ExchangeOutcome.POSITIVE, (PENDING_22, POS_F187))
    conn, driver = make_connection(exchange, delay_s=1.2)
    client = Client(conn, config=UDS_CLIENT_CONFIG)

    started = time.monotonic()
    response = client.send_request(udsoncan.Request.from_payload(REQ_F187))
    elapsed = time.monotonic() - started

    assert elapsed >= 1.2
    assert driver.calls == [REQ_F187]
    assert response is not None
    assert response.positive
    assert response.original_payload == POS_F187

    ReadDataByIdentifier.interpret_response(
        response,
        didlist=[DID_F187],
        didconfig=UDS_CLIENT_CONFIG["data_identifiers"],
        tolerate_zero_padding=True,
    )
    assert response.service_data.values[DID_F187] == b"4G0907468A"
    with pytest.raises(NotImplementedError):
        RawDidCodec().encode(b"\x00")


# -- L3: ReadOnlyUdsClient -----------------------------------------------------

CATALOG: EcuCatalog = EcuCatalog.load(MOCK_CATALOG)

PUBLIC_METHODS: frozenset[str] = frozenset(
    {"read_did", "read_dids", "read_dtcs", "read_dtc_snapshot", "obd_read"}
)


@dataclass
class RecordingLog:
    """Fake `TrafficLog`: records the `emit` arguments in order."""

    events: list[dict[str, Any]] = field(default_factory=list)

    def emit(
        self,
        ev: str,
        layer: str,
        data: str = "",
        *,
        ecu: str | None = None,
        guard: object = None,
        meta: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        event = {
            "ev": ev,
            "layer": layer,
            "data": data,
            "ecu": ecu,
            "guard": dict(guard) if isinstance(guard, Mapping) else guard,
            "meta": dict(meta or {}),
        }
        self.events.append(event)
        return event

    def of(self, ev: str) -> list[dict[str, Any]]:
        return [e for e in self.events if e["ev"] == ev]


def positive(*messages: bytes) -> UdsExchange:
    return make_exchange(ExchangeOutcome.POSITIVE, messages)


def negative(*messages: bytes) -> UdsExchange:
    return make_exchange(ExchangeOutcome.NEGATIVE, messages, nrc=messages[-1][2])


@pytest.fixture
def make_client() -> Callable[..., tuple[ReadOnlyUdsClient, FakeDriver, RecordingLog]]:
    def factory(*exchanges: UdsExchange | Exception) -> tuple[ReadOnlyUdsClient, FakeDriver, RecordingLog]:
        log = RecordingLog()
        driver = FakeDriver(list(exchanges), log=log)
        conn = ElmUdsConnection(driver)  # type: ignore[arg-type]
        conn.open()
        return ReadOnlyUdsClient(conn, ReadOnlyPolicy(CATALOG)), driver, log

    return factory


@pytest.mark.parametrize(
    ("exchange", "expected", "nrc"),
    [
        *(
            pytest.param(negative(PENDING_22, bytes([0x7F, 0x22, code])), cls, code, id=f"nrc-{code:02X}")
            for code, cls in [
                (0x11, NrcServiceNotSupported),
                (0x12, NrcSubFunctionNotSupported),
                (0x13, NrcIncorrectLength),
                (0x21, NrcBusyRepeatRequest),
                (0x22, NrcConditionsNotCorrect),
                (0x31, NrcRequestOutOfRange),
                (0x33, NrcSecurityAccessDenied),
                (0x7E, NrcSubFunctionNotSupportedInActiveSession),
                (0x7F, NrcServiceNotSupportedInActiveSession),
            ]
        ),
        pytest.param(negative(bytes.fromhex("7F2210")), UdsNegativeResponse, 0x10, id="nrc-other"),
        pytest.param(
            make_exchange(ExchangeOutcome.PENDING_UNRESOLVED, (PENDING_22, PENDING_22), nrc=0x78),
            ResponsePendingUnresolved,
            None,
            id="pending-unresolved",
        ),
        pytest.param(
            make_exchange(ExchangeOutcome.NO_DATA, (), error_token="NO DATA"), NoResponse, None, id="no-data"
        ),
    ],
)
def test_exception_mapping(
    make_client: Callable[..., tuple[ReadOnlyUdsClient, FakeDriver, RecordingLog]],
    exchange: UdsExchange,
    expected: type[UdsError],
    nrc: int | None,
) -> None:
    client, driver, log = make_client(exchange)

    with pytest.raises(UdsError) as caught:
        client.read_did(DID_F187)

    assert type(caught.value) is expected
    assert caught.value.exit_code == 3
    assert caught.value.exchange is exchange
    if nrc is not None:
        assert isinstance(caught.value, UdsNegativeResponse)
        assert (caught.value.sid, caught.value.nrc) == (0x22, nrc)
    assert driver.calls == [REQ_F187]
    assert [e["meta"]["direction"] for e in log.of("uds")] == ["req", "resp"]
    assert log.of("uds")[-1]["meta"]["outcome"] == str(exchange.outcome)


def test_read_did_and_dids(
    make_client: Callable[..., tuple[ReadOnlyUdsClient, FakeDriver, RecordingLog]],
) -> None:
    client, driver, _ = make_client(positive(PENDING_22, POS_F187))
    assert client.read_did(DID_F187) == b"4G0907468A"
    assert driver.calls == [REQ_F187]

    pos_f190 = bytes.fromhex("62F190") + b"WAUZZZ4G0EN000000"
    unsupported = make_exchange(ExchangeOutcome.ADAPTER_ERROR, (), error_token="?")
    client, driver, _ = make_client(
        positive(pos_f190),
        negative(bytes.fromhex("7F2231")),
        make_exchange(ExchangeOutcome.NO_DATA, (), error_token="NO DATA"),
        make_exchange(ExchangeOutcome.PENDING_UNRESOLVED, (PENDING_22,), nrc=0x78),
        unsupported,
    )
    dids = [0xF190, 0xF1A3, 0xF17C, 0xF18C, 0x0405]
    results = client.read_dids(dids)

    # One request per DID, in argument order.
    assert driver.calls == [b"\x22" + did.to_bytes(2, "big") for did in dids]
    assert all(isinstance(r, DidResponse) for r in results)
    assert [r.did for r in results] == dids
    assert [r.status for r in results] == [
        DidStatus.OK,
        DidStatus.NRC,
        DidStatus.NO_DATA,
        DidStatus.PENDING_UNRESOLVED,
        DidStatus.UNSUPPORTED,
    ]
    assert results[0].data == b"WAUZZZ4G0EN000000"
    assert results[1].nrc == 0x31 and results[1].data is None
    assert results[4].exchange is unsupported

    # ReadOnlyViolation and TransportError abort the series.
    violation = ReadOnlyViolation("adapter", "LINE/state", "test", "STPX H:710,D:22F187,R:1")
    client, driver, _ = make_client(violation, positive(POS_F187))
    with pytest.raises(ReadOnlyViolation):
        client.read_dids([DID_F187, 0xF190])
    assert driver.calls == [REQ_F187]
    client, driver, _ = make_client(TransportError("port closed"), positive(POS_F187))
    with pytest.raises(TransportError):
        client.read_dids([DID_F187, 0xF190])
    assert driver.calls == [REQ_F187]
    other_adapter = make_exchange(ExchangeOutcome.ADAPTER_ERROR, (), error_token="CAN ERROR")
    client, driver, _ = make_client(other_adapter, positive(POS_F187))
    with pytest.raises(AdapterResponseError):
        client.read_dids([DID_F187, 0xF190])
    assert driver.calls == [REQ_F187]


@pytest.mark.parametrize(
    ("report", "request_hex", "response_hex", "mask", "count", "records", "snapshots", "zeros"),
    [
        pytest.param(DtcReportType.NUMBER_BY_MASK, "1901FF", "5901FF010003", 0xFF, 3, [], [], 0, id="0x01"),
        pytest.param(
            DtcReportType.BY_MASK,
            "1902FF",
            "5902FF" "0123452F" "00000000" "C1010008",
            0xFF,
            2,
            [DtcRecord(0x012345, 0x2F), DtcRecord(0xC10100, 0x08)],
            [],
            1,
            id="0x02",
        ),
        pytest.param(
            DtcReportType.SNAPSHOT_IDS,
            "1903",
            "5903" "01234501" "00000000" "01234502",
            None,
            2,
            [],
            [(0x012345, 1), (0x012345, 2)],
            1,
            id="0x03",
        ),
        pytest.param(
            DtcReportType.SUPPORTED,
            "190A",
            "590AFF" "00000000" "00000050" "C1010000",
            0xFF,
            1,
            [DtcRecord(0xC10100, 0x00)],
            [],
            2,
            id="0x0A",
        ),
    ],
)
def test_read_dtcs(
    make_client: Callable[..., tuple[ReadOnlyUdsClient, FakeDriver, RecordingLog]],
    report: DtcReportType,
    request_hex: str,
    response_hex: str,
    mask: int | None,
    count: int,
    records: list[DtcRecord],
    snapshots: list[tuple[int, int]],
    zeros: int,
) -> None:
    response = bytes.fromhex(response_hex)
    client, driver, _ = make_client(positive(bytes.fromhex("7F1978"), response))

    result = client.read_dtcs(report)

    assert driver.calls == [bytes.fromhex(request_hex)]
    assert result.subfunction == int(report)
    assert result.raw == response
    assert result.availability_mask == mask
    assert result.count == count
    assert result.records == records
    assert result.snapshot_ids == snapshots
    assert result.zero_records == zeros


def test_obd_read_skips_pending(
    make_client: Callable[..., tuple[ReadOnlyUdsClient, FakeDriver, RecordingLog]],
) -> None:
    final = bytes.fromhex("4100BE3FA813")
    pending = bytes.fromhex("7F0178")
    client, driver, log = make_client(positive(pending, pending, final))
    assert client.obd_read(0x01, 0x00) == final
    assert driver.calls == [bytes.fromhex("0100")]
    assert log.of("uds")[-1]["data"] == final.hex().upper()

    client, driver, _ = make_client(positive(bytes.fromhex("4300")))
    assert client.obd_read(0x03) == bytes.fromhex("4300")
    assert driver.calls == [b"\x03"]

    # Reply without the mode + 0x40 prefix.
    client, _, _ = make_client(positive(bytes.fromhex("4200BE3FA813")))
    with pytest.raises(UnexpectedResponse):
        client.obd_read(0x01, 0x00)

    # An NRC other than 0x78 yields a typed exception; only 0x78 yields ResponsePendingUnresolved.
    client, _, _ = make_client(negative(pending, bytes.fromhex("7F0112")))
    with pytest.raises(NrcSubFunctionNotSupported) as caught:
        client.obd_read(0x01, 0x00)
    assert (caught.value.sid, caught.value.nrc) == (0x01, 0x12)
    client, _, _ = make_client(make_exchange(ExchangeOutcome.PENDING_UNRESOLVED, (pending,), nrc=0x78))
    with pytest.raises(ResponsePendingUnresolved):
        client.obd_read(0x01, 0x00)
    client, _, _ = make_client(make_exchange(ExchangeOutcome.NO_DATA, (), error_token="NO DATA"))
    with pytest.raises(NoResponse):
        client.obd_read(0x09, 0x02)


@pytest.mark.parametrize(
    ("method", "args", "expected"),
    [
        pytest.param("read_did", (DID_F187,), ["22F187"], id="read_did"),
        pytest.param("read_dids", ([DID_F187, DID_F187],), ["22F187", "22F187"], id="read_dids"),
        pytest.param("read_dtcs", (DtcReportType.BY_MASK, 0x08), ["190208"], id="read_dtcs"),
        pytest.param("read_dtc_snapshot", (0x012345, 0x01), ["190401234501"], id="read_dtc_snapshot"),
        pytest.param("obd_read", (0x01, 0x00), ["0100"], id="obd_read"),
    ],
)
def test_single_send_path(
    make_client: Callable[..., tuple[ReadOnlyUdsClient, FakeDriver, RecordingLog]],
    monkeypatch: pytest.MonkeyPatch,
    method: str,
    args: tuple[Any, ...],
    expected: list[str],
) -> None:
    # The client has no public methods besides the five reads (no writing and no control).
    public = {name for name in dir(ReadOnlyUdsClient) if not name.startswith("_")}
    assert public == PUBLIC_METHODS

    def forbidden(*_: Any, **__: Any) -> None:
        pytest.fail("a public method bypassed _checked")

    monkeypatch.setattr(Client, "send_request", forbidden)
    monkeypatch.setattr(ElmUdsConnection, "send", forbidden)
    monkeypatch.setattr(ElmUdsConnection, "wait_frame", forbidden)
    client, driver, log = make_client()
    seen: list[str] = []

    def fake_checked(payload: bytes) -> CheckedResponse:
        seen.append(bytes(payload).hex().upper())
        # Positive reply echoing the request (e.g. 22F187 gives 62F187).
        raw = bytes([payload[0] + 0x40]) + bytes(payload[1:])
        response = udsoncan.Response.from_payload(raw) if payload[0] in (0x22, 0x19) else None
        return CheckedResponse(raw, response)

    monkeypatch.setattr(client, "_checked", fake_checked)
    getattr(client, method)(*args)

    assert seen == expected
    assert driver.calls == []
    assert log.events == []
