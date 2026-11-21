"""Layer L3: read-only UDS client over `ElmUdsConnection` (spec T5, FR-19).

`ReadOnlyUdsClient` provides reads only: `read_did`, `read_dids`,
`read_dtcs`, `read_dtc_snapshot` and `obd_read`. There is no method for
writing, session control or sending a raw payload.

Single send path (audit M5): every public method builds the payload from typed
arguments and passes it to the private `_checked`, which:

1. evaluates the payload with `policy.check_uds`; a rejection yields a `guard`
   event of the `uds` layer in the driver log and `ReadOnlyViolation` before
   the payload reaches udsoncan or the driver;
2. emits a `uds` event with `meta.direction = req`;
3. for SIDs 0x22 and 0x19 sends `Request.from_payload(payload)` through
   `Client.send_request` (udsoncan handles 0x78 natively);
4. for OBD modes (0x01, 0x03, 0x06, 0x07, 0x09, 0x0A) sends the payload through
   `connection.send` and reads `connection.wait_frame`, skipping `7F <mode> 78`
   (audit m8);
5. emits a `uds` event with `meta.direction = resp` and `meta.outcome`, also
   when the exchange ends with an exception.

udsoncan exceptions are mapped to typed `UdsError` exceptions (code 3). DTC
0x000000 is skipped by the own 0x19 reply parser and counted in
`DtcReport.zero_records` (audit m14).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import IntEnum, StrEnum
from types import MappingProxyType
from typing import Any, ClassVar, Final

import udsoncan
from udsoncan.client import Client
from udsoncan.exceptions import (
    ConfigError,
    InvalidResponseException,
    NegativeResponseException,
    TimeoutException,
    UnexpectedResponseException,
)
from udsoncan.services import ReadDataByIdentifier

from obd_bridge.errors import AdapterResponseError, ReadOnlyViolation, UdsError
from obd_bridge.policy import LAYER_UDS, ReadOnlyPolicy
from obd_bridge.stn.parser import ExchangeOutcome, UdsExchange
from obd_bridge.traffic_log import EventKind, Layer
from obd_bridge.uds.connection import UDS_CLIENT_CONFIG, ElmUdsConnection

__all__ = [
    "NRC_EXCEPTIONS",
    "OBD_MODES",
    "CheckedResponse",
    "DidResponse",
    "DidStatus",
    "DtcRecord",
    "DtcReport",
    "DtcReportType",
    "NoResponse",
    "NrcBusyRepeatRequest",
    "NrcConditionsNotCorrect",
    "NrcIncorrectLength",
    "NrcRequestOutOfRange",
    "NrcSecurityAccessDenied",
    "NrcServiceNotSupported",
    "NrcServiceNotSupportedInActiveSession",
    "NrcSubFunctionNotSupported",
    "NrcSubFunctionNotSupportedInActiveSession",
    "ReadOnlyUdsClient",
    "ResponsePendingUnresolved",
    "UdsNegativeResponse",
    "UnexpectedResponse",
    "negative_response_error",
    "parse_dtc_report",
]

SID_READ_DID: Final[int] = 0x22
"""ReadDataByIdentifier."""

SID_READ_DTC: Final[int] = 0x19
"""ReadDTCInformation."""

UDS_SIDS: Final[frozenset[int]] = frozenset({SID_READ_DID, SID_READ_DTC})
"""Services sent through `udsoncan.Client.send_request`."""

OBD_MODES: Final[frozenset[int]] = frozenset({0x01, 0x03, 0x06, 0x07, 0x09, 0x0A})
"""OBD modes sent directly through the connection (not supported by udsoncan)."""

OBD_MODES_WITH_PID: Final[frozenset[int]] = frozenset({0x01, 0x06, 0x09})
"""OBD modes that require a PID byte (the others do not accept one)."""

NRC_RESPONSE_PENDING: Final[int] = 0x78
"""requestCorrectlyReceived-ResponsePending."""

_NEGATIVE_SID: Final[int] = 0x7F
_POSITIVE_OFFSET: Final[int] = 0x40
_DTC_RECORD_LEN: Final[int] = 4
_ADAPTER_UNSUPPORTED_TOKEN: Final[str] = "?"
_OUTCOME_ERROR: Final[str] = "error"


# ---------------------------------------------------------------------------
# Exceptions


class UdsNegativeResponse(UdsError):
    """Negative response `7F <sid> <nrc>`; base class of the `Nrc*` exceptions.

    Attributes:
        sid: request SID (also an OBD mode).
        nrc: NRC code of the reply.
        exchange: driver exchange (`UdsExchange`), or `None`.
    """

    description: ClassVar[str] = "negative response"

    def __init__(self, sid: int, nrc: int, *, exchange: UdsExchange | None = None) -> None:
        self.sid = sid
        self.nrc = nrc
        self.exchange = exchange
        super().__init__(f"NRC 0x{nrc:02X} ({self.description}) for service 0x{sid:02X}")


class NrcServiceNotSupported(UdsNegativeResponse):
    """NRC 0x11 serviceNotSupported."""

    description = "service not supported"


class NrcSubFunctionNotSupported(UdsNegativeResponse):
    """NRC 0x12 subFunctionNotSupported."""

    description = "subfunction not supported"


class NrcIncorrectLength(UdsNegativeResponse):
    """NRC 0x13 incorrectMessageLengthOrInvalidFormat."""

    description = "incorrect length or format"


class NrcBusyRepeatRequest(UdsNegativeResponse):
    """NRC 0x21 busyRepeatRequest."""

    description = "ECU busy, repeat the request"


class NrcConditionsNotCorrect(UdsNegativeResponse):
    """NRC 0x22 conditionsNotCorrect."""

    description = "conditions not correct"


class NrcRequestOutOfRange(UdsNegativeResponse):
    """NRC 0x31 requestOutOfRange."""

    description = "request out of range"


class NrcSecurityAccessDenied(UdsNegativeResponse):
    """NRC 0x33 securityAccessDenied."""

    description = "access denied (security access)"


class NrcSubFunctionNotSupportedInActiveSession(UdsNegativeResponse):
    """NRC 0x7E subFunctionNotSupportedInActiveSession."""

    description = "subfunction not supported in the active session"


class NrcServiceNotSupportedInActiveSession(UdsNegativeResponse):
    """NRC 0x7F serviceNotSupportedInActiveSession."""

    description = "service not supported in the active session"


NRC_EXCEPTIONS: Final[Mapping[int, type[UdsNegativeResponse]]] = MappingProxyType(
    {
        0x11: NrcServiceNotSupported,
        0x12: NrcSubFunctionNotSupported,
        0x13: NrcIncorrectLength,
        0x21: NrcBusyRepeatRequest,
        0x22: NrcConditionsNotCorrect,
        0x31: NrcRequestOutOfRange,
        0x33: NrcSecurityAccessDenied,
        0x7E: NrcSubFunctionNotSupportedInActiveSession,
        0x7F: NrcServiceNotSupportedInActiveSession,
    }
)
"""Table mapping NRCs to typed exceptions (spec T5); other codes yield `UdsNegativeResponse`."""


def negative_response_error(
    sid: int, nrc: int, *, exchange: UdsExchange | None = None
) -> UdsNegativeResponse:
    """Returns the typed exception for `7F <sid> <nrc>` according to `NRC_EXCEPTIONS`."""
    cls = NRC_EXCEPTIONS.get(nrc, UdsNegativeResponse)
    return cls(sid, nrc, exchange=exchange)


class NoResponse(UdsError):
    """No ECU reply (`NO DATA` or an empty queue without `7F xx 78`).

    Attribute `exchange`: driver exchange, or `None`.
    """

    def __init__(self, message: str, *, exchange: UdsExchange | None = None) -> None:
        self.exchange = exchange
        super().__init__(message)


class ResponsePendingUnresolved(UdsError):
    """Only `7F xx 78` without a final reply within the exchange limit.

    Attribute `exchange`: driver exchange, or `None`.
    """

    def __init__(self, message: str, *, exchange: UdsExchange | None = None) -> None:
        self.exchange = exchange
        super().__init__(message)


class UnexpectedResponse(UdsError):
    """Reply that does not match the request (different SID, subfunction, DID or incomplete data).

    Attributes:
        payload: received payload, or `None`.
        exchange: driver exchange, or `None`.
    """

    def __init__(
        self, message: str, *, payload: bytes | None = None, exchange: UdsExchange | None = None
    ) -> None:
        self.payload = payload
        self.exchange = exchange
        super().__init__(message)


# ---------------------------------------------------------------------------
# Result types


@dataclass(frozen=True)
class CheckedResponse:
    """Result of `_checked`.

    Attributes:
        payload: full payload of the final reply (with the SID + 0x40 byte).
        response: `udsoncan.Response` object for 0x22 and 0x19, `None` for OBD modes.
        exchange: driver exchange (`connection.last_exchange`), or `None`.
    """

    payload: bytes
    response: udsoncan.Response | None
    exchange: UdsExchange | None = None


class DidStatus(StrEnum):
    """Read status of a single DID in `read_dids`."""

    OK = "ok"
    NRC = "nrc"
    NO_DATA = "no_data"
    PENDING_UNRESOLVED = "pending_unresolved"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True)
class DidResponse:
    """Result of reading a single DID.

    Attributes:
        did: data identifier.
        status: read status.
        data: data after the `62 DID` header (only for `ok`).
        nrc: NRC code (only for `nrc`).
        elapsed_ms: exchange time measured by the driver, or `None`.
        exchange: driver exchange, or `None`.
    """

    did: int
    status: DidStatus
    data: bytes | None = None
    nrc: int | None = None
    elapsed_ms: float | None = None
    exchange: UdsExchange | None = None


class DtcReportType(IntEnum):
    """Subfunctions of 0x19 supported by `read_dtcs`."""

    NUMBER_BY_MASK = 0x01
    BY_MASK = 0x02
    SNAPSHOT_IDS = 0x03
    SUPPORTED = 0x0A


_MASKED_REPORTS: Final[frozenset[DtcReportType]] = frozenset(
    {DtcReportType.NUMBER_BY_MASK, DtcReportType.BY_MASK}
)


@dataclass(frozen=True)
class DtcRecord:
    """DTC record: 3-byte code and status byte."""

    dtc: int
    status: int


@dataclass(frozen=True)
class DtcReport:
    """Parsed 0x19 reply (subfunctions 01, 02, 03, 0A).

    Attributes:
        subfunction: request subfunction.
        raw: full reply payload (`59 <sub> ...`).
        availability_mask: `DTCStatusAvailabilityMask`, or `None` (subfunction 03).
        count: number of DTCs from the reply (01) or number of records after skipping DTC 000000.
        records: DTC records (02, 0A) without DTC 000000.
        snapshot_ids: pairs `(dtc, record number)` (03) without DTC 000000.
        zero_records: number of skipped records with DTC 000000.
    """

    subfunction: int
    raw: bytes
    availability_mask: int | None
    count: int
    records: list[DtcRecord] = field(default_factory=list)
    snapshot_ids: list[tuple[int, int]] = field(default_factory=list)
    zero_records: int = 0


def parse_dtc_report(report: DtcReportType, raw: bytes) -> DtcReport:
    """Own parser of 0x19 replies for subfunctions 01, 02, 03 and 0A.

    Records with DTC 0x000000 are skipped and counted in `zero_records`. An
    incomplete record at the end is accepted only as zero padding.

    Raises:
        UnexpectedResponse: different SID or subfunction, reply too short, or a
            non-zero incomplete tail.
    """
    report = DtcReportType(report)
    data = bytes(raw)
    if len(data) < 2 or data[0] != SID_READ_DTC + _POSITIVE_OFFSET or data[1] != report:
        raise UnexpectedResponse(
            f"Reply {data.hex().upper()} does not match request 19 {report:02X}", payload=data
        )
    if report is DtcReportType.NUMBER_BY_MASK:
        if len(data) < 6 or any(data[6:]):
            raise UnexpectedResponse(
                f"Reply 19 01 has an invalid length: {data.hex().upper()}", payload=data
            )
        return DtcReport(
            subfunction=int(report),
            raw=data,
            availability_mask=data[2],
            count=int.from_bytes(data[4:6], "big"),
        )

    if report is DtcReportType.SNAPSHOT_IDS:
        mask: int | None = None
        body = data[2:]
    else:
        if len(data) < 3:
            raise UnexpectedResponse(
                f"Reply 19 {report:02X} without availability mask: {data.hex().upper()}", payload=data
            )
        mask = data[2]
        body = data[3:]

    tail = len(body) % _DTC_RECORD_LEN
    if tail:
        if any(body[-tail:]):
            raise UnexpectedResponse(
                f"Reply 19 {report:02X} with an incomplete record: {data.hex().upper()}", payload=data
            )
        body = body[:-tail]

    records: list[DtcRecord] = []
    snapshots: list[tuple[int, int]] = []
    zeros = 0
    for offset in range(0, len(body), _DTC_RECORD_LEN):
        dtc = int.from_bytes(body[offset : offset + 3], "big")
        value = body[offset + 3]
        if dtc == 0:
            zeros += 1
            continue
        if report is DtcReportType.SNAPSHOT_IDS:
            snapshots.append((dtc, value))
        else:
            records.append(DtcRecord(dtc, value))
    return DtcReport(
        subfunction=int(report),
        raw=data,
        availability_mask=mask,
        count=len(snapshots) if report is DtcReportType.SNAPSHOT_IDS else len(records),
        records=records,
        snapshot_ids=snapshots,
        zero_records=zeros,
    )


def _require_int(name: str, value: object, maximum: int) -> int:
    """Checks that `value` is an integer in the range 0..`maximum`."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be int, got {value!r}")
    if not 0 <= value <= maximum:
        raise ValueError(f"{name} out of range 0..0x{maximum:X}: 0x{value:X}")
    return value


# ---------------------------------------------------------------------------
# Client


class ReadOnlyUdsClient:
    """Read-only UDS and OBD client; the only send path is `_checked`.

    Parameters:
        connection: L2 connection; if it is not open, the constructor sets the
            open flag (the driver stays untouched).
        policy: read-only policy that evaluates every payload before sending.

    `uds` and `guard` events go to the driver log (`connection.driver.log`).
    """

    def __init__(self, connection: ElmUdsConnection, policy: ReadOnlyPolicy) -> None:
        if not isinstance(policy, ReadOnlyPolicy):
            raise TypeError(f"ReadOnlyUdsClient requires ReadOnlyPolicy, got {type(policy).__name__}")
        if not isinstance(connection, ElmUdsConnection):
            raise TypeError(
                f"ReadOnlyUdsClient requires ElmUdsConnection, got {type(connection).__name__}"
            )
        self._connection = connection
        self._policy = policy
        if not connection.is_open():
            connection.open()
        self._client = Client(connection, config=UDS_CLIENT_CONFIG)

    # -- public methods (read only) -----------------------------------------

    def read_did(self, did: int) -> bytes:
        """`22 <DID>`; returns the data after the `62 DID` header (`RawDidCodec` interpretation).

        Raises:
            ReadOnlyViolation: payload rejected by the guard.
            UdsNegativeResponse (and `Nrc*`), NoResponse, ResponsePendingUnresolved,
            UnexpectedResponse: result of the exchange.
            AdapterResponseError, TransportError: from lower layers.
        """
        did = _require_int("did", did, 0xFFFF)
        checked = self._checked(bytes([SID_READ_DID]) + did.to_bytes(2, "big"))
        response = checked.response
        if response is None:
            raise UnexpectedResponse("No udsoncan response object for 0x22", exchange=checked.exchange)
        try:
            ReadDataByIdentifier.interpret_response(
                response,
                didlist=[did],
                didconfig=UDS_CLIENT_CONFIG["data_identifiers"],
                tolerate_zero_padding=True,
            )
        except (InvalidResponseException, UnexpectedResponseException, ConfigError, ValueError) as exc:
            raise UnexpectedResponse(
                f"Reply {checked.payload.hex().upper()} does not match DID 0x{did:04X}: {exc}",
                payload=checked.payload,
                exchange=checked.exchange,
            ) from exc
        values: Mapping[int, Any] = response.service_data.values
        if did not in values:
            raise UnexpectedResponse(
                f"Reply {checked.payload.hex().upper()} without DID 0x{did:04X}",
                payload=checked.payload,
                exchange=checked.exchange,
            )
        return bytes(values[did])

    def read_dids(self, dids: Sequence[int]) -> list[DidResponse]:
        """Sequential `read_did` for every DID (one DID per request).

        NRC, `NoResponse`, `ResponsePendingUnresolved` and `AdapterResponseError`
        with token `?` are recorded as a status. Other exceptions
        (`ReadOnlyViolation`, `TransportError`, `AdapterResponseError` with a
        different token, `UnexpectedResponse`) abort the series.
        """
        results: list[DidResponse] = []
        for did in dids:
            try:
                data = self.read_did(did)
            except UdsNegativeResponse as exc:
                results.append(self._did_result(did, DidStatus.NRC, exc.exchange, nrc=exc.nrc))
            except NoResponse as exc:
                results.append(self._did_result(did, DidStatus.NO_DATA, exc.exchange))
            except ResponsePendingUnresolved as exc:
                results.append(self._did_result(did, DidStatus.PENDING_UNRESOLVED, exc.exchange))
            except AdapterResponseError as exc:
                exchange = exc.exchange if isinstance(exc.exchange, UdsExchange) else None
                if exchange is None or exchange.error_token != _ADAPTER_UNSUPPORTED_TOKEN:
                    raise
                results.append(self._did_result(did, DidStatus.UNSUPPORTED, exchange))
            else:
                results.append(
                    self._did_result(did, DidStatus.OK, self._connection.last_exchange, data=data)
                )
        return results

    def read_dtcs(self, report: DtcReportType, status_mask: int = 0xFF) -> DtcReport:
        """`19 <sub> [mask]`; mask only for subfunctions 01 and 02.

        The result comes from the own parser `parse_dtc_report` (DTC 000000 skipped).
        """
        report = DtcReportType(report)
        mask = _require_int("status_mask", status_mask, 0xFF)
        payload = bytes([SID_READ_DTC, report])
        if report in _MASKED_REPORTS:
            payload += bytes([mask])
        checked = self._checked(payload)
        return parse_dtc_report(report, checked.payload)

    def read_dtc_snapshot(self, dtc: int, record: int) -> bytes:
        """`19 04 <DTC(3)> <record>`; returns the full reply payload `59 04 ...`.

        Record 0xFF (all records) is rejected by UdsGuard (`ReadOnlyViolation`).
        """
        dtc = _require_int("dtc", dtc, 0xFFFFFF)
        record = _require_int("record", record, 0xFF)
        checked = self._checked(bytes([SID_READ_DTC, 0x04]) + dtc.to_bytes(3, "big") + bytes([record]))
        raw = checked.payload
        if raw[:2] != bytes([SID_READ_DTC + _POSITIVE_OFFSET, 0x04]):
            raise UnexpectedResponse(
                f"Reply {raw.hex().upper()} does not match request 19 04",
                payload=raw,
                exchange=checked.exchange,
            )
        return raw

    def obd_read(self, mode: int, pid: int | None = None) -> bytes:
        """`<mode> [pid]`; returns the full reply payload (`mode + 0x40`, ...).

        Modes 01, 06 and 09 require `pid`; modes 03, 07 and 0A do not accept it.
        """
        mode = _require_int("mode", mode, 0xFF)
        if mode not in OBD_MODES:
            raise ValueError(f"obd_read supports OBD modes {sorted(OBD_MODES)}, got 0x{mode:02X}")
        payload = bytes([mode])
        if mode in OBD_MODES_WITH_PID:
            if pid is None:
                raise ValueError(f"OBD mode 0x{mode:02X} requires a PID")
            payload += bytes([_require_int("pid", pid, 0xFF)])
        elif pid is not None:
            raise ValueError(f"OBD mode 0x{mode:02X} does not accept a PID")
        return self._checked(payload).payload

    # -- the only send path -----------------------------------------------------

    def _checked(self, payload: bytes) -> CheckedResponse:
        """Guard, `uds` events and sending of one payload (the 5 steps of spec T5)."""
        data = bytes(payload)
        subject = data.hex().upper()
        decision = self._policy.check_uds(data)
        if not decision.allowed:
            self._emit(
                EventKind.GUARD,
                subject,
                guard={"decision": "rejected", "rule": decision.rule, "reason": decision.reason},
            )
            raise ReadOnlyViolation(LAYER_UDS, decision.rule, decision.reason or "", subject)

        self._emit(
            EventKind.UDS,
            subject,
            guard={"decision": "allowed", "rule": decision.rule, "reason": None},
            meta={"direction": "req"},
        )
        try:
            if data[0] in UDS_SIDS:
                result = self._send_uds(data)
            elif data[0] in OBD_MODES:
                result = self._send_obd(data)
            else:
                raise UdsError(f"No send path for SID 0x{data[0]:02X}")
        except Exception as exc:
            self._emit_response(None, exc)
            raise
        self._emit_response(result, None)
        return result

    def _send_uds(self, data: bytes) -> CheckedResponse:
        """Step 3: `Request.from_payload` and `Client.send_request` with exception mapping."""
        request = udsoncan.Request.from_payload(data)
        if request.service is None or request.get_payload() != data:
            raise UdsError(f"Payload {data.hex().upper()} changes after passing through udsoncan")
        try:
            response = self._client.send_request(request)
        except NegativeResponseException as exc:
            code = exc.response.code if exc.response.code is not None else 0
            raise negative_response_error(data[0], code, exchange=self._connection.last_exchange) from exc
        except TimeoutException as exc:
            raise self._timeout_error(data, pending_seen=False) from exc
        except (InvalidResponseException, UnexpectedResponseException) as exc:
            received = getattr(getattr(exc, "response", None), "original_payload", None)
            raise UnexpectedResponse(
                f"Invalid reply to {data.hex().upper()}: {exc}",
                payload=bytes(received) if received is not None else None,
                exchange=self._connection.last_exchange,
            ) from exc
        if response is None:
            raise NoResponse(
                f"No reply to {data.hex().upper()}", exchange=self._connection.last_exchange
            )
        return CheckedResponse(bytes(response.original_payload), response, self._connection.last_exchange)

    def _send_obd(self, data: bytes) -> CheckedResponse:
        """Step 4: `connection.send` and `wait_frame`, skipping `7F <mode> 78`."""
        mode = data[0]
        connection = self._connection
        connection.send(data)
        pending_seen = False
        while True:
            try:
                message = connection.wait_frame(exception=True)
            except TimeoutException as exc:
                raise self._timeout_error(data, pending_seen=pending_seen) from exc
            if message is None:
                raise self._timeout_error(data, pending_seen=pending_seen)
            message = bytes(message)
            if message[:1] == bytes([_NEGATIVE_SID]):
                if len(message) < 3 or message[1] != mode:
                    raise UnexpectedResponse(
                        f"Negative response {message.hex().upper()} does not refer to mode 0x{mode:02X}",
                        payload=message,
                        exchange=connection.last_exchange,
                    )
                if message[2] == NRC_RESPONSE_PENDING:
                    pending_seen = True
                    continue
                raise negative_response_error(mode, message[2], exchange=connection.last_exchange)
            if message[:1] != bytes([mode + _POSITIVE_OFFSET]):
                raise UnexpectedResponse(
                    f"Reply {message.hex().upper()} without prefix 0x{mode + _POSITIVE_OFFSET:02X}",
                    payload=message,
                    exchange=connection.last_exchange,
                )
            return CheckedResponse(message, None, connection.last_exchange)

    def _timeout_error(self, data: bytes, *, pending_seen: bool) -> UdsError:
        """Maps a missing reply according to `connection.last_exchange.outcome`."""
        exchange = self._connection.last_exchange
        subject = data.hex().upper()
        outcome = exchange.outcome if exchange is not None else None
        if outcome is ExchangeOutcome.PENDING_UNRESOLVED or (exchange is None and pending_seen):
            return ResponsePendingUnresolved(
                f"Only 7F {data[0]:02X} 78 without a final reply to {subject}", exchange=exchange
            )
        return NoResponse(f"No ECU reply to {subject}", exchange=exchange)

    # -- events -----------------------------------------------------------------

    def _emit_response(self, result: CheckedResponse | None, error: BaseException | None) -> None:
        """Step 5: `uds` event with `direction: resp` and the exchange `outcome`."""
        exchange = self._connection.last_exchange
        meta: dict[str, Any] = {"direction": "resp"}
        if exchange is not None:
            meta["outcome"] = str(exchange.outcome)
        else:
            meta["outcome"] = _OUTCOME_ERROR if error is not None else str(ExchangeOutcome.POSITIVE)
        data = ""
        if result is not None:
            data = result.payload.hex().upper()
        elif exchange is not None and exchange.final is not None:
            data = exchange.final.hex().upper()
        if isinstance(error, UdsNegativeResponse):
            meta["nrc"] = error.nrc
        if error is not None:
            meta["error"] = type(error).__name__
        self._emit(EventKind.UDS, data, meta=meta)

    def _emit(
        self,
        ev: EventKind,
        data: str,
        *,
        guard: Mapping[str, Any] | None = None,
        meta: Mapping[str, Any] | None = None,
    ) -> None:
        """Writes a `uds` layer event to the driver log (`connection.driver.log`)."""
        driver = self._connection.driver
        target = getattr(driver, "target", None)
        ecu = target.vag_address if target is not None else None
        driver.log.emit(str(ev), str(Layer.UDS), data, ecu=ecu, guard=guard, meta=meta)

    def _did_result(
        self,
        did: int,
        status: DidStatus,
        exchange: UdsExchange | None,
        *,
        data: bytes | None = None,
        nrc: int | None = None,
    ) -> DidResponse:
        elapsed = exchange.elapsed_ms if exchange is not None else None
        return DidResponse(did, status, data=data, nrc=nrc, elapsed_ms=elapsed, exchange=exchange)
