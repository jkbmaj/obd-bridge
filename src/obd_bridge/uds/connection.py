"""Layer L2: udsoncan connection over the STN driver (spec T5, FR-18).

`ElmUdsConnection` implements the `udsoncan.connections.BaseConnection`
contract without its own thread or transport. `specific_send` blocks until
`StnDriver.transact` finishes (`STPX` line, reply up to the `>` character) and
puts the assembled messages into the receive queue before returning.
`Client.send_request` starts counting the overall limit only after
`conn.send()`, so the time of the blocking exchange does not use up
`request_timeout` or `p2_timeout`.

Every write to the adapter goes through `driver.transact`, that is through the
UdsGuard in the driver's `_egress`. `open()` and `close()` change only the
connection flag: the caller manages the driver lifecycle.
"""

from __future__ import annotations

import logging
from collections import deque
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any, Final

from udsoncan.common.DidCodec import DidCodec
from udsoncan.connections import BaseConnection
from udsoncan.exceptions import TimeoutException

from obd_bridge.errors import AdapterResponseError
from obd_bridge.stn.driver import StnDriver
from obd_bridge.stn.parser import ExchangeOutcome, UdsExchange

__all__ = [
    "UDS_CLIENT_CONFIG",
    "ElmUdsConnection",
    "RawDidCodec",
]


class RawDidCodec(DidCodec):
    """DID codec without interpretation: data after the `62 DID` header as raw bytes.

    `__len__` raises `DidCodec.ReadAllRemainingData`, so udsoncan passes the
    whole rest of the reply to `decode` (one DID per request). Encoding does not
    exist, because the bridge API does not write DIDs.
    """

    def encode(self, *did_value: Any) -> bytes:
        """Always `NotImplementedError`: writing a DID does not exist in the API."""
        raise NotImplementedError("RawDidCodec does not encode values: writing a DID is not supported")

    def decode(self, did_payload: bytes) -> bytes:
        """Returns the DID data unchanged."""
        return bytes(did_payload)

    def __len__(self) -> int:
        """Length not known in advance: read the whole remaining part of the reply."""
        raise DidCodec.ReadAllRemainingData


# `ignore_all_zero_dtc` intentionally not set (audit m14): it works only in
# the `get_dtc_*` methods, which the client does not use; DTC 0x000000 is
# skipped by the own parser. `Client` copies the configuration and fills in
# missing keys with udsoncan defaults.
UDS_CLIENT_CONFIG: Final[Mapping[str, Any]] = MappingProxyType(
    {
        "exception_on_negative_response": True,
        "exception_on_invalid_response": True,
        "exception_on_unexpected_response": True,
        "tolerate_zero_padding": True,
        "request_timeout": 5.0,
        "p2_timeout": 1.0,
        "p2_star_timeout": 5.0,
        "use_server_timing": False,
        "data_identifiers": MappingProxyType({"default": RawDidCodec}),
    }
)

# Outcomes for which all assembled messages go to the queue.
_QUEUED_OUTCOMES: Final[frozenset[ExchangeOutcome]] = frozenset(
    {
        ExchangeOutcome.POSITIVE,
        ExchangeOutcome.NEGATIVE,
        ExchangeOutcome.PENDING_UNRESOLVED,
    }
)


class ElmUdsConnection(BaseConnection):
    """udsoncan connection over `StnDriver` with a blocking `specific_send`.

    Parameters:
        driver: driver in state TARGET_SELECTED (with a selected target).

    Attributes:
        driver: L1 driver; the only write path is `driver.transact`.
        name: `ElmUdsConnection[<target VAG address>]` at creation time.
        last_exchange: last exchange from `transact`, or `None` (before the
            first send and when `transact` raised an exception).
    """

    def __init__(self, driver: StnDriver) -> None:
        super().__init__()
        target = driver.target
        address = target.vag_address if target is not None else "?"
        self.name = f"ElmUdsConnection[{address}]"
        self.logger = logging.getLogger(self.name)
        self.driver = driver
        self.last_exchange: UdsExchange | None = None
        self._rxqueue: deque[bytes] = deque()
        self._opened = False

    # -- lifecycle (flag only) -----------------------------------------------

    def open(self) -> ElmUdsConnection:
        """Sets the open flag; the driver is not opened."""
        self._opened = True
        return self

    def close(self) -> None:
        """Clears the open flag and the queue; the driver is not closed."""
        self._opened = False
        self._rxqueue.clear()

    def is_open(self) -> bool:
        """Whether the connection is open (flag set by `open`)."""
        return self._opened

    # -- send and receive -----------------------------------------------------

    def specific_send(self, payload: bytes, timeout: float | None = None) -> None:
        """One request through `driver.transact`, blocking; replies go to the queue.

        The `timeout` parameter is ignored: the exchange limit is set by the
        driver (the target's `timeout_ms`). The queue is cleared before sending,
        so it contains only messages of the current exchange.

        `outcome` mapping (spec T5):
            `positive`, `negative`: all messages in order, including
                `7F xx 78` (udsoncan handles 0x78 natively);
            `pending_unresolved`: the `7F xx 78` messages;
            `no_data`: empty queue;
            `adapter_error`, `incomplete`, `unparsed`: `AdapterResponseError`.

        Raises:
            AdapterResponseError: adapter reply not usable (code 3).
            ReadOnlyViolation, DriverError, TransportError: from the driver, unchanged.
        """
        self._rxqueue.clear()
        self.last_exchange = None
        exchange = self.driver.transact(bytes(payload))
        self.last_exchange = exchange
        if exchange.outcome in _QUEUED_OUTCOMES:
            self._rxqueue.extend(exchange.messages)
            return
        if exchange.outcome is ExchangeOutcome.NO_DATA:
            return
        token = f", token {exchange.error_token}" if exchange.error_token else ""
        raise AdapterResponseError(
            exchange,
            f"Adapter reply without UDS data (outcome {exchange.outcome}{token}) for {self.name}",
        )

    def specific_wait_frame(self, timeout: float | None = None) -> bytes | None:
        """Returns the next message from the queue without waiting.

        The reply is complete after `specific_send` returns, so an empty queue
        means no further messages regardless of `timeout`.

        Raises:
            TimeoutException: empty queue.
        """
        if not self._rxqueue:
            raise TimeoutException(f"No message in the receive queue of {self.name}")
        return self._rxqueue.popleft()

    def empty_rxqueue(self) -> None:
        """Clears the receive queue."""
        self._rxqueue.clear()
