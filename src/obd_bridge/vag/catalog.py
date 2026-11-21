"""ECU catalog (`defs/ecu-catalog.yaml`, schema `obdb.ecu-catalog/1`).

The catalog is the addressee allowlist of the read-only policy: the driver and
the guard send frames only to CAN IDs from the `tx` fields of UDS modules. The
loader checks the type of every value explicitly (addresses and IDs must be
quoted strings, because YAML 1.2 reads `02` or `710` as a number) as well as
the range, uniqueness and FC rules from spec T7.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

from ruamel.yaml.error import YAMLError

from obd_bridge.errors import CatalogError
from obd_bridge.yamlio import load_yaml

__all__ = [
    "CATALOG_SCHEMA",
    "DEFAULT_CATALOG_PATH",
    "CatalogError",
    "Confidence",
    "EcuCatalog",
    "EcuTarget",
    "FcMode",
    "ModuleEntry",
    "NotAddressable",
    "Protocol",
    "UnknownModule",
]

CATALOG_SCHEMA = "obdb.ecu-catalog/1"
DEFAULT_CATALOG_PATH = Path("defs/ecu-catalog.yaml")

# VAG rule: reply = request + 0x6A; OBD pairs (01, 02) use + 8.
_REPLY_OFFSET = 0x6A
_OBD_PAIR_OFFSET = 8
_OBD_AUTO_TX = range(0x7E0, 0x7E8)
_ID_RANGE = range(0x700, 0x7F0)
_FUNCTIONAL_ID = 0x7DF
_TIMEOUT_RANGE = range(1, 5001)

_ADDRESS_RE = re.compile(r"^[0-9A-F]{2}$")
_CAN_ID_RE = re.compile(r"^[0-9A-F]{3}$")

_TOP_KEYS = frozenset({"schema", "reply_offset", "default_timeout_ms", "sources", "modules"})
_TOP_REQUIRED = ("schema", "reply_offset", "default_timeout_ms", "modules")
_MODULE_KEYS = frozenset(
    {"address", "name", "component", "protocol", "tx", "rx", "fc", "timeout_ms", "confidence", "note"}
)
_MODULE_REQUIRED = ("address", "name", "protocol", "confidence")
_UDS_ONLY_KEYS = ("tx", "rx", "fc", "timeout_ms")


class Protocol(StrEnum):
    """Diagnostic protocol of a module; only `uds` is addressable."""

    UDS = "uds"
    TP20 = "tp20"
    KWP = "kwp"
    UNKNOWN = "unknown"


class FcMode(StrEnum):
    """Flow Control mode: `auto` for OBD pairs, `pair` for an explicit STN pair."""

    AUTO = "auto"
    PAIR = "pair"


class Confidence(StrEnum):
    """Confidence of the CAN ID and protocol assignment."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class UnknownModule(CatalogError):
    """VAG address outside the catalog."""

    def __init__(self, address: str) -> None:
        self.address = address
        super().__init__(f"Module {address} is not in the ECU catalog")


class NotAddressable(CatalogError):
    """Catalog module without a known UDS CAN ID (e.g. `tp20`, `kwp`, `unknown`)."""

    def __init__(self, address: str, protocol: str) -> None:
        self.address = address
        self.protocol = protocol
        super().__init__(
            f"Module {address} is not addressable via UDS (protocol {protocol}, no CAN ID)"
        )


@dataclass(frozen=True)
class EcuTarget:
    """UDS addressee: CAN ID pair, FC mode and reply timeout."""

    vag_address: str
    tx_id: int
    rx_id: int
    fc_mode: Literal["auto", "pair"]
    protocol: Literal["uds"]
    timeout_ms: int


@dataclass(frozen=True)
class ModuleEntry:
    """Catalog entry; `target` is set only for a UDS module with `tx`."""

    address: str
    name: str
    protocol: Protocol
    confidence: Confidence
    component: str | None = None
    note: str | None = None
    target: EcuTarget | None = None


def _fail(where: str, message: str) -> CatalogError:
    return CatalogError(f"ECU catalog error ({where}): {message}")


def _require_str(value: Any, where: str, key: str) -> str:
    if not isinstance(value, str):
        raise _fail(
            where,
            f"field {key} must be a quoted string, got {type(value).__name__} {value!r}",
        )
    return value


def _require_timeout(value: Any, where: str, key: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value not in _TIMEOUT_RANGE:
        raise _fail(where, f"field {key} must be an integer 1..5000, got {value!r}")
    return value


def _parse_can_id(value: Any, where: str, key: str) -> int:
    text = _require_str(value, where, key)
    if not _CAN_ID_RE.match(text):
        raise _fail(where, f"field {key} must have 3 upper-case hex digits, got {text!r}")
    can_id = int(text, 16)
    if can_id == _FUNCTIONAL_ID:
        raise _fail(where, f"field {key} cannot point to the functional address 7DF")
    if can_id not in _ID_RANGE:
        raise _fail(where, f"field {key} out of range 700..7EF: {text}")
    return can_id


def _parse_enum[E: StrEnum](enum: type[E], value: Any, where: str, key: str) -> E:
    text = _require_str(value, where, key)
    try:
        return enum(text)
    except ValueError:
        allowed = ", ".join(member.value for member in enum)
        raise _fail(where, f"field {key} has an unknown value {text!r} (allowed: {allowed})") from None


def _optional_str(raw: Mapping[str, Any], where: str, key: str) -> str | None:
    if key not in raw:
        return None
    return _require_str(raw[key], where, key)


def _parse_target(
    raw: Mapping[str, Any], address: str, where: str, default_timeout_ms: int
) -> EcuTarget | None:
    if "tx" not in raw:
        for key in ("rx", "fc", "timeout_ms"):
            if key in raw:
                raise _fail(where, f"field {key} requires field tx")
        return None
    tx_id = _parse_can_id(raw["tx"], where, "tx")
    if "fc" not in raw:
        raise _fail(where, "field fc is required with tx")
    fc_mode = _parse_enum(FcMode, raw["fc"], where, "fc")
    rx_id = _parse_can_id(raw["rx"], where, "rx") if "rx" in raw else tx_id + _REPLY_OFFSET
    if rx_id == _FUNCTIONAL_ID:
        raise _fail(where, "derived rx cannot be the functional address 7DF")
    if rx_id not in _ID_RANGE:
        raise _fail(where, f"derived rx {rx_id:03X} out of range 700..7EF")
    if fc_mode is FcMode.AUTO:
        if tx_id not in _OBD_AUTO_TX:
            raise _fail(where, f"fc: auto requires tx in range 7E0..7E7, got {tx_id:03X}")
        if rx_id != tx_id + _OBD_PAIR_OFFSET:
            raise _fail(where, f"fc: auto requires rx = tx + 8 ({tx_id + _OBD_PAIR_OFFSET:03X}), got {rx_id:03X}")
    elif rx_id != tx_id + _REPLY_OFFSET:
        raise _fail(where, f"fc: pair requires rx = tx + 0x6A ({tx_id + _REPLY_OFFSET:03X}), got {rx_id:03X}")
    timeout_ms = (
        _require_timeout(raw["timeout_ms"], where, "timeout_ms")
        if "timeout_ms" in raw
        else default_timeout_ms
    )
    return EcuTarget(
        vag_address=address,
        tx_id=tx_id,
        rx_id=rx_id,
        fc_mode=fc_mode.value,
        protocol="uds",
        timeout_ms=timeout_ms,
    )


def _parse_module(raw: Any, index: int, default_timeout_ms: int) -> ModuleEntry:
    where = f"module no. {index + 1}"
    if not isinstance(raw, Mapping):
        raise _fail(where, "module entry must be a mapping")
    unknown = sorted(str(key) for key in raw if key not in _MODULE_KEYS)
    if unknown:
        raise _fail(where, f"unknown keys: {', '.join(unknown)}")
    for key in _MODULE_REQUIRED:
        if key not in raw:
            raise _fail(where, f"missing required field {key}")
    address = _require_str(raw["address"], where, "address")
    if not _ADDRESS_RE.match(address):
        raise _fail(where, f"address must have 2 upper-case hex digits, got {address!r}")
    where = f"module {address}"
    name = _require_str(raw["name"], where, "name")
    if not name.strip():
        raise _fail(where, "field name cannot be empty")
    protocol = _parse_enum(Protocol, raw["protocol"], where, "protocol")
    confidence = _parse_enum(Confidence, raw["confidence"], where, "confidence")
    if protocol is not Protocol.UDS:
        forbidden = [key for key in _UDS_ONLY_KEYS if key in raw]
        if forbidden:
            raise _fail(where, f"protocol {protocol} does not allow fields: {', '.join(forbidden)}")
        target = None
    else:
        target = _parse_target(raw, address, where, default_timeout_ms)
    return ModuleEntry(
        address=address,
        name=name,
        protocol=protocol,
        confidence=confidence,
        component=_optional_str(raw, where, "component"),
        note=_optional_str(raw, where, "note"),
        target=target,
    )


def _check_uniqueness(entries: list[ModuleEntry]) -> None:
    addresses: set[str] = set()
    tx_owner: dict[int, str] = {}
    rx_owner: dict[int, str] = {}
    for entry in entries:
        if entry.address in addresses:
            raise _fail(f"module {entry.address}", "duplicate address")
        addresses.add(entry.address)
        target = entry.target
        if target is None:
            continue
        if target.tx_id in tx_owner:
            raise _fail(
                f"module {entry.address}",
                f"tx {target.tx_id:03X} duplicated with module {tx_owner[target.tx_id]}",
            )
        if target.rx_id in rx_owner:
            raise _fail(
                f"module {entry.address}",
                f"rx {target.rx_id:03X} duplicated with module {rx_owner[target.rx_id]}",
            )
        tx_owner[target.tx_id] = entry.address
        rx_owner[target.rx_id] = entry.address
    for tx_id, address in tx_owner.items():
        if tx_id in rx_owner:
            raise _fail(
                f"module {address}",
                f"tx {tx_id:03X} is also the rx of module {rx_owner[tx_id]}",
            )


def _parse_document(data: Any) -> list[ModuleEntry]:
    where = "header"
    if not isinstance(data, Mapping):
        raise _fail(where, "document must be a mapping")
    unknown = sorted(str(key) for key in data if key not in _TOP_KEYS)
    if unknown:
        raise _fail(where, f"unknown keys: {', '.join(unknown)}")
    for key in _TOP_REQUIRED:
        if key not in data:
            raise _fail(where, f"missing required field {key}")
    schema = _require_str(data["schema"], where, "schema")
    if schema != CATALOG_SCHEMA:
        raise _fail(where, f"unsupported schema {schema!r}, expected {CATALOG_SCHEMA}")
    reply_offset = _require_str(data["reply_offset"], where, "reply_offset")
    if not _CAN_ID_RE.match(reply_offset) or int(reply_offset, 16) != _REPLY_OFFSET:
        raise _fail(where, f"reply_offset must have the value \"06A\", got {reply_offset!r}")
    default_timeout_ms = _require_timeout(data["default_timeout_ms"], where, "default_timeout_ms")
    sources = data.get("sources")
    if sources is not None:
        if not isinstance(sources, Mapping):
            raise _fail(where, "field sources must be a mapping")
        for key, value in sources.items():
            _require_str(value, where, f"sources.{key}")
    modules = data["modules"]
    if not isinstance(modules, list) or not modules:
        raise _fail(where, "field modules must be a non-empty list")
    entries = [_parse_module(raw, index, default_timeout_ms) for index, raw in enumerate(modules)]
    _check_uniqueness(entries)
    return entries


class EcuCatalog:
    """Validated ECU catalog; entries in file order."""

    def __init__(self, entries: list[ModuleEntry]) -> None:
        self._entries: tuple[ModuleEntry, ...] = tuple(entries)
        self._by_address: dict[str, ModuleEntry] = {entry.address: entry for entry in entries}
        self._targets: tuple[EcuTarget, ...] = tuple(
            entry.target for entry in entries if entry.target is not None
        )
        self._by_tx: dict[int, EcuTarget] = {target.tx_id: target for target in self._targets}

    @classmethod
    def load(cls, path: Path = DEFAULT_CATALOG_PATH) -> EcuCatalog:
        """Loads and validates the catalog; every violation of a T7 rule raises `CatalogError`."""
        if not Path(path).is_file():
            raise CatalogError(f"{path} not found. Run obdb from the project directory.")
        try:
            data = load_yaml(path)
        except YAMLError as error:
            raise CatalogError(f"Invalid YAML in ECU catalog {path}: {error}") from error
        return cls(_parse_document(data))

    def get(self, address: str) -> EcuTarget:
        """Returns the UDS addressee of a module; `UnknownModule` or `NotAddressable` if there is none."""
        key = address.strip().upper()
        entry = self._by_address.get(key)
        if entry is None:
            raise UnknownModule(key)
        if entry.target is None:
            raise NotAddressable(key, entry.protocol.value)
        return entry.target

    def entries(self) -> list[ModuleEntry]:
        """All catalog entries (including non-addressable ones)."""
        return list(self._entries)

    def all_uds(self) -> list[EcuTarget]:
        """UDS addressees with a known CAN ID, in file order."""
        return list(self._targets)

    def tx_ids(self) -> frozenset[int]:
        """Set of request CAN IDs (the guard addressee allowlist)."""
        return frozenset(self._by_tx)

    def rx_ids(self) -> frozenset[int]:
        """Set of reply CAN IDs."""
        return frozenset(target.rx_id for target in self._targets)

    def pair_of(self, tx_id: int) -> tuple[int, int] | None:
        """Pair `(tx, rx)` for a request CAN ID from the catalog; `None` for an ID outside the catalog."""
        target = self._by_tx.get(tx_id)
        if target is None:
            return None
        return (target.tx_id, target.rx_id)
