"""Offline readout of a probe file and comparison with a reference (`obdb report`).

The module reads an `obdb.probe/1` file written by `obdb probe --execute` and
turns its raw `STPX` items into identification values and DTC lists per VAG
module. With a reference file (`obdb.reference/1`, e.g. values copied from
the OBDeleven app) it compares both. It never opens a port and sends nothing.

Extraction rules:
    Steps with a non-null `repeat_of` are skipped (summary data comes only
    from the first execution of a step). Only `STPX H:<tx>,D:<payload>` items
    are used; the CAN ID `tx` is mapped to the VAG address via the ECU
    catalog. Payload `22 F1xx` gives an identification value, `19 02` the DTC
    list, `19 01` the DTC count and `19 0A` the supported DTCs. When the same
    read occurs more than once, the first positive reply wins; when no
    positive reply exists, the first failure is kept.

DTC records:
    A `19 02 FF` reply also lists records without a fault bit (status with
    only the `testNotCompleted...` bits, or 0x00). Such records are listed
    separately (`inactive_dtcs`), are not counted as DTCs and are never
    compared; an expected code read only without a fault bit stays `gone`.

DTC count (`19 01`):
    The value is shown as the module reports it and never compared. With
    the mask 0xFF sent by `obdb probe` the module also counts records
    without a fault bit, so the count can be higher than the number of
    DTCs from `19 02`.

Supported DTCs (`19 0A`):
    The reply lists every DTC the module supports, also those without a
    fault, so it is reported separately and never compared with the
    reference. The compared DTC list comes from `19 02`.

Hand-edited files:
    Values that YAML could read as numbers or timestamps (`nrc`, DIDs,
    software versions such as `0075`, dates) must be quoted strings, as
    `obdb probe` writes them; an unquoted `nrc: 0x31` is read as the number 49.

JSON document: `obdb.report/1`.
"""

from __future__ import annotations

import json
import re
import stat
import unicodedata
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from ruamel.yaml.error import YAMLError

from obd_bridge.errors import ReportInputError, os_error_text
from obd_bridge.stn.profile import PROBE_SCHEMA
from obd_bridge.uds.client import NRC_EXCEPTIONS, DtcReportType, UnexpectedResponse, parse_dtc_report
from obd_bridge.uds.dtc import (
    PRESENCE_ACTIVE,
    PRESENCE_NO_FAULT,
    decode_did_reply,
    did_name,
    dtc_presence,
    dtc_status_flags,
    format_dtc,
    is_fault_status,
    is_identification_did,
    parse_dtc,
)
from obd_bridge.vag.catalog import EcuCatalog
from obd_bridge.yamlio import load_yaml

__all__ = [
    "DIFFERS",
    "GONE",
    "MATCH",
    "NEW",
    "NOT_COMPARED",
    "NOT_IN_REFERENCE",
    "NOT_PROBED",
    "NOT_READ",
    "PRESENT_IN_BOTH",
    "REFERENCE_SCHEMA",
    "REPORT_SCHEMA",
    "DtcRead",
    "DtcView",
    "IdentRead",
    "ModuleReadout",
    "ProbeReadout",
    "Reference",
    "ReferenceModule",
    "build_report",
    "load_probe",
    "load_reference",
    "parse_reference",
    "readout_from_document",
    "render_report_json",
    "render_report_text",
]

REFERENCE_SCHEMA: Final[str] = "obdb.reference/1"
"""Schema of the reference file."""

REPORT_SCHEMA: Final[str] = "obdb.report/1"
"""Schema of the `obdb report --json` document."""

MATCH: Final[str] = "match"
DIFFERS: Final[str] = "differs"
NOT_READ: Final[str] = "not_read"
NOT_IN_REFERENCE: Final[str] = "not_in_reference"
NOT_PROBED: Final[str] = "not_probed"
NOT_COMPARED: Final[str] = "not_compared"
PRESENT_IN_BOTH: Final[str] = "present_in_both"
NEW: Final[str] = "new"
GONE: Final[str] = "gone"

_SID_READ_DID: Final[int] = 0x22
_SID_READ_DTC: Final[int] = 0x19
_HEX_RE: Final = re.compile(r"[0-9A-Fa-f]+")
_TX_RE: Final = re.compile(r"[0-9A-Fa-f]{3}")
_ADDRESS_RE: Final = re.compile(r"[0-9A-Fa-f]{2}")
_DID_RE: Final = re.compile(r"[0-9A-Fa-f]{4}")
_REFERENCE_KEYS: Final[frozenset[str]] = frozenset({"schema", "source", "modules"})
_REFERENCE_MODULE_KEYS: Final[frozenset[str]] = frozenset({"identification", "dtcs"})
_NOT_REQUESTED: Final[str] = "not requested in the probe"
_REQUESTS: Final[Mapping[int, str]] = {0x01: "19 01", 0x02: "19 02", 0x0A: "19 0A"}
_INDENT: Final[str] = "  "
_COMPARED: Final[str] = "compared"


# ---------------------------------------------------------------------------
# Readout model


@dataclass
class IdentRead:
    """One identification DID of a module: value, or the reason it was not read."""

    did: int
    value: str | None = None
    encoding: str | None = None
    step: int | None = None
    reason: str | None = None

    @property
    def ok(self) -> bool:
        return self.value is not None


@dataclass(frozen=True)
class DtcView:
    """DTC record with its decoded status."""

    code: int
    status: int

    @property
    def text(self) -> str:
        return format_dtc(self.code)

    @property
    def presence(self) -> str:
        return dtc_presence(self.status)

    @property
    def flags(self) -> tuple[str, ...]:
        return dtc_status_flags(self.status)


@dataclass
class DtcRead:
    """Result of a `19 xx` read: records (02, 0A) or count (01), or the reason it failed."""

    step: int | None = None
    reason: str | None = None
    records: tuple[DtcView, ...] = ()
    count: int | None = None

    @property
    def ok(self) -> bool:
        return self.reason is None


@dataclass
class ModuleReadout:
    """Everything read from one module (one request CAN ID)."""

    tx: int
    address: str | None
    name: str | None
    identification: dict[int, IdentRead] = field(default_factory=dict)
    dtcs: DtcRead | None = None
    dtc_count: DtcRead | None = None
    supported: DtcRead | None = None


@dataclass
class ProbeReadout:
    """Probe file metadata and module readouts in catalog order."""

    path: str
    session_id: str | None
    mode: str | None
    outcome: str | None
    started_at: str | None
    modules: list[ModuleReadout]


@dataclass(frozen=True)
class ReferenceModule:
    """Expected values of one module; `dtcs` None means DTCs are not compared."""

    identification: Mapping[int, str]
    dtcs: tuple[int, ...] | None


@dataclass(frozen=True)
class Reference:
    """Validated reference file."""

    path: str
    source: str | None
    modules: Mapping[str, ReferenceModule]


# ---------------------------------------------------------------------------
# Probe file


def _probe_error(path: str, message: str) -> ReportInputError:
    return ReportInputError(f"Probe file {path}: {message}")


def _load_mapping(path: Path, kind: str) -> Any:
    try:
        mode = path.stat().st_mode
    except OSError as exc:  # missing file, locked directory, path through a regular file
        raise ReportInputError(f"Cannot read {kind} file {path}: {os_error_text(exc)}") from exc
    if not stat.S_ISREG(mode):
        raise ReportInputError(f"Cannot read {kind} file {path}: not a regular file")
    try:
        return load_yaml(path)
    except OSError as exc:
        raise ReportInputError(f"Cannot read {kind} file {path}: {os_error_text(exc)}") from exc
    except UnicodeDecodeError as exc:
        raise ReportInputError(
            f"{kind.capitalize()} file {path} is not valid UTF-8 (invalid byte at position {exc.start})"
        ) from exc
    except YAMLError as exc:
        raise ReportInputError(f"Invalid YAML in {kind} file {path}: {exc}") from exc
    except RecursionError as exc:
        raise ReportInputError(f"Invalid YAML in {kind} file {path}: nesting too deep") from exc
    except Exception as exc:  # any other loader failure is an input error, not an internal one
        raise ReportInputError(f"Invalid YAML in {kind} file {path}: {type(exc).__name__}: {exc}") from exc


def load_probe(path: Path, catalog: EcuCatalog) -> ProbeReadout:
    """Loads an `obdb.probe/1` file and extracts the module readouts.

    Raises:
        ReportInputError: missing or unreadable file, invalid YAML, wrong
            schema or an invalid `checklist` structure (code 64).
    """
    document = _load_mapping(Path(path), "probe")
    return readout_from_document(document, catalog, path=str(path))


def _optional_text(document: Mapping[str, Any], key: str) -> str | None:
    value = document.get(key)
    return None if value is None else str(value)


def readout_from_document(document: Any, catalog: EcuCatalog, *, path: str = "<document>") -> ProbeReadout:
    """Module readouts from an already loaded probe document (see the module docstring for the rules)."""
    if not isinstance(document, dict):
        raise _probe_error(path, "the document is not a YAML mapping")
    schema = document.get("schema")
    if schema != PROBE_SCHEMA:
        raise _probe_error(path, f"schema {schema!r} instead of {PROBE_SCHEMA!r}")
    checklist = document.get("checklist")
    if not isinstance(checklist, list):
        raise _probe_error(path, "field 'checklist' must be a list")

    addresses = {target.tx_id: target.vag_address for target in catalog.all_uds()}
    names = {entry.address: entry.name for entry in catalog.entries()}
    modules: dict[int, ModuleReadout] = {}
    for index, step in enumerate(checklist):
        where = f"checklist[{index}]"
        if not isinstance(step, dict):
            raise _probe_error(path, f"{where} is not a mapping")
        items = step.get("items")
        if not isinstance(items, list):
            raise _probe_error(path, f"{where}.items must be a list")
        if step.get("repeat_of") is not None:
            continue
        number = step.get("step")
        step_number = number if isinstance(number, int) and not isinstance(number, bool) else None
        for position, item in enumerate(items):
            if not isinstance(item, dict) or not isinstance(item.get("line"), str):
                raise _probe_error(path, f"{where}.items[{position}] must be a mapping with a string 'line'")
            parsed = _stpx_fields(item["line"])
            if parsed is None:
                continue
            tx, payload = parsed
            module = modules.get(tx)
            if module is None:
                address = addresses.get(tx)
                module = ModuleReadout(tx=tx, address=address, name=names.get(address) if address else None)
                modules[tx] = module
            _apply_item(module, payload, item, step_number)

    order = {target.tx_id: position for position, target in enumerate(catalog.all_uds())}
    ordered = sorted(modules.values(), key=lambda module: (order.get(module.tx, len(order)), module.tx))
    return ProbeReadout(
        path=path,
        session_id=_optional_text(document, "session_id"),
        mode=_optional_text(document, "mode"),
        outcome=_optional_text(document, "outcome"),
        started_at=_optional_text(document, "started_at"),
        modules=ordered,
    )


def _stpx_fields(line: str) -> tuple[int, bytes] | None:
    """`(tx, payload)` from `STPX H:<tx>,D:<payload>[,...]`; None for any other line."""
    if not line.startswith("STPX "):
        return None
    fields: dict[str, str] = {}
    for part in line[5:].split(","):
        key, separator, value = part.partition(":")
        if separator:
            fields[key.strip().upper()] = value.strip()
    tx, payload = fields.get("H", ""), fields.get("D", "")
    if not _TX_RE.fullmatch(tx) or not _HEX_RE.fullmatch(payload) or len(payload) % 2:
        return None
    return int(tx, 16), bytes.fromhex(payload)


def _failure_reason(item: Mapping[str, Any]) -> str | None:
    """Reason an item gave no usable reply; None for `ok`."""
    result = item.get("result")
    if result == "ok":
        return None
    if result == "nrc":
        nrc = str(item.get("nrc") or "").upper()
        try:
            description = NRC_EXCEPTIONS[int(nrc, 16)].description
        except (KeyError, ValueError):
            description = None
        return f"NRC 0x{nrc}, {description}" if description else f"NRC 0x{nrc or '??'}"
    if result == "no_data":
        return "NO DATA"
    if result == "pending_unresolved":
        return "NRC 0x78 without a final reply"
    if result == "unsupported":
        return "adapter replied ?"
    if result == "skipped":
        return "skipped"
    if result == "error":
        return str(item.get("error") or item.get("response") or "error")
    return f"result {result!r}"


def _reply_bytes(item: Mapping[str, Any]) -> tuple[bytes | None, str | None]:
    """Reply bytes of an `ok` item, or `(None, reason)`."""
    reason = _failure_reason(item)
    if reason is not None:
        return None, reason
    response = item.get("response")
    if not isinstance(response, str) or not _HEX_RE.fullmatch(response) or len(response) % 2:
        return None, f"reply is not hex: {response!r}"
    return bytes.fromhex(response), None


def _apply_item(module: ModuleReadout, payload: bytes, item: Mapping[str, Any], step: int | None) -> None:
    if len(payload) == 3 and payload[0] == _SID_READ_DID:
        did = int.from_bytes(payload[1:3], "big")
        if is_identification_did(did):
            current = module.identification.get(did)
            new = _ident_read(did, item, step)
            if current is None or (not current.ok and new.ok):
                module.identification[did] = new
        return
    if len(payload) >= 2 and payload[0] == _SID_READ_DTC and payload[1] in _REQUESTS:
        subfunction = payload[1]
        read = _dtc_read(subfunction, item, step)
        if subfunction == DtcReportType.BY_MASK:
            module.dtcs = _first_positive(module.dtcs, read)
        elif subfunction == DtcReportType.NUMBER_BY_MASK:
            module.dtc_count = _first_positive(module.dtc_count, read)
        else:
            module.supported = _first_positive(module.supported, read)


def _first_positive(current: DtcRead | None, new: DtcRead) -> DtcRead:
    """First positive read; without one, the first failure."""
    if current is None or (not current.ok and new.ok):
        return new
    return current


def _ident_read(did: int, item: Mapping[str, Any], step: int | None) -> IdentRead:
    reply, reason = _reply_bytes(item)
    if reply is None:
        return IdentRead(did=did, step=step, reason=reason)
    try:
        value = decode_did_reply(reply)
    except ValueError as exc:
        return IdentRead(did=did, step=step, reason=str(exc))
    if value.did != did:
        return IdentRead(did=did, step=step, reason=f"reply for another DID: {reply.hex().upper()}")
    return IdentRead(did=did, value=value.text, encoding=value.encoding, step=step)


def _dtc_read(subfunction: int, item: Mapping[str, Any], step: int | None) -> DtcRead:
    reply, reason = _reply_bytes(item)
    if reply is None:
        return DtcRead(step=step, reason=reason)
    try:
        report = parse_dtc_report(DtcReportType(subfunction), reply)
    except UnexpectedResponse as exc:
        return DtcRead(step=step, reason=str(exc))
    records = tuple(DtcView(record.dtc, record.status) for record in report.records)
    return DtcRead(step=step, records=records, count=report.count)


# ---------------------------------------------------------------------------
# Reference file


def _reference_error(path: str, message: str) -> ReportInputError:
    return ReportInputError(f"Reference file {path}: {message}")


def load_reference(path: Path) -> Reference:
    """Loads and validates an `obdb.reference/1` file.

    Raises:
        ReportInputError: missing file, invalid YAML or any schema violation (code 64).
    """
    return parse_reference(_load_mapping(Path(path), "reference"), path=str(path))


def _quoted_hint(value: Any) -> str:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return " (quote the value: YAML reads unquoted digits as a number)"
    return ""


def parse_reference(document: Any, *, path: str = "<document>") -> Reference:
    """Validates a loaded reference document strictly (see `REFERENCE_SCHEMA`)."""
    if not isinstance(document, dict):
        raise _reference_error(path, "the document is not a YAML mapping")
    unknown = sorted(str(key) for key in document if key not in _REFERENCE_KEYS)
    if unknown:
        raise _reference_error(path, f"unknown top-level keys: {', '.join(unknown)}")
    if document.get("schema") != REFERENCE_SCHEMA:
        raise _reference_error(path, f"schema {document.get('schema')!r} instead of {REFERENCE_SCHEMA!r}")
    source = document.get("source")
    if source is not None and not isinstance(source, str):
        raise _reference_error(path, "field 'source' must be a string")
    raw_modules = document.get("modules")
    if not isinstance(raw_modules, dict):
        raise _reference_error(path, "field 'modules' must be a mapping of module addresses")

    modules: dict[str, ReferenceModule] = {}
    for key, raw in raw_modules.items():
        if not isinstance(key, str) or not _ADDRESS_RE.fullmatch(key):
            raise _reference_error(
                path, f"module key {key!r} must be a quoted two-digit hex address, e.g. \"19\"{_quoted_hint(key)}"
            )
        address = key.upper()
        if address in modules:
            raise _reference_error(path, f"module {address} is listed twice")
        modules[address] = _reference_module(path, address, raw)
    return Reference(path=path, source=source, modules=modules)


def _reference_module(path: str, address: str, raw: Any) -> ReferenceModule:
    where = f"module {address}"
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise _reference_error(path, f"{where} must be a mapping")
    unknown = sorted(str(key) for key in raw if key not in _REFERENCE_MODULE_KEYS)
    if unknown:
        raise _reference_error(path, f"{where}: unknown keys: {', '.join(unknown)}")

    identification: dict[int, str] = {}
    raw_ident = raw.get("identification")
    if raw_ident is not None:
        if not isinstance(raw_ident, dict):
            raise _reference_error(path, f"{where}: 'identification' must be a mapping of DID to value")
        for did_key, value in raw_ident.items():
            if not isinstance(did_key, str) or not _DID_RE.fullmatch(did_key):
                raise _reference_error(
                    path, f"{where}: DID {did_key!r} must be four hex digits, e.g. F187{_quoted_hint(did_key)}"
                )
            did = int(did_key, 16)
            if not is_identification_did(did):
                raise _reference_error(
                    path, f"{where}: DID {did_key.upper()} is outside the identification range F100..F1FF"
                )
            if did in identification:
                raise _reference_error(path, f"{where}: DID {did_key.upper()} is listed twice")
            if not isinstance(value, str):
                raise _reference_error(
                    path, f"{where}: value of DID {did_key.upper()} must be a string{_quoted_hint(value)}"
                )
            identification[did] = value

    dtcs: tuple[int, ...] | None = None
    if "dtcs" in raw:
        raw_dtcs = raw["dtcs"]
        if not isinstance(raw_dtcs, list):
            raise _reference_error(path, f"{where}: 'dtcs' must be a list (an empty list means no DTCs expected)")
        codes: list[int] = []
        for value in raw_dtcs:
            try:
                code = parse_dtc(value)
            except ValueError as exc:
                raise _reference_error(path, f"{where}: {exc}") from exc
            if code in codes:
                raise _reference_error(path, f"{where}: DTC {format_dtc(code)} is listed twice")
            codes.append(code)
        dtcs = tuple(codes)
    return ReferenceModule(identification=identification, dtcs=dtcs)


# ---------------------------------------------------------------------------
# Report document


def _compare_values(read: str, expected: str) -> str:
    return MATCH if read.strip() == expected.strip() else DIFFERS


def _ident_entries(module: ModuleReadout | None, expected: Mapping[int, str] | None) -> list[dict[str, Any]]:
    reads = module.identification if module is not None else {}
    dids = sorted(set(reads) | set(expected or {}))
    entries: list[dict[str, Any]] = []
    for did in dids:
        read = reads.get(did)
        reference = expected.get(did) if expected is not None else None
        comparison: str | None = None
        if expected is not None:
            if reference is None:
                comparison = NOT_IN_REFERENCE if read is not None and read.ok else None
            elif read is None or read.value is None:
                comparison = NOT_READ
            else:
                comparison = _compare_values(read.value, reference)
        entries.append(
            {
                "did": f"{did:04X}",
                "name": did_name(did),
                "read": read is not None and read.ok,
                "value": read.value if read is not None else None,
                "encoding": read.encoding if read is not None else None,
                "step": read.step if read is not None else None,
                "reason": _ident_reason(read),
                "reference": reference,
                "comparison": comparison,
            }
        )
    return entries


def _ident_reason(read: IdentRead | None) -> str | None:
    if read is None:
        return _NOT_REQUESTED
    return None if read.ok else read.reason


def _dtc_entry(view: DtcView, comparison: str | None) -> dict[str, Any]:
    return {
        "code": view.text,
        "dtc": f"{view.code:06X}",
        "status": f"0x{view.status:02X}",
        "presence": view.presence,
        "flags": list(view.flags),
        "comparison": comparison,
    }


def _dtc_block(
    module: ModuleReadout | None, reference: ReferenceModule | None, has_reference: bool
) -> dict[str, Any] | None:
    read = module.dtcs if module is not None else None
    expected = reference.dtcs if reference is not None else None
    if read is None and expected is None:
        return None
    ok = read is not None and read.ok
    if not has_reference:
        comparison = None
    elif expected is None:
        comparison = NOT_COMPARED
    elif not ok:
        comparison = NOT_READ
    else:
        comparison = _COMPARED
    records: list[dict[str, Any]] = []
    inactive: list[dict[str, Any]] = []
    gone: list[dict[str, Any]] = []
    if ok and read is not None:
        faults = [view for view in read.records if is_fault_status(view.status)]
        without_fault = {view.code for view in read.records if not is_fault_status(view.status)}
        fault_codes = {view.code for view in faults}
        for view in faults:
            mark = None
            if comparison == _COMPARED and expected is not None:
                mark = PRESENT_IN_BOTH if view.code in expected else NEW
            records.append(_dtc_entry(view, mark))
        inactive = [_dtc_entry(view, None) for view in read.records if not is_fault_status(view.status)]
        if comparison == _COMPARED and expected is not None:
            gone = [
                {"code": format_dtc(code), "read_without_fault_bit": code in without_fault}
                for code in expected
                if code not in fault_codes
            ]
    return {
        "request": "19 02",
        "read": ok,
        "step": read.step if read is not None else None,
        "reason": None if ok else (read.reason if read is not None else _NOT_REQUESTED),
        "count": len(records) if ok else None,
        "records": records,
        "inactive_dtcs": inactive,
        "reference": [format_dtc(code) for code in expected] if expected is not None else None,
        "gone": gone,
        "comparison": comparison,
    }


def _count_block(read: DtcRead | None, request: str, *, with_records: bool) -> dict[str, Any] | None:
    if read is None:
        return None
    block: dict[str, Any] = {
        "request": request,
        "read": read.ok,
        "step": read.step,
        "reason": read.reason,
        "count": read.count if read.ok else None,
    }
    if with_records:
        block["records"] = [_dtc_entry(view, None) for view in read.records] if read.ok else []
    return block


def _module_document(
    address: str | None,
    name: str | None,
    module: ModuleReadout | None,
    reference: ReferenceModule | None,
    has_reference: bool,
) -> dict[str, Any]:
    probed = module is not None
    expected_ident: Mapping[int, str] | None = None
    if has_reference:
        expected_ident = reference.identification if reference is not None else {}
    return {
        "address": address,
        "name": name,
        "tx": f"{module.tx:03X}" if module is not None else None,
        "probed": probed,
        "in_reference": reference is not None,
        "comparison": NOT_PROBED if not probed and reference is not None else None,
        "identification": _ident_entries(module, expected_ident) if probed else [],
        "dtcs": _dtc_block(module, reference, has_reference) if probed else None,
        "dtc_count": _count_block(module.dtc_count if module else None, "19 01", with_records=False),
        "supported_dtcs": _count_block(module.supported if module else None, "19 0A", with_records=True),
    }


def _summary(modules: Sequence[Mapping[str, Any]], has_reference: bool) -> dict[str, Any]:
    identification = [entry for module in modules for entry in module["identification"]]
    dtc_blocks = [module["dtcs"] for module in modules if module["dtcs"] is not None]
    records = [record for block in dtc_blocks for record in block["records"]]
    summary: dict[str, Any] = {
        "modules": len(modules),
        "modules_probed": sum(1 for module in modules if module["probed"]),
        "identification_read": sum(1 for entry in identification if entry["read"]),
        "identification_not_read": sum(
            1 for entry in identification if not entry["read"] and entry["step"] is not None
        ),
        "dtcs": len(records),
        "dtcs_active": sum(1 for record in records if record["presence"] == PRESENCE_ACTIVE),
        "dtcs_without_fault_bit": sum(len(block["inactive_dtcs"]) for block in dtc_blocks),
        "comparison": None,
    }
    if has_reference:
        marks = [entry["comparison"] for entry in identification]
        dtc_marks = [record["comparison"] for record in records]
        summary["comparison"] = {
            "modules_not_probed": sum(1 for module in modules if module["comparison"] == NOT_PROBED),
            "identification": {key: marks.count(key) for key in (MATCH, DIFFERS, NOT_READ, NOT_IN_REFERENCE)},
            "dtcs": {
                PRESENT_IN_BOTH: dtc_marks.count(PRESENT_IN_BOTH),
                NEW: dtc_marks.count(NEW),
                GONE: sum(len(block["gone"]) for block in dtc_blocks),
                "lists_not_read": sum(1 for block in dtc_blocks if block["comparison"] == NOT_READ),
                "lists_not_compared": sum(1 for block in dtc_blocks if block["comparison"] == NOT_COMPARED),
            },
        }
    return summary


def build_report(readout: ProbeReadout, catalog: EcuCatalog, reference: Reference | None = None) -> dict[str, Any]:
    """The `obdb.report/1` document: probe metadata, modules and summary counts."""
    has_reference = reference is not None
    expected = reference.modules if reference is not None else {}
    by_address = {module.address: module for module in readout.modules if module.address is not None}
    names = {entry.address: entry.name for entry in catalog.entries()}
    modules: list[dict[str, Any]] = []
    seen: set[str] = set()
    for entry in catalog.entries():
        module = by_address.get(entry.address)
        if module is None and entry.address not in expected:
            continue
        seen.add(entry.address)
        modules.append(_module_document(entry.address, entry.name, module, expected.get(entry.address), has_reference))
    for module in readout.modules:
        if module.address is None:
            modules.append(_module_document(None, None, module, None, has_reference))
    for address in sorted(set(expected) - seen):
        modules.append(_module_document(address, names.get(address), None, expected[address], has_reference))
    return {
        "schema": REPORT_SCHEMA,
        "probe": {
            "path": readout.path,
            "session_id": readout.session_id,
            "mode": readout.mode,
            "outcome": readout.outcome,
            "started_at": readout.started_at,
        },
        "reference": {"path": reference.path, "source": reference.source} if reference is not None else None,
        "modules": modules,
        "summary": _summary(modules, has_reference),
    }


def render_report_json(document: Mapping[str, Any]) -> str:
    """The `obdb.report/1` document as JSON."""
    return json.dumps(document, ensure_ascii=False, indent=2)


# ---------------------------------------------------------------------------
# Text output


# Unicode categories escaped in text output: control (Cc), format (Cf, e.g. U+202E
# right-to-left override), line separator (Zl, U+2028) and paragraph separator (Zp, U+2029).
_ESCAPED_CATEGORIES: Final = frozenset({"Cc", "Cf", "Zl", "Zp"})


def _printable(text: str) -> str:
    """Text with control, format and line or paragraph separator characters replaced by visible escapes.

    Examples: `\\n`, `\\x1b`, `\\u202e`, `\\u2028`.
    """
    return "".join(
        char.encode("unicode_escape").decode("ascii") if unicodedata.category(char) in _ESCAPED_CATEGORIES else char
        for char in text
    )


def _mark(comparison: str | None, reference: str | None = None) -> str:
    if comparison is None:
        return ""
    if comparison == DIFFERS:
        return f"differs (reference: {reference})"
    return comparison.replace("_", " ")


def _rows(rows: Iterable[Sequence[str]], indent: str) -> list[str]:
    """Rows with left-aligned columns separated by two spaces."""
    body = [list(row) for row in rows]
    if not body:
        return []
    body = [[_printable(cell) for cell in row] for row in body]
    widths = [max(len(row[index]) for row in body) for index in range(len(body[0]))]
    return [
        (indent + "  ".join(cell.ljust(widths[index]) for index, cell in enumerate(row))).rstrip()
        for row in body
    ]


def _ident_value(entry: Mapping[str, Any]) -> str:
    if entry["read"]:
        value = str(entry["value"])
        return f"{value} (hex)" if entry["encoding"] == "hex" else (value or "(empty)")
    return f"(not read: {entry['reason']})"


def _step_note(block: Mapping[str, Any]) -> str:
    return f"{block['request']}, step {block['step']}" if block["step"] is not None else block["request"]


def _module_title(module: Mapping[str, Any]) -> str:
    address = module["address"] or "??"
    parts = [f"Module {address}"]
    if module["name"]:
        parts.append(str(module["name"]))
    if module["tx"]:
        parts.append(f"(tx {module['tx']})")
    if module["address"] is None or module["name"] is None:
        parts.append("(not in the ECU catalog)")
    return " ".join(parts)


def _module_lines(module: Mapping[str, Any], has_reference: bool) -> list[str]:
    if not module["probed"]:
        return [f"{_module_title(module)}: not probed"]
    out = [_module_title(module)]
    if module["identification"]:
        out.append(f"{_INDENT}Identification:")
        out.extend(
            _rows(
                (
                    (
                        entry["did"],
                        entry["name"] or "unknown DID",
                        _ident_value(entry),
                        *([_mark(entry["comparison"], entry["reference"])] if has_reference else []),
                    )
                    for entry in module["identification"]
                ),
                _INDENT * 2,
            )
        )
    dtcs = module["dtcs"]
    if dtcs is not None:
        if dtcs["read"]:
            header = f"{_INDENT}DTCs ({_step_note(dtcs)}): {dtcs['count']}"
        else:
            header = f"{_INDENT}DTCs ({_step_note(dtcs)}): not read: {dtcs['reason']}"
        if dtcs["comparison"] == NOT_COMPARED:
            header += f" [{_mark(NOT_COMPARED)}]"
        out.append(header)
        rows = [
            (
                record["code"],
                record["status"],
                record["presence"],
                ", ".join(record["flags"]) or "-",
                *([_mark(record["comparison"])] if has_reference else []),
            )
            for record in dtcs["records"]
        ]
        rows.extend(
            (
                entry["code"],
                "-",
                "-",
                "-",
                _mark(GONE) + (" (read without a fault bit)" if entry["read_without_fault_bit"] else ""),
            )
            for entry in dtcs["gone"]
        )
        if dtcs["comparison"] == NOT_READ and dtcs["reference"]:
            rows.extend((code, "-", "-", "-", "expected, not read") for code in dtcs["reference"])
        out.extend(_rows(rows, _INDENT * 2))
        if dtcs["inactive_dtcs"]:
            out.append(f"{_INDENT}Records without a fault bit: {len(dtcs['inactive_dtcs'])} (not compared)")
            out.extend(
                _rows(
                    (
                        (record["code"], record["status"], record["presence"], ", ".join(record["flags"]) or "-")
                        for record in dtcs["inactive_dtcs"]
                    ),
                    _INDENT * 2,
                )
            )
    count = module["dtc_count"]
    if count is not None:
        value = (
            f"{count['count']} (as reported by the module; may include records without a fault bit)"
            if count["read"]
            else f"not read: {count['reason']}"
        )
        out.append(f"{_INDENT}DTC count ({_step_note(count)}): {value}")
    supported = module["supported_dtcs"]
    if supported is not None:
        if supported["read"]:
            faulty = sum(1 for record in supported["records"] if record["presence"] != PRESENCE_NO_FAULT)
            value = f"{supported['count']} records, {faulty} with a fault bit (not compared)"
        else:
            value = f"not read: {supported['reason']}"
        out.append(f"{_INDENT}Supported DTCs ({_step_note(supported)}): {value}")
    if len(out) == 1:
        out.append(f"{_INDENT}(no identification or DTC reads)")
    return out


def _summary_line(summary: Mapping[str, Any]) -> str:
    comparison = summary["comparison"]
    if comparison is None:
        return (
            f"Summary: {summary['modules_probed']} modules probed; identification: "
            f"{summary['identification_read']} read, {summary['identification_not_read']} not read; "
            f"DTCs: {summary['dtcs']} ({summary['dtcs_active']} active), "
            f"records without a fault bit: {summary['dtcs_without_fault_bit']}."
        )
    ident = comparison["identification"]
    dtcs = comparison["dtcs"]
    return (
        f"Summary: {summary['modules']} modules, {comparison['modules_not_probed']} not probed; "
        f"identification: {ident[MATCH]} match, {ident[DIFFERS]} differs, {ident[NOT_READ]} not read, "
        f"{ident[NOT_IN_REFERENCE]} not in reference; DTCs: {dtcs[PRESENT_IN_BOTH]} present in both, "
        f"{dtcs[NEW]} new, {dtcs[GONE]} gone, lists not read: {dtcs['lists_not_read']}, "
        f"lists not compared: {dtcs['lists_not_compared']}."
    )


def render_report_text(document: Mapping[str, Any]) -> str:
    """Report as text: header, one block per module, summary line."""
    probe = document["probe"]
    reference = document["reference"]
    has_reference = reference is not None
    out = [
        f"Probe file: {probe['path']}",
        (
            f"Session: {probe['session_id'] or 'unknown'}, mode {probe['mode'] or 'unknown'}, "
            f"outcome {probe['outcome'] or 'unknown'}, started {probe['started_at'] or 'unknown'}"
        ),
    ]
    if has_reference:
        source = f" ({reference['source']})" if reference["source"] else ""
        out.append(f"Reference: {reference['path']}{source}")
    for module in document["modules"]:
        out.append("")
        out.extend(_module_lines(module, has_reference))
    if not document["modules"]:
        out.extend(["", "No module reads in the probe file."])
    out.extend(["", _summary_line(document["summary"])])
    return "\n".join(_printable(line) for line in out)
