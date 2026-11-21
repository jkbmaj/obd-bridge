"""Plan of the `obdb probe` probe: DID constants and the list of 25 steps (spec T9, FR-23, FR-26).

Step numbering comes from the research report (section 8). Steps 9 (`STBR`)
and 23 (ELM hex line) are removed without renumbering, so the plan has 25 steps:
1 to 8, 10 to 22 and 24 to 27.

The plan describes the default branch: FC strategy `st_pairs` succeeds, no DTCs.
Before every module step (stages B to D) and in step 26 the plan contains an
engine state sample (`ProbeStep.sample`, package D): `ATRV`, selection of
engine 01 and the RPM read `22 F40C`. A step that does not start with its own
target selection (12 to 16, 24, 25) has a reselection of its target at the end
of the sample.
Lines come from the same pure builder functions as in the driver
(`OPEN_PROTOCOL_LINES`, `target_select_lines`, `stpx_line`, the enums
`AdapterQuery` and `ProbeCommand`), so the plan and the driver produce identical lines.
Conditional branches (`?`, `elm_fallback`, `1903`/`1904`) are described as text
in the `conditional` field.

Safety:
    The module performs no I/O; the only input is the ECU catalog passed
    to `build_steps`. The plan contains no `STBR`, `STBRT`, `ATZ` or ELM hex
    lines; every `STPX` line has `R:1`, and the payload is a read request
    (0x22 or 0x19).
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Final

from obd_bridge.stn.driver import (
    FORMAT_LINES,
    OPEN_PROTOCOL_LINES,
    AdapterQuery,
    FcStrategy,
    ProbeCommand,
    fc_lines,
    needs_fc_config,
    stpx_line,
    target_select_lines,
)
from obd_bridge.vag.catalog import EcuCatalog, EcuTarget

__all__ = [
    "ADDRESS_BRAKES",
    "ADDRESS_CHASSIS",
    "ADDRESS_DASHBOARD",
    "ADDRESS_ENGINE",
    "ADDRESS_GATEWAY",
    "ADDRESS_MULTIMEDIA",
    "ADDRESS_TRANSMISSION",
    "CODING_DID",
    "DEFAULT_FC_STRATEGY",
    "ENGINE_RPM_DID",
    "GW_IDENT",
    "GW_NRC_DID",
    "IDENT_FULL",
    "INSTALLATION_DIDS",
    "MAX_SNAPSHOT_RECORDS",
    "MODULE_03_DIDS",
    "MODULE_34_DIDS",
    "MODULE_5F_DIDS",
    "NOX_DIDS",
    "OBD_BITMAPS",
    "PLAN_SCHEMA",
    "READ_DTC_BY_MASK",
    "READ_DTC_COUNT",
    "READ_DTC_SNAPSHOT_IDS",
    "READ_SUPPORTED_DTC",
    "SEGMENTATION_DID",
    "STEP_NUMBERS",
    "TIMING_REPEAT",
    "LineKind",
    "PlanLine",
    "PlanTotals",
    "ProbeStage",
    "ProbeStep",
    "StepTag",
    "build_steps",
    "dtc_snapshot_payload",
    "plan_document",
    "plan_totals",
    "read_did",
]

# ---------------------------------------------------------------------------
# DID constants (spec T9, section "DID constants")

IDENT_FULL: Final[tuple[str, ...]] = (
    "F186",
    "F187",
    "F189",
    "F191",
    "F1A3",
    "F197",
    "F19E",
    "F1A2",
    "F18C",
    "F190",
    "F1AA",
)
"""Full module identification (11 DIDs), steps 17 and 18."""

GW_IDENT: Final[tuple[str, ...]] = ("F189", "F191", "F197", "F19E", "F1A2")
"""Identification of gateway J533 in step 13 (after F187 from step 12)."""

OBD_BITMAPS: Final[tuple[str, ...]] = (
    "F400",
    "F420",
    "F440",
    "F460",
    "F480",
    "F4A0",
    "F4C0",
    "F600",
    "F800",
)
"""Bitmaps of supported OBD PIDs via 0x22 (9 DIDs), step 18."""

NOX_DIDS: Final[tuple[str, ...]] = (
    "F483",
    "13BC",
    "13BD",
    "1502",
    "1503",
    "1528",
    "1530",
    "1529",
    "150D",
    "150E",
    "150F",
    "1510",
    "1515",
    "1516",
    "1538",
    "153B",
    "14DF",
    "16F4",
    "14E2",
    "15FF",
    "16F5",
    "1526",
    "175F",
    "1527",
    "14AD",
    "14AE",
)
"""Engine NOx DIDs (26, order from `docs/dids-obdeleven.md`, section `## 01`; F483 belongs to the list)."""

INSTALLATION_DIDS: Final[tuple[str, ...]] = ("2A2A", "2A29", "2A2C")
"""Gateway installation lists (80 B, 80 B, 160 B), step 15."""

MODULE_34_DIDS: Final[tuple[str, ...]] = ("F187", "F189", "F197", "F19E", "F1A2")
"""Identification of module 34 (suspension), step 19."""

MODULE_5F_DIDS: Final[tuple[str, ...]] = ("F187", "F189", "F19E", "F1A2")
"""Identification of module 5F (multimedia), step 20."""

MODULE_03_DIDS: Final[tuple[str, ...]] = ("F187", "F189", "F191", "F197", "F19E", "F1A2")
"""Identification of module 03 (brakes), step 21."""

ENGINE_RPM_DID: Final[str] = "F40C"
"""Engine 01 RPM DID (OBD PID 0C via 0x22, like the `F4xx` bitmaps in step 18); package D sample."""

CODING_DID: Final[str] = "0600"
"""Module coding DID (read via 0x22)."""

GW_NRC_DID: Final[str] = "0634"
"""Gateway DID for which the response `7F 22 22` is expected (step 14)."""

SEGMENTATION_DID: Final[str] = "F187"
"""DID used in steps 12, 22, 24 (multi-frame response)."""

READ_DTC_COUNT: Final[bytes] = bytes.fromhex("1901FF")
"""0x19 01 FF: number of DTCs for status mask FF."""

READ_DTC_BY_MASK: Final[bytes] = bytes.fromhex("1902FF")
"""0x19 02 FF: list of DTCs for status mask FF."""

READ_DTC_SNAPSHOT_IDS: Final[bytes] = bytes.fromhex("1903")
"""0x19 03: snapshot record identifiers."""

READ_SUPPORTED_DTC: Final[bytes] = bytes.fromhex("190A")
"""0x19 0A: all supported DTCs."""

MAX_SNAPSHOT_RECORDS: Final[int] = 10
"""Maximum number of `1904` requests in step 16 (records from `1903`, rec other than FF)."""

TIMING_REPEAT: Final[int] = 100
"""Number of repetitions of `STPX H:7E1,D:22F187,R:1` in step 24."""

DEFAULT_FC_STRATEGY: Final[FcStrategy] = FcStrategy.ST_PAIRS
"""FC strategy of the plan's default branch."""

PLAN_SCHEMA: Final[str] = "obdb.probe-plan/1"
"""Schema of the plan document (`obdb probe --json`)."""

STEP_NUMBERS: Final[tuple[int, ...]] = (*range(1, 9), *range(10, 23), 24, 25, 26, 27)
"""Probe step numbers (without 9 and 23)."""

# VAG addresses of the probe modules (catalog `defs/ecu-catalog.yaml`).
ADDRESS_ENGINE: Final[str] = "01"
ADDRESS_TRANSMISSION: Final[str] = "02"
ADDRESS_BRAKES: Final[str] = "03"
ADDRESS_DASHBOARD: Final[str] = "17"
ADDRESS_GATEWAY: Final[str] = "19"
ADDRESS_CHASSIS: Final[str] = "34"
ADDRESS_MULTIMEDIA: Final[str] = "5F"

_STPC: Final[str] = "STPC"
_ATWS: Final[str] = "ATWS"


def read_did(did: str) -> bytes:
    """Payload `22 <DID>` for a DID in hex notation (e.g. `F187`)."""
    if len(did) != 4:
        raise ValueError(f"DID must have 4 hex digits, got {did!r}")
    return bytes.fromhex("22" + did)


def dtc_snapshot_payload(dtc: int, record: int) -> bytes:
    """Payload `19 04 <DTC 3 B> <record>` for the conditional branch of step 16.

    Raises:
        ValueError: DTC outside 3 bytes or record outside 00..FE (FF is rejected
            by UdsGuard as "all records").
    """
    if not 0 <= dtc <= 0xFFFFFF:
        raise ValueError(f"DTC must fit in 3 bytes, got {dtc!r}")
    if not 0 <= record <= 0xFE:
        raise ValueError(f"Snapshot record must be in the range 00..FE, got {record!r}")
    return bytes((0x19, 0x04)) + dtc.to_bytes(3, "big") + bytes((record,))


# ---------------------------------------------------------------------------
# Plan types


class ProbeStage(StrEnum):
    """Probe stage (report section 8)."""

    A = "A"
    B = "B"
    C = "C"
    D = "D"
    E = "E"


class StepTag(StrEnum):
    """Step tag: R read, V volatile adapter state, B transmission on CAN."""

    R = "R"
    V = "V"
    B = "B"


class LineKind(StrEnum):
    """Kind of plan line, which tells the runner the driver method to use.

    ADAPTER: adapter command without a target (`warm_start`, `set_format`, `query`,
        `probe_command`, `open_protocol`, `set_rx_segmentation`, `close`).
    SELECT: `select_target` line for the target `target` (addressing and FC).
    UDS: `STPX` line with payload `payload` to the target `target`.
    """

    ADAPTER = "adapter"
    SELECT = "select"
    UDS = "uds"


@dataclass(frozen=True)
class PlanLine:
    """One line of the default branch in wire order.

    Attributes:
        line: exact line sent to the adapter (without terminator).
        repeat: number of repetitions (100 in step 24, otherwise 1).
        kind: kind of line (`LineKind`).
        target: VAG address of the target for `SELECT` and `UDS`, otherwise None.
        payload: UDS payload for `UDS`, otherwise None.
    """

    line: str
    repeat: int = 1
    kind: LineKind = LineKind.ADAPTER
    target: str | None = None
    payload: bytes | None = None

    def as_dict(self) -> dict[str, Any]:
        """JSON form in the plan: `{"line", "repeat"}`."""
        return {"line": self.line, "repeat": self.repeat}


@dataclass(frozen=True)
class ProbeStep:
    """Probe step.

    Attributes:
        number: step number from the report (without 9 and 23).
        stage: stage A to E.
        tags: tags R, V, B in the order of table T9.
        title: short title in English.
        description: description in English with the expected result and stop condition.
        lines: lines of the default branch.
        conditional: descriptions of conditional branches in English.
        sample: engine state sample lines sent before the step lines
            (`ATRV`, selection of engine 01, `22 F40C`); empty tuple without a sample.
    """

    number: int
    stage: ProbeStage
    tags: tuple[StepTag, ...]
    title: str
    description: str
    lines: tuple[PlanLine, ...] = ()
    conditional: tuple[str, ...] = field(default_factory=tuple)
    sample: tuple[PlanLine, ...] = ()

    @property
    def targets(self) -> tuple[str, ...]:
        """VAG addresses of the step targets in order of first use."""
        seen: list[str] = []
        for item in self.lines:
            if item.target is not None and item.target not in seen:
                seen.append(item.target)
        return tuple(seen)

    def as_dict(self) -> dict[str, Any]:
        """JSON form of the step (`obdb.probe-plan/1`)."""
        return {
            "step": self.number,
            "stage": self.stage.value,
            "tags": [tag.value for tag in self.tags],
            "title": self.title,
            "description": self.description,
            "sample": [item.as_dict() for item in self.sample],
            "lines": [item.as_dict() for item in self.lines],
            "conditional": list(self.conditional),
        }


@dataclass(frozen=True)
class PlanTotals:
    """Plan summary (table footer and the `totals` block in JSON).

    Attributes:
        steps: number of steps.
        lines: number of default branch lines including `repeat` and engine samples.
        stpx: number of `STPX` lines including `repeat` and engine samples.
    """

    steps: int
    lines: int
    stpx: int

    def as_dict(self) -> dict[str, int]:
        """JSON form: `{"steps", "lines", "stpx"}`."""
        return {"steps": self.steps, "lines": self.lines, "stpx": self.stpx}


# ---------------------------------------------------------------------------
# Plan construction


class _LineBuilder:
    """Reproduces the driver's `fc_applied` and `fc_configured` rule without I/O."""

    def __init__(self, catalog: EcuCatalog, strategy: FcStrategy) -> None:
        self._catalog = catalog
        self._strategy = strategy
        self._fc_applied = False
        self._fc_configured: set[int] = set()

    def target(self, address: str) -> EcuTarget:
        return self._catalog.get(address)

    def select(self, address: str) -> list[PlanLine]:
        target = self.target(address)
        configures_fc = needs_fc_config(target, self._strategy, self._fc_applied, self._fc_configured)
        lines = target_select_lines(target, self._strategy, self._fc_applied, self._fc_configured)
        if configures_fc:
            self._fc_applied = True
            if self._strategy is not FcStrategy.ELM_FALLBACK:
                self._fc_configured.add(target.tx_id)
        return [PlanLine(line, kind=LineKind.SELECT, target=address) for line in lines]

    def uds(self, address: str, payload: bytes, repeat: int = 1) -> PlanLine:
        line = stpx_line(self.target(address), payload)
        return PlanLine(line, repeat=repeat, kind=LineKind.UDS, target=address, payload=payload)

    def dids(self, address: str, dids: Iterable[str]) -> list[PlanLine]:
        return [self.uds(address, read_did(did)) for did in dids]

    def sample(self, restore: str | None = None) -> tuple[PlanLine, ...]:
        """Engine state sample: `ATRV`, selection of engine 01, RPM read `22 F40C`.

        `restore` is the target of a step that does not start with its own target
        selection; the sample then ends with a reselection of that target (sample
        lines, not step lines).
        """
        lines = [
            PlanLine(AdapterQuery.ATRV.value),
            *self.select(ADDRESS_ENGINE),
            self.uds(ADDRESS_ENGINE, read_did(ENGINE_RPM_DID)),
        ]
        if restore is not None:
            lines.extend(self.select(restore))
        return tuple(lines)


def _adapter(lines: Iterable[str]) -> list[PlanLine]:
    return [PlanLine(str(line)) for line in lines]


def _step(
    number: int,
    stage: ProbeStage,
    tags: Sequence[StepTag],
    title: str,
    description: str,
    lines: Iterable[PlanLine] = (),
    conditional: Iterable[str] = (),
    sample: Iterable[PlanLine] = (),
) -> ProbeStep:
    return ProbeStep(
        number=number,
        stage=stage,
        tags=tuple(tags),
        title=title,
        description=description,
        lines=tuple(lines),
        conditional=tuple(conditional),
        sample=tuple(sample),
    )


def _fc_text(strategy: FcStrategy, target: EcuTarget) -> str:
    return ", ".join(fc_lines(strategy, target))


def build_steps(catalog: EcuCatalog) -> list[ProbeStep]:
    """List of the 25 probe steps for the default branch (`st_pairs` succeeds, no DTCs).

    Parameters:
        catalog: ECU catalog; the CAN IDs and timeouts of the targets come from it.

    Raises:
        CatalogError: the catalog lacks a UDS module with `tx` required by the plan.
    """
    A, B, C, D, E = ProbeStage.A, ProbeStage.B, ProbeStage.C, ProbeStage.D, ProbeStage.E
    R, V, BUS = StepTag.R, StepTag.V, StepTag.B
    b = _LineBuilder(catalog, DEFAULT_FC_STRATEGY)
    gateway = b.target(ADDRESS_GATEWAY)
    gw = ADDRESS_GATEWAY
    tcu = ADDRESS_TRANSMISSION
    ecm = ADDRESS_ENGINE
    elm_note = (
        "with the elm_fallback strategy every target selection contains ATFCSH<tx>, ATFCSD300000, ATFCSM1 "
        "instead of the STCFCPA pair and the STFFCA filter"
    )

    steps: list[ProbeStep] = []

    # -- Stage A: adapter without an open protocol ---------------------------
    steps.append(
        _step(
            1, A, (R,), "Open port",
            "Open port at 38400 without RTS/CTS and DSR/DTR, banner window 1000 ms. Expected: no data "
            "or ELM327 v1.3a. Result always ok, banner in adapter.banner; open error: stop, code 3.",
        )
    )
    steps.append(
        _step(
            2, A, (V,), "Adapter warm start",
            "ATWS (warm_start). Expected a line with ELM327; otherwise error, stop, code 3.",
            _adapter([_ATWS]),
        )
    )
    steps.append(
        _step(
            3, A, (V,), "Response format",
            "ATE0, ATL0, ATS0, ATH1 (set_format). Expected OK; otherwise error, stop, code 3.",
            _adapter(FORMAT_LINES),
        )
    )
    steps.append(
        _step(
            4, A, (R,), "Adapter identification",
            "STI, STDI (identify) and ATI, AT@1 (query). Expected: STN2120 v4.5.0, STN2120 r1.0, "
            "ELM327 v1.3a, SCANTOOL.NET LLC. STI without the STN prefix: error, stop, code 3.",
            _adapter([AdapterQuery.STI, AdapterQuery.STDI, AdapterQuery.ATI, AdapterQuery.AT1]),
        )
    )
    steps.append(
        _step(
            5, A, (R,), "Supply voltage",
            "ATRV, STVR. Expected approx. 12.5 V.",
            _adapter([AdapterQuery.ATRV, AdapterQuery.STVR]),
            ["with ATRV below 12.4 V or unreadable: warning in adapter.voltage_warning, "
             "the probe continues (the threshold is temporarily not enforced)",
             "engine samples before modules: warning below 12.4 V with the engine off, "
             "below 13.2 V with the engine running (the alternator may not be charging); no stop"],
        )
    )
    steps.append(
        _step(
            6, A, (R,), "Programmable parameters",
            "ATPPS. Expected lines PP:VV F/N; all PPs in adapter.pp, no stop.",
            _adapter([AdapterQuery.ATPPS]),
        )
    )
    steps.append(
        _step(
            7, A, (R,), "Protocol in NVM and current",
            "ATDPN, STPR, STPRS. Expected protocol number and name; no stop.",
            _adapter([AdapterQuery.ATDPN, AdapterQuery.STPR, AdapterQuery.STPRS]),
        )
    )
    steps.append(
        _step(
            8, A, (V,), "Probing for ST commands",
            "Probing commands (probe_command). Expected OK or ? (command missing); result ok with the "
            "commands map, other token: error without a stop.",
            _adapter(ProbeCommand),
        )
    )

    # -- Stage B: protocol and gateway J533 ---------------------------------
    steps.append(
        _step(
            10, B, (V,), "Open CAN 11/500 protocol",
            "open_protocol: 7 lines, each with OK. Otherwise error, steps 11 to 25 skipped, stage E, code 3.",
            _adapter(OPEN_PROTOCOL_LINES),
        )
    )
    steps.append(
        _step(
            11, B, (V,), "Gateway selection and FC strategy",
            "select_target for gateway 19 (J533): addressing and FC pair before the filter. Expected OK; "
            "result ok with fc_strategy.",
            b.select(gw),
            [
                f"on ?: {_fc_text(FcStrategy.ST_PAIRS_LEGACY, gateway)} (st_pairs_legacy)",
                f"on ?: {_fc_text(FcStrategy.ELM_FALLBACK, gateway)} (elm_fallback)",
                "all strategies ?: unsupported, stop of stages B to D, code 3",
            ],
        )
    )
    # Engine state sample before every module step (package D). The sample is
    # built before the step lines because `_LineBuilder` reproduces the wire order
    # (the first sample configures the FC pair of engine 01).
    sample_note = (
        "before the step an engine state sample: ATRV and engine 01 RPM (22 F40C); "
        "NRC, NO DATA or an error gives state unknown without a stop"
    )
    sample = b.sample(restore=gw)
    steps.append(
        _step(
            12, B, (BUS,), "Read gateway F187 (FF and CF)",
            "Expected 62 F1 87 and part number 4G0907468 in a multi-frame response (FC test).",
            [b.uds(gw, read_did(SEGMENTATION_DID))],
            [
                "on ?: stop of stages B to D, code 3",
                "on NO DATA (car does not respond, --execute only): stop of stages B to D, code 4",
                "on CAN ERROR or BUS ERROR: stop, code 4",
                sample_note,
            ],
            sample,
        )
    )
    sample = b.sample(restore=gw)
    steps.append(
        _step(
            13, B, (BUS,), "Gateway identification",
            "Read 5 GW_IDENT DIDs. Expected 62 ..., F197 J533--Gateway, F19E EV_GatewPkoUDS.",
            b.dids(gw, GW_IDENT),
            [sample_note],
            sample,
        )
    )
    sample = b.sample(restore=gw)
    steps.append(
        _step(
            14, B, (BUS,), "Gateway coding",
            "Read 0600 (5 B of coding) and 0634 (expected NRC 7F 22 22).",
            b.dids(gw, (CODING_DID, GW_NRC_DID)),
            [sample_note],
            sample,
        )
    )
    sample = b.sample(restore=gw)
    steps.append(
        _step(
            15, B, (BUS,), "Installation lists",
            "Read 2A2A, 2A29, 2A2C (80 B, 80 B, 160 B); comparison of 2A2A with the catalog in installation.",
            b.dids(gw, INSTALLATION_DIDS),
            [sample_note],
            sample,
        )
    )
    sample = b.sample(restore=gw)
    steps.append(
        _step(
            16, B, (BUS,), "Gateway DTCs",
            "0x19 02 FF with the gateway timeout. Expected 59 02 ...",
            [b.uds(gw, READ_DTC_BY_MASK)],
            [
                "with reported DTCs: 1903 (snapshot identifiers)",
                f"then 1904<DTC><rec> for records from 1903 (rec other than FF, max. {MAX_SNAPSHOT_RECORDS})",
                sample_note,
            ],
            sample,
        )
    )

    # -- Stage C: module identification ------------------------------------
    fc_continue = "select_target error: error, rest of the step skipped, the probe continues"
    sample = b.sample()
    steps.append(
        _step(
            17, C, (BUS,), "Transmission 02 (J217)",
            "Full identification (11 DIDs), coding 0600, 1901FF, 1902FF, 190A. Expected F186 01, "
            "F19E EV_TCMAL551...",
            [
                *b.select(tcu),
                *b.dids(tcu, IDENT_FULL),
                b.uds(tcu, read_did(CODING_DID)),
                b.uds(tcu, READ_DTC_COUNT),
                b.uds(tcu, READ_DTC_BY_MASK),
                b.uds(tcu, READ_SUPPORTED_DTC),
            ],
            [fc_continue, elm_note, sample_note],
            sample,
        )
    )
    sample = b.sample()
    steps.append(
        _step(
            18, C, (BUS,), "Engine 01 (J623)",
            "Full identification (11 DIDs), coding 0600, OBD bitmaps (9) and NOx DIDs (26). "
            "Expected identification, bitmaps and NOx response lengths.",
            [
                *b.select(ecm),
                *b.dids(ecm, IDENT_FULL),
                b.uds(ecm, read_did(CODING_DID)),
                *b.dids(ecm, OBD_BITMAPS),
                *b.dids(ecm, NOX_DIDS),
            ],
            [fc_continue, elm_note, sample_note],
            sample,
        )
    )
    sample = b.sample()
    steps.append(
        _step(
            19, C, (BUS,), "Suspension 34",
            "Identification (5 DIDs), coding 0600, 1902FF, 1903. Expected F187 4G0907553...",
            [
                *b.select(ADDRESS_CHASSIS),
                *b.dids(ADDRESS_CHASSIS, MODULE_34_DIDS),
                b.uds(ADDRESS_CHASSIS, read_did(CODING_DID)),
                b.uds(ADDRESS_CHASSIS, READ_DTC_BY_MASK),
                b.uds(ADDRESS_CHASSIS, READ_DTC_SNAPSHOT_IDS),
            ],
            ["no response: compare with the 2A2C list from step 15", fc_continue, elm_note, sample_note],
            sample,
        )
    )
    sample = b.sample()
    steps.append(
        _step(
            20, C, (BUS,), "Multimedia 5F (J794)",
            "Identification (4 DIDs) and coding 0600. Expected F19E EV_MU..., approx. 25 B of coding.",
            [
                *b.select(ADDRESS_MULTIMEDIA),
                *b.dids(ADDRESS_MULTIMEDIA, MODULE_5F_DIDS),
                b.uds(ADDRESS_MULTIMEDIA, read_did(CODING_DID)),
            ],
            [fc_continue, elm_note, sample_note],
            sample,
        )
    )
    sample = b.sample()
    steps.append(
        _step(
            21, C, (BUS,), "Instrument cluster 17 and brakes 03",
            "Coding 0600 of module 17 (11 B), then identification of module 03 (6 DIDs). Step enabled "
            "by default.",
            [
                *b.select(ADDRESS_DASHBOARD),
                b.uds(ADDRESS_DASHBOARD, read_did(CODING_DID)),
                *b.select(ADDRESS_BRAKES),
                *b.dids(ADDRESS_BRAKES, MODULE_03_DIDS),
            ],
            [fc_continue, elm_note, sample_note],
            sample,
        )
    )

    # -- Stage D: adapter behaviour ----------------------------------------
    sample = b.sample()
    steps.append(
        _step(
            22, D, (V, BUS), "Assembled line format (STCSEGR1)",
            "Selection of transmission 02 (FC pairs already configured), STCSEGR1, STPX via driver.transact, "
            "STCSEGR0. Result ok when the response is not an error token; raw lines in stcsegr1_lines.",
            [
                *b.select(tcu),
                PlanLine("STCSEGR1"),
                b.uds(tcu, read_did(SEGMENTATION_DID)),
                PlanLine("STCSEGR0"),
            ],
            [
                "skipped when STCSEGR0 gave ? in step 8",
                "STCSEGR0 is always sent after a successful STCSEGR1, also when STPX ends with an error",
                sample_note,
            ],
            sample,
        )
    )
    sample = b.sample(restore=tcu)
    steps.append(
        _step(
            24, D, (BUS,), "STPX timing at 38400",
            f"{TIMING_REPEAT} reads of F187 from transmission 02; time from write to >. Result ok with at least "
            "one positive response; statistics in timing.stpx_22f187_ms.",
            [b.uds(tcu, read_did(SEGMENTATION_DID), repeat=TIMING_REPEAT)],
            ["on CAN ERROR or BUS ERROR: stop, code 4", sample_note],
            sample,
        )
    )
    sample = b.sample(restore=tcu)
    steps.append(
        _step(
            25, D, (BUS,), "Observation of NRC 0x78",
            "190A on transmission 02, then 1902FF on the gateway. Observation of 7F xx 78; result per entry, "
            "sets nrc78_mode.",
            [
                b.uds(tcu, READ_SUPPORTED_DTC),
                *b.select(gw),
                b.uds(gw, READ_DTC_BY_MASK),
            ],
            [sample_note],
            sample,
        )
    )

    # -- Stage E: shutdown -------------------------------------------------
    sample = b.sample()
    steps.append(
        _step(
            26, E, (R, BUS), "Bus status",
            "Stage E engine state sample (ATRV, engine 01 RPM), then ATRV, ATCS (read_status). "
            "Expected CAN error counters close to zero; ATCS text in session_end.meta.atcs.",
            _adapter([AdapterQuery.ATRV, AdapterQuery.ATCS]),
            [
                "engine sample only without an earlier probe stop (otherwise only ATRV and ATCS)",
                "engine state change in a module step: result with engine_event, one repeat of the step with "
                "the engine running (running sample before and after the repeat)",
            ],
            sample,
        )
    )
    steps.append(
        _step(
            27, E, (V,), "Shutdown",
            "STPC (only when the protocol is open) and port close. Expected OK; error logged, port "
            "always closed.",
            _adapter([_STPC]),
            ["no STPC when the protocol was not opened or a transport error occurred"],
        )
    )
    return steps


def plan_totals(steps: Sequence[ProbeStep]) -> PlanTotals:
    """Number of steps, default branch lines (with `repeat`, with engine samples) and `STPX` lines (with `repeat`)."""
    wire = [item for step in steps for item in (*step.sample, *step.lines)]
    lines = sum(item.repeat for item in wire)
    stpx = sum(item.repeat for item in wire if item.kind is LineKind.UDS)
    return PlanTotals(steps=len(steps), lines=lines, stpx=stpx)


def plan_document(steps: Sequence[ProbeStep]) -> dict[str, Any]:
    """JSON plan document (`obdb.probe-plan/1`, mode `plan`)."""
    return {
        "schema": PLAN_SCHEMA,
        "mode": "plan",
        "steps": [step.as_dict() for step in steps],
        "totals": plan_totals(steps).as_dict(),
    }
