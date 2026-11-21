"""Tests of `obdb report` (offline probe file readout and reference comparison).

The probe file is produced the same way as in `test_probe_execute.py`: a
live session against `CarSimTransport` with the mock catalog writes a real
`obdb.probe/1` file. The simulated modules answer with synthetic
identification values and DTC records; the reference files are synthetic too.
No test opens a port.
"""

from __future__ import annotations

import json
import os
import shutil
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from conftest import MOCK_CATALOG
from obd_bridge import cli
from obd_bridge.errors import ReportInputError
from obd_bridge.probe.readout import (
    REPORT_SCHEMA,
    build_report,
    load_reference,
    parse_reference,
    readout_from_document,
    render_report_text,
)
from obd_bridge.vag.catalog import EcuCatalog
from test_probe_execute import CarSimTransport, FakeClock, run_live

CATALOG: EcuCatalog = EcuCatalog.load(MOCK_CATALOG)

SIM_UDS: dict[tuple[str, str], Any] = {
    ("710", "22F187"): bytes.fromhex("62F187") + b"TEST907468  ",
    ("710", "22F189"): bytes.fromhex("62F189") + b"9001",
    ("710", "22F191"): bytes.fromhex("7F2231"),
    ("710", "22F197"): bytes.fromhex("62F197") + b"MockGateway\x00\xff",
    ("710", "1902FF"): bytes.fromhex("5902FF" "52050709" "92500128" "D20A0050" "53031500"),
    ("7E1", "1901FF"): bytes.fromhex("5901FF010001"),
    ("7E1", "1902FF"): bytes.fromhex("5902FF" "D2010008"),
    ("7E1", "190A"): [bytes.fromhex("7F1978"), bytes.fromhex("590AFF" "52050700" "D2010008")],
    ("741", "1902FF"): "NO DATA",
}
"""Synthetic module replies.

Gateway 19: C120507 (0x09, active), B125001 (0x28, stored) and two records without a fault
bit, U120A00 (0x50) and C130315 (0x00). Transmission 02: U120100 (0x08).
"""

REFERENCE_TEXT = """\
schema: obdb.reference/1
source: "synthetic reference"
modules:
  "19":
    identification:
      F187: " TEST907468 "
      F189: "9002"
      F191: "HW-1"
      F197: "MockGateway"
    dtcs: ["C120507", "U120A00"]
  "02":
    dtcs: []
  "34":
    dtcs: ["C130315"]
  "03": {}
  "6c":
    identification: {F187: "X"}
"""


@pytest.fixture(scope="module")
def probe_file(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    """Real probe file from a simulated live session (written once per module)."""
    root = tmp_path_factory.mktemp("probe")
    (root / "defs").mkdir()
    shutil.copyfile(MOCK_CATALOG, root / "defs" / "ecu-catalog.yaml")
    with pytest.MonkeyPatch.context() as patch:
        patch.chdir(root)
        clock = FakeClock()
        session = run_live(CarSimTransport(CATALOG, clock, uds=SIM_UDS), clock)
    assert session.exit_code == 0, session.result.stop
    assert session.probe_path is not None
    yield (root / session.probe_path).resolve()


@pytest.fixture
def reference_file(project_dir: Path) -> Path:
    path = project_dir / "ref.yaml"
    path.write_text(REFERENCE_TEXT, encoding="utf-8")
    return path


def _run(argv: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str, str]:
    code = cli.main(argv)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def _module(document: dict[str, Any], address: str) -> dict[str, Any]:
    return next(module for module in document["modules"] if module["address"] == address)


def _ident(module: dict[str, Any], did: str) -> dict[str, Any]:
    return next(entry for entry in module["identification"] if entry["did"] == did)


@pytest.fixture(autouse=True)
def _no_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    """`obdb report` must never reach the transport factory."""

    def refuse(url: str) -> Any:
        pytest.fail(f"obdb report tried to open a transport: {url}")

    monkeypatch.setattr(cli, "open_transport", refuse)


# ---------------------------------------------------------------------------
# End to end


def test_report_text_without_reference(
    project_dir: Path, probe_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, err = _run(["report", str(probe_file)], capsys)
    assert code == 0 and err == ""
    assert f"Probe file: {probe_file}" in out
    assert "outcome completed" in out
    assert "Reference:" not in out
    gateway = out[out.index("Module 19 Gateway (tx 710)") :]
    gateway = gateway[: gateway.index("\n\n")]
    assert "F187  spare part number (OBDeleven: Software number)  TEST907468" in gateway
    assert "F197  system name (OBDeleven: System description)" in gateway and "MockGateway" in gateway
    assert "9001" in gateway
    assert "(not read: NRC 0x31, request out of range)" in gateway
    assert "DTCs (19 02, step 16): 2" in gateway
    assert "C120507  0x09  active  testFailed, confirmedDTC" in gateway
    assert "B125001  0x28  stored  confirmedDTC, testFailedSinceLastClear" in gateway
    assert "  Records without a fault bit: 2 (not compared)" in gateway
    assert "U120A00  0x50  no fault  testNotCompletedSinceLastClear, testNotCompletedThisOperationCycle" in gateway
    assert "C130315  0x00  no fault  -" in gateway
    assert "match" not in gateway and "new" not in gateway

    transmission = out[out.index("Module 02 Transmission (tx 7E1)") :]
    assert "U120100  0x08  stored  confirmedDTC" in transmission
    assert "DTC count (19 01, step 17): 1 (as reported by the module; may include records without a fault bit)" in transmission
    assert "Supported DTCs (19 0A, step 17): 2 records, 1 with a fault bit (not compared)" in transmission
    assert "010203 (hex)" in transmission
    assert "Module 34 Chassis (tx 741)" in out
    assert "DTCs (19 02, step 19): not read: NO DATA" in out
    assert "Module 17 Instrument Cluster (tx 740)\n  (no identification or DTC reads)" in out
    assert out.rstrip().splitlines()[-1].startswith("Summary: 7 modules probed; identification: ")
    assert not (project_dir / "data").exists()


def test_report_text_with_reference(
    project_dir: Path, probe_file: Path, reference_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, err = _run(["report", str(probe_file), "--reference", str(reference_file)], capsys)
    assert code == 0 and err == ""
    assert f"Reference: {reference_file} (synthetic reference)" in out
    lines = out.splitlines()

    def line_with(*parts: str) -> str:
        return next(line for line in lines if all(part in line for part in parts))

    assert line_with("F187", "TEST907468").rstrip().endswith("  match")
    assert line_with("F189", "9001").rstrip().endswith("differs (reference: 9002)")
    assert line_with("F191", "NRC 0x31").rstrip().endswith("not read")
    assert line_with("F197", "MockGateway").rstrip().endswith("match")
    assert line_with("F19E", "010203 (hex)").rstrip().endswith("not in reference")
    assert line_with("C120507", "0x09").rstrip().endswith("present in both")
    assert line_with("B125001", "0x28").rstrip().endswith("new")
    assert line_with("U120A00").rstrip().endswith("gone (read without a fault bit)")
    assert line_with("U120A00", "0x50").rstrip().endswith(
        "no fault  testNotCompletedSinceLastClear, testNotCompletedThisOperationCycle"
    )
    assert line_with("U120100", "0x08").rstrip().endswith("new")
    assert "DTCs (19 02, step 19): not read: NO DATA\n" in out
    assert "Module 03 Brakes (tx 713)" in out
    assert line_with("C130315", "expected").rstrip().endswith("  -  -  -  expected, not read")
    assert "Module 6C Mock UDS Module B: not probed" in out
    assert lines[-1] == (
        "Summary: 8 modules, 1 not probed; identification: 2 match, 1 differs, 1 not read, "
        "39 not in reference; DTCs: 1 present in both, 2 new, 1 gone, lists not read: 1, "
        "lists not compared: 0."
    )


def test_report_json_with_reference(
    project_dir: Path, probe_file: Path, reference_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, _ = _run(["report", str(probe_file), "--reference", str(reference_file), "--json"], capsys)
    assert code == 0
    document = json.loads(out)
    assert document["schema"] == REPORT_SCHEMA == "obdb.report/1"
    assert document["probe"]["outcome"] == "completed" and document["probe"]["mode"] == "live"
    assert document["reference"] == {"path": str(reference_file), "source": "synthetic reference"}

    gateway = _module(document, "19")
    assert gateway["name"] == "Gateway" and gateway["tx"] == "710" and gateway["probed"]
    assert _ident(gateway, "F187") == {
        "did": "F187",
        "name": "spare part number (OBDeleven: Software number)",
        "read": True,
        "value": "TEST907468",
        "encoding": "ascii",
        "step": 12,
        "reason": None,
        "reference": " TEST907468 ",
        "comparison": "match",
    }
    assert _ident(gateway, "F189")["comparison"] == "differs"
    assert _ident(gateway, "F189")["reference"] == "9002"
    assert _ident(gateway, "F191")["comparison"] == "not_read"
    assert _ident(gateway, "F191")["reason"] == "NRC 0x31, request out of range"
    dtcs = gateway["dtcs"]
    assert dtcs["read"] and dtcs["step"] == 16 and dtcs["comparison"] == "compared"
    assert dtcs["records"][0] == {
        "code": "C120507",
        "dtc": "520507",
        "status": "0x09",
        "presence": "active",
        "flags": ["testFailed", "confirmedDTC"],
        "comparison": "present_in_both",
    }
    assert dtcs["records"][1]["code"] == "B125001" and dtcs["records"][1]["comparison"] == "new"
    assert len(dtcs["records"]) == 2 and dtcs["count"] == 2
    assert [(entry["code"], entry["presence"], entry["comparison"]) for entry in dtcs["inactive_dtcs"]] == [
        ("U120A00", "no fault", None),
        ("C130315", "no fault", None),
    ]
    assert dtcs["gone"] == [{"code": "U120A00", "read_without_fault_bit": True}]

    transmission = _module(document, "02")
    assert transmission["dtcs"]["reference"] == [] and transmission["dtcs"]["records"][0]["comparison"] == "new"
    assert transmission["dtc_count"]["count"] == 1
    assert transmission["supported_dtcs"]["count"] == 2
    assert all(entry["comparison"] == "not_in_reference" for entry in transmission["identification"])

    chassis = _module(document, "34")
    assert chassis["dtcs"]["read"] is False and chassis["dtcs"]["comparison"] == "not_read"
    assert chassis["dtcs"]["reason"] == "NO DATA"

    brakes = _module(document, "03")
    assert brakes["in_reference"] and brakes["dtcs"] is None

    missing = _module(document, "6C")
    assert missing["probed"] is False and missing["comparison"] == "not_probed"

    comparison = document["summary"]["comparison"]
    assert comparison["modules_not_probed"] == 1
    assert comparison["identification"] == {"match": 2, "differs": 1, "not_read": 1, "not_in_reference": 39}
    assert comparison["dtcs"] == {
        "present_in_both": 1,
        "new": 2,
        "gone": 1,
        "lists_not_read": 1,
        "lists_not_compared": 0,
    }


def test_report_json_without_reference(
    project_dir: Path, probe_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, _ = _run(["report", str(probe_file), "--json"], capsys)
    assert code == 0
    document = json.loads(out)
    assert document["reference"] is None and document["summary"]["comparison"] is None
    gateway = _module(document, "19")
    assert all(entry["comparison"] is None for entry in gateway["identification"])
    assert all(record["comparison"] is None for record in gateway["dtcs"]["records"])
    assert gateway["dtcs"]["comparison"] is None
    assert document["summary"]["dtcs"] == 3 and document["summary"]["dtcs_active"] == 1
    assert document["summary"]["dtcs_without_fault_bit"] == 2
    assert [module["address"] for module in document["modules"]] == ["01", "02", "03", "17", "19", "34", "5F"]


# ---------------------------------------------------------------------------
# Extraction rules


def _synthetic_probe(steps: list[dict[str, Any]]) -> dict[str, Any]:
    return {"schema": "obdb.probe/1", "session_id": "synthetic", "outcome": "completed", "checklist": steps}


def _item(line: str, result: str, response: str | None = None, nrc: str | None = None) -> dict[str, Any]:
    return {"line": line, "result": result, "response": response, "nrc": nrc, "error": None}


def test_repeat_steps_are_ignored_and_first_positive_wins() -> None:
    steps = [
        {
            "step": 19,
            "repeat_of": None,
            "items": [
                _item("STPX H:741,D:22F187,R:1", "no_data", "NO DATA"),
                _item("STPX H:741,D:22F189,R:1", "ok", "62F189" + b"1111".hex()),
                _item("STPX H:741,D:220600,R:1", "ok", "620600010203"),
                _item("STPX H:741,D:1903,R:1", "ok", "5903"),
                _item("ATRV", "ok", "12.6V"),
            ],
        },
        {
            "step": 19,
            "repeat_of": 19,
            "items": [
                _item("STPX H:741,D:22F189,R:1", "ok", "62F189" + b"2222".hex()),
                _item("STPX H:741,D:1902FF,R:1", "ok", "5902FF52050709"),
            ],
        },
        {
            "step": 22,
            "repeat_of": None,
            "items": [
                _item("STPX H:741,D:22F187,R:1", "ok", "62F187" + b"LATER".hex()),
                _item("STPX H:741,D:22F189,R:1", "ok", "62F189" + b"3333".hex()),
                _item("STPX H:7AA,D:22F187,R:1", "ok", "62F187" + b"ORPHAN".hex()),
            ],
        },
    ]
    readout = readout_from_document(_synthetic_probe(steps), CATALOG)
    chassis = next(module for module in readout.modules if module.address == "34")
    assert chassis.identification[0xF187].value == "LATER" and chassis.identification[0xF187].step == 22
    assert chassis.identification[0xF189].value == "1111"
    assert set(chassis.identification) == {0xF187, 0xF189}
    assert chassis.dtcs is None
    orphan = readout.modules[-1]
    assert orphan.address is None and orphan.tx == 0x7AA

    document = build_report(readout, CATALOG)
    text = render_report_text(document)
    assert "Module ?? (tx 7AA) (not in the ECU catalog)" in text
    assert "1111" in text and "2222" not in text and "3333" not in text


def test_unparseable_replies_are_not_read() -> None:
    steps = [
        {
            "step": 17,
            "repeat_of": None,
            "items": [
                _item("STPX H:7E1,D:22F187,R:1", "ok", "62F18901"),
                _item("STPX H:7E1,D:22F189,R:1", "ok", "not hex"),
                _item("STPX H:7E1,D:1902FF,R:1", "ok", "5901FF"),
                _item("STPX H:7E1,D:1901FF,R:1", "pending_unresolved", "7F1978"),
                _item("STPX H:7E1,D:190A,R:1", "unsupported", "?"),
                _item("STPX H:7E1,D:22F191,R:1", "nrc", "7F2233", "33"),
                _item("STPX H:7E1,D:22F197,R:1", "nrc", "7F2299", "99"),
            ],
        }
    ]
    module = readout_from_document(_synthetic_probe(steps), CATALOG).modules[0]
    assert module.identification[0xF187].reason == "reply for another DID: 62F18901"
    assert module.identification[0xF189].reason == "reply is not hex: 'not hex'"
    assert module.identification[0xF191].reason == "NRC 0x33, access denied (security access)"
    assert module.identification[0xF197].reason == "NRC 0x99"
    assert module.dtcs is not None and not module.dtcs.ok
    assert "does not match request 19 02" in str(module.dtcs.reason)
    assert module.dtc_count is not None and module.dtc_count.reason == "NRC 0x78 without a final reply"
    assert module.supported is not None and module.supported.reason == "adapter replied ?"


def test_dtcs_not_compared_without_reference_list() -> None:
    steps = [
        {
            "step": 16,
            "repeat_of": None,
            "items": [
                _item("STPX H:710,D:22F187,R:1,T:1500", "ok", "62F187" + b"ABC ".hex()),
                _item("STPX H:710,D:1902FF,R:1,T:1500", "ok", "5902FF52050709"),
            ],
        }
    ]
    readout = readout_from_document(_synthetic_probe(steps), CATALOG)
    reference = parse_reference(
        {"schema": "obdb.reference/1", "modules": {"19": {"identification": {"F187": "abc"}}}}
    )
    document = build_report(readout, CATALOG, reference)
    gateway = _module(document, "19")
    assert _ident(gateway, "F187")["comparison"] == "differs"
    assert gateway["dtcs"]["comparison"] == "not_compared"
    assert gateway["dtcs"]["records"][0]["comparison"] is None
    text = render_report_text(document)
    assert "DTCs (19 02, step 16): 1 [not compared]" in text
    assert "differs (reference: abc)" in text
    assert document["summary"]["comparison"]["dtcs"]["lists_not_compared"] == 1


def test_records_without_fault_bit_and_reference() -> None:
    reply = "5902FF" "52050750" "92500100" "D2010008" "52C80001"
    steps = [{"step": 16, "repeat_of": None, "items": [_item("STPX H:710,D:1902FF,R:1,T:1500", "ok", reply)]}]
    readout = readout_from_document(_synthetic_probe(steps), CATALOG)
    reference = parse_reference(
        {"schema": "obdb.reference/1", "modules": {"19": {"dtcs": ["C120507", "U120100", "B123413"]}}}
    )
    document = build_report(readout, CATALOG, reference)
    dtcs = _module(document, "19")["dtcs"]
    assert [(entry["code"], entry["status"], entry["presence"], entry["comparison"]) for entry in dtcs["records"]] == [
        ("U120100", "0x08", "stored", "present_in_both"),
        ("C12C800", "0x01", "active", "new"),
    ]
    assert [(entry["code"], entry["status"], entry["presence"]) for entry in dtcs["inactive_dtcs"]] == [
        ("C120507", "0x50", "no fault"),
        ("B125001", "0x00", "no fault"),
    ]
    assert all(entry["comparison"] is None for entry in dtcs["inactive_dtcs"])
    assert dtcs["gone"] == [
        {"code": "C120507", "read_without_fault_bit": True},
        {"code": "B123413", "read_without_fault_bit": False},
    ]
    summary = document["summary"]
    assert summary["dtcs"] == 2 and summary["dtcs_active"] == 1 and summary["dtcs_without_fault_bit"] == 2
    assert summary["comparison"]["dtcs"] == {
        "present_in_both": 1,
        "new": 1,
        "gone": 2,
        "lists_not_read": 0,
        "lists_not_compared": 0,
    }
    text = render_report_text(document)
    assert "DTCs (19 02, step 16): 2\n" in text
    lines = [line.split() for line in text.splitlines()]
    assert ["C120507", "-", "-", "-", "gone", "(read", "without", "a", "fault", "bit)"] in lines
    assert ["B123413", "-", "-", "-", "gone"] in lines
    assert "  Records without a fault bit: 2 (not compared)" in text
    assert "B125001  0x00  no fault  -" in text


def test_first_failure_is_kept() -> None:
    steps = [
        {
            "step": 19,
            "repeat_of": None,
            "items": [
                _item("STPX H:741,D:22F187,R:1", "nrc", "7F2231", "31"),
                _item("STPX H:741,D:1902FF,R:1", "no_data", "NO DATA"),
            ],
        },
        {
            "step": 22,
            "repeat_of": None,
            "items": [
                _item("STPX H:741,D:22F187,R:1", "skipped"),
                _item("STPX H:741,D:1902FF,R:1", "unsupported", "?"),
            ],
        },
    ]
    module = readout_from_document(_synthetic_probe(steps), CATALOG).modules[0]
    assert module.identification[0xF187].reason == "NRC 0x31, request out of range"
    assert module.identification[0xF187].step == 19
    assert module.dtcs is not None and module.dtcs.reason == "NO DATA" and module.dtcs.step == 19


def test_repeat_after_failed_original_is_still_ignored() -> None:
    """Documented rule: a repeat (`repeat_of`) is never a data source, even when the original failed."""
    steps = [
        {"step": 19, "repeat_of": None, "items": [_item("STPX H:741,D:22F187,R:1", "no_data", "NO DATA")]},
        {"step": 19, "repeat_of": 19, "items": [_item("STPX H:741,D:22F187,R:1", "ok", "62F187" + b"OK".hex())]},
    ]
    module = readout_from_document(_synthetic_probe(steps), CATALOG).modules[0]
    assert module.identification[0xF187].value is None
    assert module.identification[0xF187].reason == "NO DATA"


def test_control_characters_are_escaped_in_text() -> None:
    steps = [
        {
            "step": 12,
            "repeat_of": None,
            "items": [
                _item("STPX H:710,D:22F187,R:1,T:1500", "error", None),
                _item("STPX H:710,D:22F189,R:1,T:1500", "ok", "62F189" + b"X".hex()),
            ],
        }
    ]
    steps[0]["items"][0]["error"] = "bad\nline\x1b[31m"
    document = _synthetic_probe(steps)
    document["session_id"] = "id\twith tab"
    readout = readout_from_document(document, CATALOG)
    reference = parse_reference(
        {
            "schema": "obdb.reference/1",
            "source": "src\nnext",
            "modules": {"19": {"identification": {"F189": "a\nb"}}},
        }
    )
    text = render_report_text(build_report(readout, CATALOG, reference))
    assert "\x1b" not in text and "\t" not in text
    assert "(not read: bad\\nline\\x1b[31m)" in text
    assert "Session: id\\twith tab," in text
    assert "(src\\nnext)" in text
    assert "differs (reference: a\\nb)" in text
    assert all(not line.startswith(("line", "next", "b")) for line in text.splitlines())


def test_unicode_format_and_separator_characters_are_escaped_in_text() -> None:
    """Format characters (Cf) and line or paragraph separators cannot reorder or split report lines."""
    steps = [
        {
            "step": 12,
            "repeat_of": None,
            "items": [_item("STPX H:710,D:22F187,R:1,T:1500", "error", None)],
        }
    ]
    steps[0]["items"][0]["error"] = "rtl\u202eoverride zero\u200bwidth"
    document = _synthetic_probe(steps)
    document["session_id"] = "line\u2028para\u2029end"
    text = render_report_text(build_report(readout_from_document(document, CATALOG), CATALOG, None))
    assert not any(char in text for char in "\u202e\u200b\u2028\u2029")
    assert "(not read: rtl\\u202eoverride zero\\u200bwidth)" in text
    assert "Session: line\\u2028para\\u2029end," in text
    assert "Zażółć" in render_report_text(
        build_report(readout_from_document(_synthetic_probe([]) | {"session_id": "Zażółć"}, CATALOG), CATALOG, None)
    )


def test_json_key_snapshot(
    project_dir: Path, probe_file: Path, reference_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, _ = _run(["report", str(probe_file), "--reference", str(reference_file), "--json"], capsys)
    assert code == 0
    document = json.loads(out)
    assert list(document) == ["schema", "probe", "reference", "modules", "summary"]
    assert list(document["probe"]) == ["path", "session_id", "mode", "outcome", "started_at"]
    assert list(document["reference"]) == ["path", "source"]
    transmission = _module(document, "02")
    assert list(transmission) == [
        "address",
        "name",
        "tx",
        "probed",
        "in_reference",
        "comparison",
        "identification",
        "dtcs",
        "dtc_count",
        "supported_dtcs",
    ]
    assert list(transmission["identification"][0]) == [
        "did",
        "name",
        "read",
        "value",
        "encoding",
        "step",
        "reason",
        "reference",
        "comparison",
    ]
    assert list(transmission["dtcs"]) == [
        "request",
        "read",
        "step",
        "reason",
        "count",
        "records",
        "inactive_dtcs",
        "reference",
        "gone",
        "comparison",
    ]
    assert list(transmission["dtcs"]["records"][0]) == ["code", "dtc", "status", "presence", "flags", "comparison"]
    assert list(transmission["dtc_count"]) == ["request", "read", "step", "reason", "count"]
    assert list(transmission["supported_dtcs"]) == ["request", "read", "step", "reason", "count", "records"]
    assert list(_module(document, "19")["dtcs"]["gone"][0]) == ["code", "read_without_fault_bit"]
    assert list(document["summary"]) == [
        "modules",
        "modules_probed",
        "identification_read",
        "identification_not_read",
        "dtcs",
        "dtcs_active",
        "dtcs_without_fault_bit",
        "comparison",
    ]
    assert list(document["summary"]["comparison"]) == ["modules_not_probed", "identification", "dtcs"]


# ---------------------------------------------------------------------------
# Invalid input


@pytest.mark.parametrize(
    ("content", "fragment"),
    [
        ("schema: obdb.probe-run/1\nchecklist: []\n", "schema 'obdb.probe-run/1' instead of 'obdb.probe/1'"),
        ("- a\n- b\n", "the document is not a YAML mapping"),
        ("schema: obdb.probe/1\n", "field 'checklist' must be a list"),
        ("schema: obdb.probe/1\nchecklist: [1]\n", "checklist[0] is not a mapping"),
        ("schema: obdb.probe/1\nchecklist:\n- items: [{line: 5}]\n", "must be a mapping with a string 'line'"),
        ("schema: [unclosed\n", "Invalid YAML in probe file"),
    ],
)
def test_invalid_probe_file(
    project_dir: Path, capsys: pytest.CaptureFixture[str], content: str, fragment: str
) -> None:
    path = project_dir / "probe.yaml"
    path.write_text(content, encoding="utf-8")
    code, out, err = _run(["report", str(path)], capsys)
    assert code == 64 and out == ""
    assert fragment in err


def test_missing_files(
    project_dir: Path, probe_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, _, err = _run(["report", str(project_dir / "missing.yaml")], capsys)
    assert code == 64 and "Cannot read probe file" in err and "file does not exist" in err
    code, _, err = _run(["report", str(probe_file), "--reference", str(project_dir / "missing.yaml")], capsys)
    assert code == 64 and "Cannot read reference file" in err
    code, _, err = _run(["report"], capsys)
    assert code == 64 and "Usage error:" in err


@pytest.mark.skipif(not hasattr(os, "geteuid") or os.geteuid() == 0, reason="root ignores directory permissions")
def test_unreadable_path_reports_the_real_cause(
    project_dir: Path, probe_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    locked = project_dir / "locked"
    locked.mkdir()
    target = locked / "probe.yaml"
    shutil.copyfile(probe_file, target)
    locked.chmod(0)
    try:
        code, out, err = _run(["report", str(target)], capsys)
        assert code == 64 and out == ""
        assert "Cannot read probe file" in err and "permission denied" in err and "does not exist" not in err
        code, out, err = _run(["report", str(probe_file), "--reference", str(target)], capsys)
        assert code == 64 and out == ""
        assert "Cannot read reference file" in err and "permission denied" in err
    finally:
        locked.chmod(0o700)


def test_path_through_a_regular_file(
    project_dir: Path, probe_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, err = _run(["report", str(probe_file / "child.yaml")], capsys)
    assert code == 64 and out == ""
    assert "Cannot read probe file" in err and "a path component is not a directory" in err


def test_paths_that_are_not_regular_files(
    project_dir: Path, probe_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    directory = project_dir / "a_directory"
    directory.mkdir()
    code, out, err = _run(["report", str(directory)], capsys)
    assert code == 64 and out == "" and "Cannot read probe file" in err and "not a regular file" in err
    code, out, err = _run(["report", str(probe_file), "--reference", str(directory)], capsys)
    assert code == 64 and out == "" and "Cannot read reference file" in err and "not a regular file" in err


def test_non_utf8_and_deeply_nested_input(
    project_dir: Path, probe_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    broken = project_dir / "latin1.yaml"
    broken.write_bytes(b"schema: obdb.probe/1\nnote: \xe9\n")
    code, _, err = _run(["report", str(broken)], capsys)
    assert code == 64 and "is not valid UTF-8" in err
    code, _, err = _run(["report", str(probe_file), "--reference", str(broken)], capsys)
    assert code == 64 and "Reference file" in err and "is not valid UTF-8" in err
    nested = project_dir / "nested.yaml"
    nested.write_text("[" * 20000 + "]" * 20000 + "\n", encoding="utf-8")
    code, _, err = _run(["report", str(nested)], capsys)
    assert code == 64 and "Invalid YAML in probe file" in err and "Internal error" not in err


def test_missing_catalog(
    tmp_path: Path, probe_file: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    code, _, err = _run(["report", str(probe_file)], capsys)
    assert code == 64 and "ecu-catalog.yaml not found" in err


@pytest.mark.parametrize(
    ("content", "fragment"),
    [
        ("schema: obdb.reference/2\nmodules: {}\n", "schema 'obdb.reference/2' instead of 'obdb.reference/1'"),
        ("schema: obdb.reference/1\n", "field 'modules' must be a mapping"),
        ("schema: obdb.reference/1\nmodules: {}\nextra: 1\n", "unknown top-level keys: extra"),
        ("schema: obdb.reference/1\nsource: 5\nmodules: {}\n", "field 'source' must be a string"),
        ("schema: obdb.reference/1\nmodules:\n  19: {}\n", "module key 19 must be a quoted two-digit hex address"),
        ("schema: obdb.reference/1\nmodules:\n  \"0619\": {}\n", "module key '0619'"),
        ("schema: obdb.reference/1\nmodules:\n  \"19\": {dtc: []}\n", "module 19: unknown keys: dtc"),
        ("schema: obdb.reference/1\nmodules:\n  \"19\": []\n", "module 19 must be a mapping"),
        ("schema: obdb.reference/1\nmodules:\n  \"19\": {}\n  \"19\": {}\n", "Invalid YAML in reference file"),
        ("schema: obdb.reference/1\nmodules:\n  \"19\": {}\n  \"1a\": {}\n  \"1A\": {}\n", "module 1A is listed twice"),
        (
            "schema: obdb.reference/1\nmodules:\n  \"19\":\n    identification: {F189: 0075}\n",
            "value of DID F189 must be a string (quote the value",
        ),
        (
            "schema: obdb.reference/1\nmodules:\n  \"19\":\n    identification: {\"0600\": \"x\"}\n",
            "DID 0600 is outside the identification range F100..F1FF",
        ),
        (
            "schema: obdb.reference/1\nmodules:\n  \"19\":\n    identification: {F18: \"x\"}\n",
            "DID 'F18' must be four hex digits",
        ),
        (
            "schema: obdb.reference/1\nmodules:\n  \"19\":\n    identification: [F187]\n",
            "'identification' must be a mapping",
        ),
        ("schema: obdb.reference/1\nmodules:\n  \"19\":\n    dtcs: U120A00\n", "'dtcs' must be a list"),
        ("schema: obdb.reference/1\nmodules:\n  \"19\":\n    dtcs: [\"U140B0\"]\n", "Invalid DTC 'U140B0'"),
        ("schema: obdb.reference/1\nmodules:\n  \"19\":\n    dtcs: [1234567]\n", "DTC must be a string"),
        (
            "schema: obdb.reference/1\nmodules:\n  \"19\":\n    dtcs: [\"U120A00\", \"u120a00\"]\n",
            "DTC U120A00 is listed twice",
        ),
    ],
)
def test_invalid_reference_file(
    project_dir: Path, probe_file: Path, capsys: pytest.CaptureFixture[str], content: str, fragment: str
) -> None:
    path = project_dir / "ref.yaml"
    path.write_text(content, encoding="utf-8")
    code, out, err = _run(["report", str(probe_file), "--reference", str(path)], capsys)
    assert code == 64 and out == ""
    assert f"{path}" in err and fragment in err


def test_reference_parsing(reference_file: Path) -> None:
    reference = load_reference(reference_file)
    assert reference.source == "synthetic reference"
    assert set(reference.modules) == {"19", "02", "34", "03", "6C"}
    assert reference.modules["19"].dtcs == (0x520507, 0xD20A00)
    assert reference.modules["19"].identification[0xF189] == "9002"
    assert reference.modules["02"].dtcs == () and reference.modules["03"].dtcs is None
    minimal = parse_reference({"schema": "obdb.reference/1", "modules": {"19": None}})
    assert minimal.modules["19"].identification == {} and minimal.modules["19"].dtcs is None
    with pytest.raises(ReportInputError) as info:
        parse_reference("text")
    assert info.value.exit_code == 64


def test_report_does_not_change_probe_file(
    project_dir: Path, probe_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    before = probe_file.read_bytes()
    assert _run(["report", str(probe_file), "--json"], capsys)[0] == 0
    assert probe_file.read_bytes() == before
    assert sorted(path.name for path in project_dir.iterdir()) == ["defs"]


def test_help_lists_report(project_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = _run(["--help"], capsys)
    assert code == 0 and "report" in out
    code, out, _ = _run(["report", "--help"], capsys)
    assert code == 0
    for fragment in ("PROBE_FILE", "--reference", "--json"):
        assert fragment in out
