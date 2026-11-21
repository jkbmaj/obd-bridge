"""Tests of the project skeleton: uv metadata, exception hierarchy, `yamlio` and the `/dev/*` blocker."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest
import serial
from ruamel.yaml.error import YAMLError

from conftest import REPO_ROOT
from obd_bridge import errors
from obd_bridge.yamlio import dump_yaml, load_yaml, write_atomic

# Table T12: class, expected base and exit code.
T12_TABLE: list[tuple[str, str, int]] = [
    ("ObdBridgeError", "Exception", 3),
    ("ReadOnlyViolation", "ObdBridgeError", 2),
    ("TransportError", "ObdBridgeError", 3),
    ("TransportTimeout", "TransportError", 3),
    ("AdapterError", "ObdBridgeError", 3),
    ("AdapterResponseError", "AdapterError", 3),
    ("ReplayMismatch", "ObdBridgeError", 5),
    ("CatalogError", "ObdBridgeError", 64),
    ("LogFormatError", "ObdBridgeError", 64),
    ("ReportInputError", "ObdBridgeError", 64),
    ("UdsError", "ObdBridgeError", 3),
]


def _resolve(name: str) -> type:
    """Returns the class from `obd_bridge.errors` or the built-in `Exception`."""
    if name == "Exception":
        return Exception
    return getattr(errors, name)


def test_removed_dead_exception_classes() -> None:
    """`StopCondition` and `errors.UsageError` removed (package B6): code 4 comes from the runner, code 64 from the typer `UsageError`."""
    assert not hasattr(errors, "StopCondition")
    assert not hasattr(errors, "UsageError")
    assert set(errors.__all__) <= set(dir(errors))


@pytest.mark.parametrize(("name", "base", "code"), T12_TABLE)
def test_exit_codes(name: str, base: str, code: int) -> None:
    cls = _resolve(name)
    assert cls.__bases__ == (_resolve(base),)
    assert cls.exit_code == code


def test_exception_fields() -> None:
    violation = errors.ReadOnlyViolation(
        layer="uds", rule="UDS/sid", reason="SID 0x2E outside the allowlist", subject="2EF1900102"
    )
    assert (violation.layer, violation.rule, violation.reason, violation.subject) == (
        "uds",
        "UDS/sid",
        "SID 0x2E outside the allowlist",
        "2EF1900102",
    )
    assert violation.exit_code == 2
    assert "UDS/sid" in str(violation)

    timeout = errors.TransportTimeout(partial=b"7E8 03")
    assert timeout.partial == b"7E8 03"
    assert errors.TransportTimeout().partial == b""

    exchange = object()
    assert errors.AdapterResponseError(exchange).exchange is exchange

    mismatch = errors.ReplayMismatch(seq=7, expected=b"ATI\r", actual=b"ATZ\r")
    assert (mismatch.seq, mismatch.expected, mismatch.actual) == (7, b"ATI\r", b"ATZ\r")
    assert mismatch.exit_code == 5


def test_yamlio_safe_roundtrip(tmp_path) -> None:
    data = {"address": "02", "tx": "7E1", "items": [1, "0A"]}
    text = dump_yaml(data)
    assert "'02'" in text or '"02"' in text
    path = tmp_path / "file.yaml"
    path.write_text(text, encoding="utf-8")
    loaded = load_yaml(path)
    assert loaded == data
    assert isinstance(loaded["address"], str)

    unsafe = tmp_path / "bad.yaml"
    unsafe.write_text("a: !!python/object:os.system {}\n", encoding="utf-8")
    with pytest.raises(YAMLError):
        load_yaml(unsafe)


def test_atomic_write_refuses_overwrite(project_dir) -> None:
    assert Path.cwd() == project_dir
    assert project_dir != REPO_ROOT
    # Relative path: the file is created in the directory from the `project_dir` fixture.
    write_atomic(Path("data") / "probes" / "probe.yaml", "a: 1\n")
    target = project_dir / "data" / "probes" / "probe.yaml"
    assert target.read_text(encoding="utf-8") == "a: 1\n"
    assert not target.with_name(target.name + ".tmp").exists()
    assert sorted(p.name for p in target.parent.iterdir()) == ["probe.yaml"]

    with pytest.raises(FileExistsError):
        write_atomic(target, "a: 2\n")
    assert target.read_text(encoding="utf-8") == "a: 1\n"
    assert not target.with_name(target.name + ".tmp").exists()


def test_dev_blocker() -> None:
    with pytest.raises(pytest.fail.Exception):
        serial.serial_for_url("/dev/cu.test")
    with pytest.raises(pytest.fail.Exception):
        serial.serial_for_url("/dev/cu.test", do_not_open=True)
    with pytest.raises(pytest.fail.Exception):
        serial.Serial("/dev/cu.test")

    port = serial.Serial()
    port.port = "/dev/cu.test"
    with pytest.raises(pytest.fail.Exception):
        port.open()

    loop = serial.serial_for_url("loop://", timeout=0)
    try:
        loop.write(b"ATI\r")
        assert loop.read(4) == b"ATI\r"
    finally:
        loop.close()


def _normalize_requirement(requirement: str) -> tuple[str, frozenset[str]]:
    """Splits a PEP 508 requirement into a normalized name and a set of specifiers."""
    match = re.fullmatch(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(.*)", requirement)
    assert match is not None, requirement
    name = re.sub(r"[-_.]+", "-", match.group(1)).lower()
    specs = frozenset(part.strip() for part in match.group(2).split(",") if part.strip())
    return name, specs


def test_project_metadata() -> None:
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = pyproject["project"]
    assert project["name"] == "obd-bridge"
    assert project["version"] == "0.0.1a"
    assert project["requires-python"] == ">=3.13"
    assert project["scripts"] == {"obdb": "obd_bridge.cli:main"}

    dependencies = dict(_normalize_requirement(r) for r in project["dependencies"])
    assert dependencies == {
        "udsoncan": frozenset({">=1.26", "<2"}),
        "pyserial": frozenset({">=3.5", "<4"}),
        "ruamel-yaml": frozenset({">=0.18"}),
        "typer": frozenset({">=0.29", "<0.30"}),
    }
    dev = dict(_normalize_requirement(r) for r in pyproject["dependency-groups"]["dev"])
    assert dev == {"pytest": frozenset({">=8"})}

    assert pyproject["build-system"]["build-backend"] == "uv_build"
    pytest_options = pyproject["tool"]["pytest"]["ini_options"]
    assert pytest_options["testpaths"] == ["tests"]
    assert pytest_options["addopts"] == "-ra"

    assert (REPO_ROOT / ".python-version").read_text(encoding="utf-8").strip() == "3.14"
    assert (REPO_ROOT / "uv.lock").is_file()

    gitignore = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    for rule in (
        "data/sessions/",
        "data/index.sqlite",
        "reports/",
        "data/probes/",
        ".venv/",
        "__pycache__/",
        ".pytest_cache/",
    ):
        assert gitignore.count(rule) == 1, rule


def test_no_dash_punctuation_in_sources() -> None:
    """FR-29: no em dash or en dash in `src/`, `tests/` and `defs/`; no comma before the conjunction "i" in `src/`."""
    dashes = re.compile("[\u2014\u2013]")
    comma_i = re.compile(r", i ")
    suffixes = {".py", ".yaml", ".json", ".jsonl", ".txt"}
    offenders: list[str] = []
    for top in ("src", "tests", "defs"):
        for path in sorted((REPO_ROOT / top).rglob("*")):
            if not path.is_file() or path.suffix not in suffixes or "__pycache__" in path.parts:
                continue
            text = path.read_text(encoding="utf-8")
            for number, line in enumerate(text.splitlines(), start=1):
                where = f"{path.relative_to(REPO_ROOT)}:{number}"
                if dashes.search(line):
                    offenders.append(f"{where}: dash")
                if top == "src" and comma_i.search(line):
                    offenders.append(f"{where}: comma before i")
    assert not offenders, "FR-29 violations:\n" + "\n".join(offenders)
