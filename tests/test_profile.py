"""Tests of the adapter profile `AdapterProfile` (spec T8, probe file T9, FR-22)."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from obd_bridge.stn.profile import AdapterProfile, ProfileError
from obd_bridge.stn.state import FcStrategy

STI = "STN2120 v4.5.0"
STDI = "STN2120 r1.0"


def _probe_text(
    *,
    started_at: str = '"2026-11-20T08:15:00.123+01:00"',
    schema: str = "obdb.probe/1",
    mode: str = "live",
    sti: str = STI,
    stdi: str = STDI,
    fc_strategy: str = "st_pairs",
    nrc78_mode: str = "unknown",
) -> str:
    """Builds the content of an `obdb.probe/1` probe file with default values from the T9 example."""
    return f"""\
schema: {schema}
session_id: 20261120T081500-probe
mode: {mode}
started_at: {started_at}
finished_at: "2026-11-20T08:17:41.456+01:00"
adapter:
  elm: ELM327 v1.3a
  sti: {sti}
  stdi: {stdi}
  stvr: "12.60"
commands: {{STCSEGR: ok, STFCP: unsupported, STCFCPA: ok, STCAFCP: untested}}
fc_strategy: {fc_strategy}
nrc78_mode: {nrc78_mode}
timing:
  stpx_22f187_ms: {{n: 100, p50: 33.0, p95: 41.0, min: 30.1, max: 55.2, baud: 38400}}
exit_code: 0
"""


def _write_probe(probes_dir: Path, day: str, name: str, text: str) -> Path:
    path = probes_dir / day / f"{name}-probe.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_load_latest_picks_newest(tmp_path: Path) -> None:
    probes = tmp_path / "probes"
    _write_probe(probes, "2026-11-19", "20261119T200000", _probe_text(
        started_at='"2026-11-19T20:00:00+01:00"', fc_strategy="elm_fallback"))
    newest = _write_probe(probes, "2026-11-20", "20261120T070000", _probe_text(
        started_at='"2026-11-20T07:30:00+00:00"', fc_strategy="st_pairs_legacy"))
    # Later local time, but earlier than `newest` in UTC (07:00 UTC).
    _write_probe(probes, "2026-11-20", "20261120T080000", _probe_text(
        started_at='"2026-11-20T08:00:00+01:00"', fc_strategy="st_pairs"))

    profile = AdapterProfile.load_latest(STI, STDI, probes_dir=probes)

    assert profile is not None
    assert profile.source == str(newest)
    assert profile.fc_strategy is FcStrategy.ST_PAIRS_LEGACY

    # `started_at` tie: the greater file name wins.
    tie_a = _write_probe(probes, "2026-11-21", "20261121T100000-a", _probe_text(
        started_at='"2026-11-21T10:00:00+01:00"', fc_strategy="st_pairs"))
    tie_b = _write_probe(probes, "2026-11-21", "20261121T100000-b", _probe_text(
        started_at='"2026-11-21T10:00:00+01:00"', fc_strategy="elm_fallback"))
    assert tie_b.name > tie_a.name

    profile = AdapterProfile.load_latest(STI, STDI, probes_dir=probes)

    assert profile is not None
    assert profile.source == str(tie_b)
    assert profile.fc_strategy is FcStrategy.ELM_FALLBACK


@pytest.mark.parametrize(
    ("label", "text"),
    [
        ("other_sti", _probe_text(sti="STN1110 v4.0.1")),
        ("other_stdi", _probe_text(stdi="STN2120 r2.0")),
        ("mode_dry_run", _probe_text(mode="dry-run")),
        ("fc_null", _probe_text(fc_strategy="null")),
        ("wrong_schema", _probe_text(schema="obdb.probe/2")),
        ("broken_yaml", "schema: obdb.probe/1\nadapter: [unclosed\n  sti: : :\n"),
        ("started_at_unquoted", _probe_text(started_at="2026-11-21T09:00:00+01:00")),
        ("unknown_strategy", _probe_text(fc_strategy="magic")),
        ("list_instead_of_map", "- schema\n- obdb.probe/1\n"),
    ],
)
def test_load_latest_filters(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, label: str, text: str
) -> None:
    probes = tmp_path / "probes"
    good = _write_probe(probes, "2026-11-20", "20261120T081500", _probe_text())
    bad = _write_probe(probes, "2026-11-21", f"20261121T090000-{label}", text)

    with caplog.at_level(logging.WARNING, logger="obd_bridge.stn.profile"):
        profile = AdapterProfile.load_latest(STI, STDI, probes_dir=probes)

    assert profile is not None
    assert profile.source == str(good)
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert any(bad.name in r.getMessage() for r in warnings), [r.getMessage() for r in warnings]
    assert not any(good.name in r.getMessage() for r in warnings)


def test_load_latest_none(tmp_path: Path) -> None:
    missing = tmp_path / "missing"
    assert AdapterProfile.load_latest(STI, STDI, probes_dir=missing) is None

    probes = tmp_path / "probes"
    probes.mkdir()
    assert AdapterProfile.load_latest(STI, STDI, probes_dir=probes) is None

    # Files outside the `*/*-probe.yaml` pattern are not candidates.
    (probes / "loose-probe.yaml").write_text(_probe_text(), encoding="utf-8")
    _write_probe(probes, "2026-11-20", "20261120T081500", _probe_text()).rename(
        probes / "2026-11-20" / "20261120T081500.yaml"
    )
    assert AdapterProfile.load_latest(STI, STDI, probes_dir=probes) is None

    # Only files rejected by the filter also give `None`.
    _write_probe(probes, "2026-11-21", "20261121T090000", _probe_text(mode="dry-run"))
    assert AdapterProfile.load_latest(STI, STDI, probes_dir=probes) is None


def test_from_probe_file_fields(tmp_path: Path) -> None:
    path = _write_probe(tmp_path, "2026-11-20", "20261120T081500", _probe_text(
        fc_strategy="st_pairs", nrc78_mode="needs_r2"))

    profile = AdapterProfile.from_probe_file(path)

    assert profile.sti == STI
    assert profile.stdi == STDI
    assert profile.commands == {
        "STCSEGR": "ok",
        "STFCP": "unsupported",
        "STCFCPA": "ok",
        "STCAFCP": "untested",
    }
    assert isinstance(profile.fc_strategy, FcStrategy)
    assert profile.fc_strategy is FcStrategy.ST_PAIRS
    assert profile.nrc78_mode == "needs_r2"
    assert profile.timing == {
        "stpx_22f187_ms": {"n": 100, "p50": 33.0, "p95": 41.0, "min": 30.1, "max": 55.2, "baud": 38400}
    }
    assert profile.source == str(path)

    with pytest.raises(AttributeError):
        profile.sti = "other"  # type: ignore[misc]

    null_fc = _write_probe(tmp_path, "2026-11-20", "20261120T090000", _probe_text(fc_strategy="null"))
    assert AdapterProfile.from_probe_file(null_fc).fc_strategy is None


def test_probe_file_name_matches_profile_glob(tmp_path: Path) -> None:
    """The probe file is `<session_id>.yaml`; the profile also finds a name with a collision suffix."""
    from obd_bridge.probe.report import probe_path_for

    jsonl = tmp_path / "data" / "sessions" / "2026-11-21" / "20261121T110000-probe-2.jsonl"
    path = probe_path_for(tmp_path, jsonl, "20261121T110000-probe-2")
    assert path == tmp_path / "data" / "probes" / "2026-11-21" / "20261121T110000-probe-2.yaml"
    path.parent.mkdir(parents=True)
    path.write_text(_probe_text(started_at='"2026-11-21T11:00:00+01:00"'), encoding="utf-8")
    profile = AdapterProfile.load_latest("STN2120 v4.5.0", "STN2120 r1.0", tmp_path / "data" / "probes")
    assert profile is not None and profile.source == str(path)


def test_probe_file_load_errors_without_library_text(tmp_path: Path) -> None:
    """Probe file load errors have a fixed description without system or ruamel text."""
    with pytest.raises(ProfileError) as missing:
        AdapterProfile.from_probe_file(tmp_path / "missing-probe.yaml")
    assert "cannot read file (file does not exist)" in str(missing.value)

    broken = tmp_path / "bad-probe.yaml"
    broken.write_text("schema: obdb.probe/1\nadapter: [sti\n", encoding="utf-8")
    with pytest.raises(ProfileError) as syntax:
        AdapterProfile.from_probe_file(broken)
    message = str(syntax.value)
    assert "invalid YAML (line" in message
    for ruamel_text in ("expected", "while parsing", "found", "Error"):
        assert ruamel_text not in message

    binary = tmp_path / "binary-probe.yaml"
    binary.write_bytes(b"schema: \xff\xfe\n")
    with pytest.raises(ProfileError) as decode:
        AdapterProfile.from_probe_file(binary)
    assert "file is not UTF-8 text" in str(decode.value)
