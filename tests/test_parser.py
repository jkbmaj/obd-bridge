"""Tests of the adapter line parser (`stn/parser.py`, spec T4, FR-11).

Golden transcripts from `tests/fixtures/transcripts/` are the only source of
expected results for typical paths; randomised tests make sure the parser
raises no exception for any input.
"""

from __future__ import annotations

import random
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from obd_bridge.stn.parser import (
    AdapterReply,
    ExchangeOutcome,
    ReplyOutcome,
    UdsExchange,
    parse_adapter_reply,
    parse_uds_exchange,
)

TRANSCRIPTS_DIR = Path(__file__).resolve().parent / "fixtures" / "transcripts"
TRANSCRIPT_FILES = sorted(TRANSCRIPTS_DIR.glob("*.txt"))

MINIMUM_TRANSCRIPTS = (
    "sf_positive",
    "ff_cf_padding",
    "ff_cf_no_padding",
    "nrc_31",
    "nrc78_then_final",
    "nrc78_only",
    "no_data",
    "foreign_frame",
    "buffer_full",
    "question_mark",
    "stopped",
    "can_error",
    "fc_rx_timeout",
    "cf_sequence_error",
    "ff_incomplete",
    "spaces_in_frames",
    "atws_banner_echo",
    "ate0_with_echo",
    "stcsegr1_unknown_format",
)


@pytest.mark.parametrize("path", TRANSCRIPT_FILES, ids=lambda p: p.stem)
def test_transcripts(path: Path, load_transcript: Callable[[Path], Any]) -> None:
    """Parser result matches the `=` line of the golden transcript."""
    transcript = load_transcript(path)
    sent, raw, rx_id, (outcome, rest) = transcript.as_parser_input()

    if transcript.kind == "adapter":
        reply = parse_adapter_reply(raw, sent)
        assert isinstance(reply, AdapterReply)
        assert reply.outcome == outcome
        if outcome == ReplyOutcome.VALUE:
            assert reply.text == rest
        elif outcome == ReplyOutcome.ERROR:
            assert reply.error_token == rest
        else:
            assert rest == ""
        return

    assert rx_id is not None, f"{path.name}: UDS transcript without @rx_id"
    exchange = parse_uds_exchange(raw, sent, rx_id)
    assert isinstance(exchange, UdsExchange)
    assert exchange.outcome == outcome, exchange
    assert exchange.line == sent
    assert exchange.raw == raw
    if outcome in (ExchangeOutcome.POSITIVE, ExchangeOutcome.NEGATIVE):
        assert exchange.final is not None
        assert exchange.final.hex().upper() == rest
        if outcome == ExchangeOutcome.NEGATIVE:
            assert exchange.nrc == exchange.final[2]
        else:
            assert exchange.nrc is None
    elif outcome == ExchangeOutcome.ADAPTER_ERROR:
        assert exchange.error_token == rest
        assert exchange.final is None
    else:
        assert rest == ""
        assert exchange.final is None


def test_minimum_transcript_set() -> None:
    """All 19 transcripts from the T4 minimum list exist."""
    names = {path.stem for path in TRANSCRIPT_FILES}
    missing = [name for name in MINIMUM_TRANSCRIPTS if name not in names]
    assert missing == []
    assert len(MINIMUM_TRANSCRIPTS) == 19


def test_parser_never_raises() -> None:
    """500 random inputs (fixed seed) through both functions without an exception."""
    rng = random.Random(20261119)
    alphabet = b"0123456789ABCDEF 7F78\r\n>?NODATA<RXERROKSTPX:,"
    for index in range(500):
        length = rng.randint(0, 160)
        if index % 2:
            raw = bytes(rng.randrange(256) for _ in range(length))
        else:
            raw = bytes(rng.choice(alphabet) for _ in range(length))
        sent = rng.choice(["", "ATWS", "STPX H:710,D:22F187,R:1", raw.decode("latin-1")[:12]])
        rx_id = rng.choice([0x77A, 0x7E8, 0x000, 0x7FF, rng.randrange(0x800)])

        reply = parse_adapter_reply(raw, sent)
        exchange = parse_uds_exchange(raw, sent, rx_id)

        assert reply.outcome in set(ReplyOutcome)
        assert exchange.outcome in set(ExchangeOutcome)
        assert exchange.pending_count >= 0


def test_foreign_and_echo() -> None:
    """Echo is removed only when equal to `sent`; foreign CAN IDs go to `foreign_frames`."""
    sent = "STPX H:710,D:22F1A3,R:1"
    raw = (sent + "\r7E80662F1A3010203\r77A0662F1A348303155\r\r>").encode("ascii")

    exchange = parse_uds_exchange(raw, sent, 0x77A)
    assert exchange.echo is True
    assert exchange.lines == ("7E80662F1A3010203", "77A0662F1A348303155")
    assert [frame.can_id for frame in exchange.foreign_frames] == [0x7E8]
    assert [frame.can_id for frame in exchange.frames] == [0x77A]
    assert exchange.messages == (bytes.fromhex("62F1A3483031"),)
    assert exchange.outcome == ExchangeOutcome.POSITIVE
    assert exchange.final == bytes.fromhex("62F1A3483031")

    # A line different from `sent` is not an echo, even when it is similar to it.
    other = parse_uds_exchange(raw, "STPX H:710,D:22F1A3,R:1,T:500", 0x77A)
    assert other.echo is False
    assert sent in other.unparsed_lines
    assert other.outcome == ExchangeOutcome.POSITIVE

    reply_echo = parse_adapter_reply(b"ATE0\rOK\r\r>", "ATE0")
    assert reply_echo.echo is True
    assert reply_echo.outcome == ReplyOutcome.OK
    reply_no_echo = parse_adapter_reply(b"ATE0\rOK\r\r>", "ATL0")
    assert reply_no_echo.echo is False
    assert reply_no_echo.outcome == ReplyOutcome.VALUE
    assert reply_no_echo.lines == ("ATE0", "OK")

    # Only foreign frames: no messages, outcome `unparsed`.
    only_foreign = parse_uds_exchange(b"7E80662F1A3010203\r\r>", sent, 0x77A)
    assert only_foreign.messages == ()
    assert len(only_foreign.foreign_frames) == 1
    assert only_foreign.outcome == ExchangeOutcome.UNPARSED


def test_scripted_transport_from_transcript(
    load_transcript: Callable[[Path | str], Any], scripted_transport: type
) -> None:
    """Transcript as a transport script: bytes, `timeout_s`, banner and an error on a wrong write."""
    from obd_bridge.errors import TransportTimeout

    transcript = load_transcript("ff_cf_padding")
    transport = transcript.to_transport(with_banner=True)
    with pytest.raises(TransportTimeout) as banner:
        transport.read_until(b">", 1.0)
    assert banner.value.partial == b""

    transport.write(transcript.sent.encode("ascii") + b"\r")
    raw = transport.read_until(b">", 7.0)
    assert raw == transcript.raw
    assert raw.endswith(b"\r>")
    assert transport.read_timeouts == [1.0, 7.0]
    assert transport.written_lines == [transcript.sent]
    assert transport.remaining == 0

    manual = scripted_transport().expect("ATE0", "ATE0\rOK\r\r>")
    with pytest.raises(pytest.fail.Exception):
        manual.write(b"ATL0\r")
