"""Command-line interface `obdb` (spec T11).

Commands:
    `obdb probe`: probe plan (without flags), `--dry-run` with `NullTransport` or
        `--execute` with preflight and a transport from the `open_transport` factory.
    `obdb audit SESSION_JSONL`: audit of a session log with the current read-only policy.
    `obdb report PROBE_FILE`: offline readout of a probe file, optionally compared
        with a reference file (`--reference`); never opens a port.

The module does not import the runner, transports or pyserial at import time: each
command branch loads only what it needs. Plan mode creates no files or
directories and does not open the port; dry-run uses only `NullTransport`;
the serial transport module is imported only in `open_transport` and, for
`--execute` without `--transport`, in `detect_transport_url`.

`main(argv)` runs the application with `standalone_mode=False` and converts
exceptions to exit codes itself (code table in spec T11).
"""

from __future__ import annotations

import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any, Final

import typer

from obd_bridge.errors import ObdBridgeError

# typer 0.29 contains its own copy of click in the private module `typer._click` and
# does not depend on the click package; the upper bound `typer<0.30` in pyproject.toml
# ensures this module exists. The test `test_usage_error_class_matches_typer` checks
# that the caught class is the one the typer parser raises.
from typer._click.exceptions import NoArgsIsHelpError, UsageError

if TYPE_CHECKING:
    from obd_bridge.probe.engine import ProbeWarning
    from obd_bridge.probe.runner import ProbeSession, StepResult
    from obd_bridge.transport.base import ByteTransport
    from obd_bridge.vag.catalog import EcuCatalog

PROG_NAME: Final[str] = "obdb"
"""Program name in help and messages."""

ODOMETER_MAX_KM: Final[int] = 2_000_000
"""Upper bound of `--odometer-km` (inclusive)."""

EXIT_OK: Final[int] = 0
EXIT_PREFLIGHT: Final[int] = 1
EXIT_INTERNAL: Final[int] = 3
EXIT_INTERRUPTED: Final[int] = 4
EXIT_USAGE: Final[int] = 64

MESSAGE_EOF: Final[str] = "No input data."
MESSAGE_INTERRUPTED: Final[str] = "Interrupted (Ctrl-C)."

_ARGV_KEY: Final[str] = "argv"

app = typer.Typer(
    name=PROG_NAME,
    help="Read-only OBD/UDS diagnostic bridge for the STN2120 adapter (Audi A6 C7).",
    add_completion=False,
    pretty_exceptions_enable=False,
    no_args_is_help=True,
    rich_markup_mode=None,
)


# ---------------------------------------------------------------------------
# Factories and helpers


def open_transport(url: str) -> ByteTransport:
    """Transport factory for `--execute`: `SerialTransport` for `/dev/*` and other pyserial URLs.

    `SerialTransport` is imported only here, so plan and dry-run do not
    load the serial transport module. The runner opens the port in step 1.
    Tests replace this function via `monkeypatch`.
    """
    from obd_bridge.transport.serial_transport import SerialTransport

    return SerialTransport(url)


def detect_transport_url(ctx: typer.Context) -> str:
    """Port of the single connected FTDI adapter for `--execute` without `--transport`.

    Enumerates USB serial devices without opening any port. No adapter gives
    `TransportError` (code 3); several adapters give `UsageError` (code 64),
    because the operator has to choose one with `--transport`. Tests replace
    this function via `monkeypatch`.
    """
    from obd_bridge.errors import TransportError
    from obd_bridge.transport.serial_transport import find_adapter_ports

    ports = find_adapter_ports()
    if len(ports) == 1:
        return ports[0]
    if not ports:
        raise TransportError("No USB adapter with an FTDI chip found; connect the adapter or pass --transport.")
    raise UsageError(
        f"several USB adapters with an FTDI chip found ({', '.join(ports)}); choose one with --transport.",
        ctx=ctx,
    )


def _load_catalog() -> EcuCatalog:
    """ECU catalog from `defs/ecu-catalog.yaml` relative to the working directory (missing file: code 64)."""
    from obd_bridge.vag.catalog import EcuCatalog

    return EcuCatalog.load()


def _argv(ctx: typer.Context) -> list[str]:
    """Invocation arguments stored by `main()` in the context object (`session_start` metadata)."""
    obj = ctx.find_root().obj
    if isinstance(obj, dict):
        return list(obj.get(_ARGV_KEY, ()))
    return []


def _echo_err(message: str) -> None:
    typer.echo(message, err=True)


def _progress(step: StepResult) -> None:
    """`--execute` progress on stderr, one line per step."""
    from obd_bridge.probe.report import format_progress

    _echo_err(format_progress(step))


def _warning(warning: ProbeWarning) -> None:
    """Warning without a stop on stderr at detection time, one line (package D)."""
    from obd_bridge.probe.report import format_warning

    _echo_err(format_warning(warning))


def _deferred_interrupt_notice(session: ProbeSession) -> None:
    """One message on stderr when Ctrl-C arrived during the audit or while writing results."""
    from obd_bridge.probe.runner import DEFERRED_INTERRUPT_NOTICE

    if session.deferred_interrupts:
        _echo_err(DEFERRED_INTERRUPT_NOTICE)


def _close_quietly(transports: Sequence[ByteTransport]) -> None:
    """Close transports created by the factory after an unhandled exception; ignore close errors."""
    for transport in transports:
        try:
            transport.close()
        except Exception:  # an emergency close must not mask the original exception
            pass


def _validate_probe_options(
    ctx: typer.Context,
    *,
    dry_run: bool,
    execute: bool,
    yes: bool,
    transport: str | None,
    note: str | None,
    odometer_km: int | None,
) -> None:
    """Constraints on `obdb probe` options from table T11; a violation gives `UsageError` (code 64)."""
    if dry_run and execute:
        raise UsageError("options --dry-run and --execute are mutually exclusive.", ctx=ctx)
    if not execute:
        if yes:
            raise UsageError("option --yes works only with --execute.", ctx=ctx)
        if transport is not None:
            raise UsageError("option --transport works only with --execute.", ctx=ctx)
    if not (dry_run or execute):
        if note is not None:
            raise UsageError("option --note requires --dry-run or --execute.", ctx=ctx)
        if odometer_km is not None:
            raise UsageError("option --odometer-km requires --dry-run or --execute.", ctx=ctx)


# ---------------------------------------------------------------------------
# Commands


@app.command(
    "probe",
    help=(
        "Probe of the adapter and modules. Without flags prints the step plan (no files and no port); "
        "--dry-run runs the whole stack with a synthetic transport; --execute connects to the car "
        "after the checklist."
    ),
)
def probe_command(
    ctx: typer.Context,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Run with NullTransport: JSONL log, no probe file and no port."),
    ] = False,
    execute: Annotated[
        bool,
        typer.Option("--execute", help="Live probe through the adapter (checklist before the port is opened)."),
    ] = False,
    yes: Annotated[
        bool,
        typer.Option("--yes", help="Confirm the checklist without a question (only with --execute)."),
    ] = False,
    transport: Annotated[
        str | None,
        typer.Option(
            "--transport",
            metavar="URL",
            help=(
                "Adapter port or pyserial URL (only with --execute). "
                "Without it the single connected adapter with an FTDI chip is used."
            ),
        ),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Output as a JSON document on stdout."),
    ] = False,
    note: Annotated[
        str | None,
        typer.Option("--note", metavar="TEXT", help="Note stored in the session log (with --dry-run or --execute)."),
    ] = None,
    odometer_km: Annotated[
        int | None,
        typer.Option(
            "--odometer-km",
            metavar="N",
            min=0,
            max=ODOMETER_MAX_KM,
            help=f"Car odometer reading in km, 0..{ODOMETER_MAX_KM} (with --dry-run or --execute).",
        ),
    ] = None,
) -> int:
    """`obdb probe`: plan, dry-run or execute (spec T9, T11)."""
    _validate_probe_options(
        ctx,
        dry_run=dry_run,
        execute=execute,
        yes=yes,
        transport=transport,
        note=note,
        odometer_km=odometer_km,
    )
    catalog = _load_catalog()
    if execute:
        return _probe_execute(
            catalog,
            url=transport if transport is not None else detect_transport_url(ctx),
            yes=yes,
            json_output=json_output,
            note=note,
            odometer_km=odometer_km,
            argv=_argv(ctx),
        )
    if dry_run:
        return _probe_dry_run(catalog, json_output=json_output, note=note, odometer_km=odometer_km, argv=_argv(ctx))
    return _probe_plan(catalog, json_output=json_output)


def _probe_plan(catalog: EcuCatalog, *, json_output: bool) -> int:
    """Step plan without I/O: no files, directories or transport (FR-23)."""
    from obd_bridge.probe.plan import build_steps
    from obd_bridge.probe.report import render_plan_json, render_plan_text

    steps = build_steps(catalog)
    typer.echo(render_plan_json(steps) if json_output else render_plan_text(steps))
    return EXIT_OK


def _probe_dry_run(
    catalog: EcuCatalog,
    *,
    json_output: bool,
    note: str | None,
    odometer_km: int | None,
    argv: list[str],
) -> int:
    """Dry-run with `NullTransport`: JSONL `mode: dry-run`, automatic audit, no probe file (FR-24)."""
    from obd_bridge.probe.report import render_dry_run_json, render_dry_run_text
    from obd_bridge.probe.runner import dry_run_probe

    session = dry_run_probe(catalog, note=note, odometer_km=odometer_km, argv=argv)
    _deferred_interrupt_notice(session)
    typer.echo(render_dry_run_json(session) if json_output else render_dry_run_text(session))
    return session.exit_code


def _probe_execute(
    catalog: EcuCatalog,
    *,
    url: str,
    yes: bool,
    json_output: bool,
    note: str | None,
    odometer_km: int | None,
    argv: list[str],
) -> int:
    """Live probe: preflight before the transport factory, progress on stderr, summary on stdout (FR-25)."""
    from obd_bridge.probe.report import render_run_json, render_run_text
    from obd_bridge.probe.runner import execute_probe

    created: list[ByteTransport] = []

    def factory(target_url: str) -> ByteTransport:
        transport = open_transport(target_url)
        created.append(transport)
        return transport

    try:
        session = execute_probe(
            catalog,
            factory,
            url=url,
            yes=yes,
            note=note,
            odometer_km=odometer_km,
            argv=argv,
            on_step=_progress,
            on_warning=_warning,
        )
    except BaseException:
        # The runner closes the driver itself; here the port is closed after an exception from outside the runner.
        _close_quietly(created)
        raise
    _deferred_interrupt_notice(session)
    typer.echo(render_run_json(session) if json_output else render_run_text(session))
    return session.exit_code


@app.command("audit", help="Audit of a JSONL session log with the current read-only policy (code 2 on violation).")
def audit_command(
    session_jsonl: Annotated[
        Path,
        typer.Argument(metavar="SESSION_JSONL", help="Session log file data/sessions/<date>/<session_id>.jsonl."),
    ],
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Output as a JSON document obdb.audit/1 on stdout."),
    ] = False,
) -> int:
    """`obdb audit`: check of the `tx` bytes of a session log (spec T10); missing file or format error: code 64."""
    from obd_bridge.audit import audit_session, render_json, render_text

    result = audit_session(session_jsonl, _load_catalog())
    typer.echo(render_json(result) if json_output else render_text(result))
    return result.exit_code


@app.command(
    "report",
    help=(
        "Offline report of a probe file: identification and DTCs per module, optionally compared with "
        "a reference file (e.g. values from OBDeleven). Never opens a port; differences do not change the "
        "exit code."
    ),
)
def report_command(
    probe_file: Annotated[
        Path,
        typer.Argument(metavar="PROBE_FILE", help="Probe file data/probes/<date>/<session_id>.yaml."),
    ],
    reference: Annotated[
        Path | None,
        typer.Option("--reference", metavar="REF_YAML", help="Reference file with schema obdb.reference/1."),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Output as a JSON document obdb.report/1 on stdout."),
    ] = False,
) -> int:
    """`obdb report`: readout of an `obdb.probe/1` file; input errors give code 64."""
    from obd_bridge.probe.readout import (
        build_report,
        load_probe,
        load_reference,
        render_report_json,
        render_report_text,
    )

    catalog = _load_catalog()
    readout = load_probe(probe_file, catalog)
    expected = load_reference(reference) if reference is not None else None
    document = build_report(readout, catalog, expected)
    typer.echo(render_report_json(document) if json_output else render_report_text(document))
    return EXIT_OK


# ---------------------------------------------------------------------------
# Entry point


def _usage_error(exc: UsageError) -> int:
    """Usage error on stderr with a prefix and a help hint; code 64."""
    command_path = exc.ctx.command_path if exc.ctx is not None else PROG_NAME
    _echo_err(f"Usage error: {exc.format_message()}")
    _echo_err(f"Help: {command_path} --help")
    return EXIT_USAGE


def _as_exit_code(value: Any) -> int:
    """Value returned by the command as the exit code (`None` gives 0)."""
    if isinstance(value, bool) or value is None:
        return EXIT_OK
    if isinstance(value, int):
        return value
    return EXIT_OK


def _invoke(command: Any, args: list[str]) -> Any:
    """Invoke the application without `standalone_mode`: exceptions reach `main()`.

    Equivalent of click's `main(standalone_mode=False)`: `EOFError` and
    `KeyboardInterrupt` from outside the runner become `Abort` with the cause in
    `__cause__`, and `Exit` (e.g. after `--help`) gives its code. A custom invocation
    instead of `command.main(...)` follows from the behaviour of typer 0.29: its `_main`
    turns `KeyboardInterrupt` into `Exit(130)`, while the T11 code table requires 4.
    """
    try:
        with command.make_context(PROG_NAME, args, obj={_ARGV_KEY: args}) as ctx:
            return command.invoke(ctx)
    except typer.Exit as exc:
        return exc.exit_code
    except (EOFError, KeyboardInterrupt) as exc:
        raise typer.Abort() from exc


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point of the `obdb` script; returns the exit code (spec T11).

    Parameters:
        argv: arguments without the program name (default `sys.argv[1:]`).

    Handling order: `NoArgsIsHelpError` (help on stdout, 0), `UsageError`
    (64), `Abort` (`EOFError` as cause: 1, otherwise 4), `ObdBridgeError`
    (its `exit_code`, message on stderr), any other exception (`Internal error`,
    3); in all other cases the value returned by the command.
    """
    args = list(sys.argv[1:] if argv is None else argv)
    command = typer.main.get_command(app)
    try:
        value = _invoke(command, args)
    except NoArgsIsHelpError as exc:
        if exc.ctx is not None:
            typer.echo(exc.ctx.get_help())
        return EXIT_OK
    except UsageError as exc:
        return _usage_error(exc)
    except typer.Abort as exc:
        if isinstance(exc.__cause__, EOFError):
            _echo_err(MESSAGE_EOF)
            return EXIT_PREFLIGHT
        _echo_err(MESSAGE_INTERRUPTED)
        return EXIT_INTERRUPTED
    except ObdBridgeError as exc:
        _echo_err(str(exc))
        return exc.exit_code
    except Exception as exc:
        _echo_err(f"Internal error: {type(exc).__name__}: {exc}")
        return EXIT_INTERNAL
    return _as_exit_code(value)
