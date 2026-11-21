# obd-bridge

> **Warning: Work In Progress.** The project is at an early stage (version `0.0.1a`). The live probe (`obdb probe --execute`) has not yet been run on a real car; some STN2120 adapter behaviour is unconfirmed (list below). The CLI interface, file formats and log schemas may change without backward compatibility. The project is not intended for production use.

> **Warning:** The tool communicates with the vehicle's control units. Use it at your own risk. The author is not liable for vehicle damage, a discharged battery or data loss.

Read-only OBD/UDS diagnostic bridge for the STN2120 adapter (OBDLink) and the Audi A6 C7. The goal of the project is repeatable, auditable reading of control unit data, in particular the ZF 8HP transmission adaptation parameters, without any risk of writing to the car.

## Project status

Done in version `0.0.1a`:

- transport layers (serial port, synthetic transport, replay), STN2120 driver, UDS connection and read-only UDS client;
- double guard (UDS layer and adapter command layer) with an allowlist;
- JSONL session log with a full traffic record, and `obdb audit`, which checks a recorded log against the current policy;
- `obdb probe`: plan, synthetic run (`--dry-run`) and live probe (`--execute`) with a checklist;
- voltage and engine state sample before each module, with one module retry after an engine state change;
- `obdb report`: offline report of a probe file with decoded DTCs and identification, optionally compared with a reference file;
- tests (`pytest`) on synthetic data, STN emulator used in verification.

Unconfirmed on hardware (⚠ to be checked in the first session):

- acceptance of uppercase `STPX` parameters on STN2120 v4.5.0;
- availability of `STCFCPA` and `STFFCA` in firmware v4.5.0;
- reading engine speed `22 F40C` from the J623 engine control unit;
- possible `BUFFER FULL` at 38400 baud for large `19 0A` responses;
- false alarms of adapter reset detection on a real FTDI.

Out of scope for this version: drive logging, data index, adaptation trend reports, UART speed change.

## Read-only policy

The policy cannot be disabled by a flag, an environment variable or a parameter. Every line sent to the adapter passes through the guard; a rejected line does not reach the port, not even a single byte, and the session ends with exit code 2.

Allowed on the CAN bus: `0x22` (ReadDataByIdentifier, 1 to 3 DIDs per request), `0x19` (ReadDTCInformation, subfunctions `01`, `02`, `03`, `04`, `06` and `0A`; `04` and `06` without record `0xFF`) and the OBD modes `01`, `03`, `06`, `07`, `09` and `0A`. Every other service is rejected, among others `0x10` (DiagnosticSessionControl), `0x3E` (TesterPresent), `0x2E`, `0x31`, `0x2F`, `0x14`, `0x27`, `0x11` and `0x34` to `0x37`. All reads therefore run in the control unit's default diagnostic session. The target can only be a module from `defs/ecu-catalog.yaml`; the functional address `0x7DF` and a scan of the range `0x700..0x769` are blocked. Adapter commands are limited to volatile settings; programmable parameters (PP) are only read.

## Requirements

- macOS or Linux, [uv](https://docs.astral.sh/uv/).
- CPython 3.13 or newer (the project pins 3.14 in `.python-version`).
- For `--execute`: an STN2120-based adapter connected over USB.

## Installation

```sh
git clone https://github.com/jkbmaj/obd-bridge.git
cd obd-bridge
uv sync
uv run obdb --help
```

> **Note:** `obdb` requires the VAG module catalog `defs/ecu-catalog.yaml` at runtime. The catalog is not included in the repository and must be provided locally. Without it, `obdb` exits with code 64.

## Usage

`obdb` runs from the project directory: the paths `defs/`, `data/sessions/` and `data/probes/` are resolved relative to the current directory.

```sh
uv run obdb probe                 # step plan, no port and no files
uv run obdb probe --dry-run       # full stack with synthetic transport, log in data/sessions/
uv run obdb probe --execute       # live probe after the checklist
uv run obdb audit data/sessions/<date>/<session_id>.jsonl
uv run obdb report data/probes/<date>/<session_id>.yaml --reference ref.yaml
```

`obdb probe` options:

| Option | Meaning |
|---|---|
| `--dry-run` | Run without a port; JSONL log, no probe file. |
| `--execute` | Live probe through the adapter; checklist before the port is opened. |
| `--yes` | Confirm the checklist without a prompt (only with `--execute`). |
| `--transport URL` | Adapter port or pyserial URL (only with `--execute`). Without it, `--execute` uses the single connected USB adapter with an FTDI chip (OBDLink); with no such adapter or with several, it stops before the checklist. Detection only lists devices and opens no port. |
| `--json` | Result as a JSON document on stdout. |
| `--note TEXT` | Note stored in the session log. |
| `--odometer-km N` | Car mileage in km, 0..2000000. |

Recommended order for the first session: `obdb probe --dry-run`, then `obdb probe --execute`, then `obdb audit` on the session log. After every `--dry-run` and `--execute` the audit also runs automatically.

### `obdb report`

`obdb report PROBE_FILE [--reference REF.yaml] [--json]` reads a probe file offline and never opens a port. Per module it shows the identification DIDs (`F187` spare part number, `F189` software version, `F191` hardware number, `F197` system name and others) and the DTCs from `19 02` in the VAG form (e.g. `C120507`) with the status byte, the presence and the ISO 14229-1 status flags. A record is a fault only when one of the status bits 0, 1, 2, 3, 5 or 7 is set: `active` with bit 0 (`testFailed`), otherwise `stored`. Records with no fault bit (e.g. status `0x50` or `0x00`) are listed separately as `no fault` and are neither counted nor compared. The DTC count from `19 01` is shown as the module reports it and is never compared; with the mask `0xFF` sent by `obdb probe` it also covers records without a fault bit, so it can be higher than the number of DTCs from `19 02`. Control characters, Unicode format characters (e.g. `U+202E`) and line or paragraph separators in values are printed as escapes such as `\x1b` or `‮`. Repeated steps (`repeat_of`) are ignored. `--json` prints a document with schema `obdb.report/1`.

With `--reference` the values are compared with a reference file, for example one copied by hand from the OBDeleven app:

```yaml
schema: obdb.reference/1
source: "OBDeleven, 2026-11-22"
modules:
  "19":
    identification: {F187: "4X0907000", F189: "0075", F197: "J533--Gateway"}
    dtcs: ["U120A00"]
```

Addresses, DIDs and values must be quoted strings (YAML reads `0075` as a number); the same applies to hand-edited probe files (`nrc`, dates). A missing `dtcs` key means the DTCs are not compared; an empty list means no DTCs are expected. Identification values are compared after stripping leading and trailing whitespace, case-sensitive; each DID is marked `match`, `differs`, `not read` or `not in reference`, each DTC `present in both`, `new` or `gone` (an expected code read only without a fault bit stays `gone` with a note), and a module without any read in the probe file is `not probed`. Differences do not change the exit code: 0 when the report was produced, 64 for a missing file, a path that is not a regular file, invalid YAML, a wrong schema or an invalid reference.

> **Note:** the mapping of `active` and `stored` to the OBDeleven labels "static" and "sporadic" is an assumption that still has to be verified against a live read.

### Before `--execute`

- Selector lever in P, parking brake applied.
- Ignition on; engine off or started before the probe (do not start or stop the engine during the probe).
- Other diagnostic tools disconnected from the OBD socket, other programs using the port closed.
- Battery charged. The probe warns at a voltage below 12.4 V (engine off) or 13.2 V (engine running), but does not stop.

The checklist prompt is `[y/N]`; only `y` or `yes` confirms it.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Success. |
| 1 | Checklist declined. |
| 2 | Read-only policy violation (guard or audit). |
| 3 | Adapter or transport error. |
| 4 | Stop condition (car not responding, bus error, Ctrl-C). |
| 5 | Replay mismatch. |
| 64 | Usage or input file error. |

## Repository layout

```text
src/obd_bridge/
  transport/   L0: serial port, synthetic transport, replay
  stn/         L1: STN2120 driver, response parser, adapter profile
  uds/         L2 and L3: UDS connection and read-only client
  policy/      UDS guard and adapter command guard
  probe/       obdb probe: plan, execution, engine state, report
  vag/         VAG module catalog
  audit.py     obdb audit
tests/         tests and recorded adapter transcripts
```

The local directories `defs/` (VAG module catalog), `docs/` and `baselines/` are not part of the repository.

## Tests

```sh
uv run pytest -q
```

The tests require neither an adapter nor a car. They run on synthetic mock data in `tests/fixtures/mock/` (a mock module catalog and mock module and DID tables), so a clean clone runs the full suite. In addition, `tests/test_private_data.py` checks the local private files `defs/ecu-catalog.yaml`, `docs/moduly-obdeleven.md` and `docs/dids-obdeleven.md` when they are present; without them these tests are skipped with a reason.

## Data and privacy

Session logs (`data/sessions/`) and probe files (`data/probes/`) contain the VIN and control unit serial numbers. Both directories are excluded in `.gitignore`; do not publish them.
