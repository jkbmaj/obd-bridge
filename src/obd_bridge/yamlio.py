"""YAML read and write in safe mode, and atomic writing of text files."""

from __future__ import annotations

import io
import os
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML

__all__ = ["dump_yaml", "load_yaml", "write_atomic"]


def _safe_yaml() -> YAML:
    """Creates a ruamel instance in safe mode (no construction of Python objects)."""
    yaml = YAML(typ="safe")
    yaml.default_flow_style = False
    yaml.allow_unicode = True
    yaml.sort_base_mapping_type_on_output = False
    return yaml


def load_yaml(path: str | os.PathLike[str]) -> Any:
    """Loads a YAML file with the safe loader.

    `!!python/*` tags and other unsafe constructs raise
    `ruamel.yaml.error.YAMLError`; the caller converts it into an error of its own domain.
    """
    with open(path, encoding="utf-8") as handle:
        return _safe_yaml().load(handle)


def dump_yaml(data: Any) -> str:
    """Serializes data to YAML text in safe mode, preserving key order."""
    buffer = io.StringIO()
    _safe_yaml().dump(data, buffer)
    return buffer.getvalue()


def write_atomic(path: str | os.PathLike[str], text: str) -> None:
    """Writes text atomically through a `.tmp` file in the same directory.

    Missing parent directories are created. An existing target file is not
    overwritten: the function raises `FileExistsError` and leaves its content unchanged.
    Order: write to `<name>.tmp`, `flush`, `os.fsync`, `os.replace`.
    """
    target = Path(path)
    if target.exists():
        raise FileExistsError(f"Target file already exists, write aborted: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(target.name + ".tmp")
    try:
        with open(tmp, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, target)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
