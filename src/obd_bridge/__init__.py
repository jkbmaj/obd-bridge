"""obd-bridge: read-only OBD/UDS diagnostic bridge for the STN2120 adapter."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__: str = version("obd-bridge")
except PackageNotFoundError:
    __version__ = "0+unknown"

__all__ = ["__version__"]
