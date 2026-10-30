import importlib
import pathlib

from ..registry import MODULES  # noqa: F401

for f in sorted(pathlib.Path(__file__).parent.glob("*.py")):
    if f.stem not in ("__init__", "base"):
        importlib.import_module(f"{__name__}.{f.stem}")
