"""Shim: real implementation lives under leaf5/stages/ (pipeline layout)."""
from pathlib import Path
import runpy

_TARGET = Path(__file__).resolve().parents[1] / "stages/S01-offsets-stack/scripts/compute_pselect_shift.py"

if __name__ == "__main__":
    runpy.run_path(str(_TARGET), run_name="__main__")
else:
    # allow `from scripts.X import main`
    _g = runpy.run_path(str(_TARGET))
    globals().update({k: v for k, v in _g.items() if not k.startswith("__")})
