"""Pytest bootstrap: put the repo root on ``sys.path``.

This lets the behavioural suite import the runnable ``examples`` (e.g. the
two-city admission demo) as the authoritative spec for the demo flow, without
turning ``examples/`` into an installed package.
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
