"""Smoke test — replace with the behavioural suite that IS the spec.

The family's rule (GOVERNANCE.md): the test suite is the authoritative
behavioural specification. Every guarantee in README "What this secures" needs
a test here; every adversarial claim needs a hostile-path test.
"""

from __future__ import annotations

import sm_parc


def test_package_imports_and_has_version() -> None:
    assert sm_parc.__version__
