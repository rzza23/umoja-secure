#!/usr/bin/env python3
"""
prohibited_common.py -- shared §11 prohibited-package matcher and
carve-out parser, used by both the backend (CycloneDX SBOM) and
Android (Gradle dep-tree) gate scripts.

Extracted 2026-10-24 (Session Z-28) from check-prohibited.py, which
had PROHIBITED, CAREOUT_RE, and load_carveouts as file-private.
The Android check needs the same three; duplicating them would be
the exact drift hazard removed from crypto helpers at Session U-1
and from IdentityChangeAck at Session Z-27. One definition, two
consumers.

NOT extracted: component_full_name() and is_runtime_component().
Both are SBOM-specific (CycloneDX `properties` convention for dev
markers; group/name construction for npm-scoped vs Maven-style).
The Android script builds f"{group}:{artifact}" directly from
Gradle's output and does not need the SBOM helpers.

Callers:
  check-prohibited.py         (backend, CycloneDX SBOM input)
  check-prohibited-android.py (Android, Gradle dep-tree input)

Task: TASK-P1-027b (Z-28 implementation)
ADR:  ADR-CI-GATE-001 §5 and §8 (amended to v0.2 by this session)
"""

import re
import sys
from pathlib import Path

PROHIBITED = [
    ("@google/*",           lambda n: n.startswith("@google/")),
    ("com.google.*",        lambda n: n.startswith("com.google.")),
    ("googleapis",          lambda n: n == "googleapis"),
    ("gaxios",              lambda n: n == "gaxios"),
    ("google-auth-library", lambda n: n == "google-auth-library"),
    ("firebase*",           lambda n: n == "firebase" or n.startswith("firebase-")),
    ("tink",                lambda n: n == "tink"),
]

CARVEOUT_RE = re.compile(r"^###\s+`([^`]+)`\s+@\s+(\S+)\s*$")


def load_carveouts(path: Path) -> set:
    """Parse DEPENDENCY-EXCEPTIONS.md §2 for exact-version carve-outs.

    Returns a set of strings "artifact@version". Only §2 entries count
    here; §1 CVE exceptions are a different mechanism, handled by
    check-cve-exceptions.py.

    Fail-closed on missing file: an unreadable exception file is not
    the same as "no active exceptions" (ADR-CI-GATE-001 §8).
    """
    if not path.exists():
        print(f"::error::carve-out file not found: {path}", file=sys.stderr)
        sys.exit(1)
    carveouts = set()
    in_section_2 = False
    for line in path.read_text().splitlines():
        stripped = line.strip()
        if stripped.startswith("## 2."):
            in_section_2 = True
            continue
        if in_section_2 and stripped.startswith("## "):
            in_section_2 = False
            continue
        if not in_section_2:
            continue
        m = CARVEOUT_RE.match(stripped)
        if m:
            artifact, version = m.group(1), m.group(2)
            carveouts.add(f"{artifact}@{version}")
    return carveouts