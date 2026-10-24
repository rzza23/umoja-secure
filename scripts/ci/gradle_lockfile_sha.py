#!/usr/bin/env python3
"""
gradle_lockfile_sha.py -- combined sha256 over the Android gradle
input files whose change must force a dep-tree regen.

Used by:
  regen-dep-tree-android.py         (writes _meta.lockfile_sha)
  check-dep-tree-refresh-android.py (verifies _meta.lockfile_sha)

Extracted 2026-10-24 (Session Z-28) so the producer and consumer of
_meta.lockfile_sha share one definition. Two independent copies would
diverge silently -- the failure mode is Rule 288 firing permanently
on every tree the regen produces, which is the opposite of the
invariant Rule 288 exists to enforce. Same extraction discipline as
prohibited_common.py (this session) and the crypto helpers (Sessions
U-1 and Z-27): one definition, two consumers.

Why three files in the combined hash. Gradle has no single lockfile --
the project does not use dependencyLocking. Versions come from three
sources:

  - android/gradle/libs.versions.toml
    The version catalog. Every version.ref resolves here.

  - android/app/build.gradle.kts
    Hardcoded coordinates for deps not yet in the catalog:
    okhttp 4.12.0, material-icons-extended 1.7.0,
    journeyapps:zxing-android-embedded 4.3.0,
    bcprov-jdk18on 1.79, desugar_jdk_libs 2.1.5,
    org.json 20240303 (test-scope).

  - android/settings.gradle.kts
    Repository declarations. A new repo added here can change
    resolution outcomes without touching any version.

A change to any of the three can change the resolved tree. All three
are hashed, separator-delimited, in the fixed order listed above.
The order matters: the check script must compute the same sha as the
regen script, or Rule 288 mis-compares.

Task: TASK-P1-027b (Z-28 implementation)
ADR:  ADR-CI-GATE-001 §4 (staged rollout, Android half)
"""

import hashlib
from pathlib import Path

GRADLE_LOCKFILE_FILES = [
    "android/gradle/libs.versions.toml",
    "android/app/build.gradle.kts",
    "android/settings.gradle.kts",
]

SEPARATOR = b"\n---\n"


def compute_lockfile_sha(repo_root: Path) -> tuple:
    """Return (hex_digest, file_list) for the combined gradle input sha.

    Hashes the three files listed in GRADLE_LOCKFILE_FILES in order,
    joined by SEPARATOR. Raises RuntimeError if any file is missing --
    a missing gradle input is a configuration error, not a "tree is
    fresh" condition, so both callers must fail closed.

    repo_root must be the repo root (the parent of android/), not the
    android/ directory itself. Both callers detect repo_root from
    their cwd before calling.
    """
    h = hashlib.sha256()
    for i, rel in enumerate(GRADLE_LOCKFILE_FILES):
        path = repo_root / rel
        if not path.exists():
            raise RuntimeError(f"gradle input not found: {path}")
        if i > 0:
            h.update(SEPARATOR)
        h.update(path.read_bytes())
    return h.hexdigest(), list(GRADLE_LOCKFILE_FILES)