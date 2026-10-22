#!/usr/bin/env python3
"""
regen-dep-tree.py -- regenerate artifacts/dep-tree.json with _meta block.

Runs `npm ls --all --json --omit=optional` from backend/ cwd, adds a
_meta block carrying the current package-lock.json sha256, and writes
the result to artifacts/dep-tree.json.

The _meta.lockfile_sha is what check-dep-tree-refresh.py verifies.
Comparing this hash against the current lockfile is deterministic
across platforms -- byte or semantic comparison of npm ls output is
not, because optional os-constrained deps (fsevents on macOS, per-
platform esbuild binaries) legitimately differ.

--omit=optional excludes optionalDependencies (a subset of platform-
varying deps). It reduces tree noise; it does not affect the freshness
check, which operates on the lockfile hash alone. SBOM (via
check-prohibited.py) remains the §11 authority and includes optional
deps for absolute enforcement.

Usage (from backend/ cwd):
  python3 ../scripts/ci/regen-dep-tree.py

Task: TASK-P1-027b (implementation, Z-26-B)
ADR:  ADR-CI-GATE-001 section 5 (amended 2026-10-22, see Z-26-B close)
"""

import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def main() -> int:
    backend = Path.cwd()
    if not (backend / "package.json").exists():
        print(f"ERROR: cwd {backend} does not look like backend/ (no package.json)",
              file=sys.stderr)
        return 2

    repo_root = backend.parent
    lockfile = backend / "package-lock.json"
    tree_path = repo_root / "artifacts" / "dep-tree.json"

    if not lockfile.exists():
        print(f"ERROR: lockfile not found: {lockfile}", file=sys.stderr)
        return 1

    result = subprocess.run(
        ["npm", "ls", "--all", "--json", "--omit=optional"],
        capture_output=True,
    )
    if result.returncode != 0:
        print(f"ERROR: npm ls exited {result.returncode}", file=sys.stderr)
        print(result.stderr.decode("utf-8", errors="replace"), file=sys.stderr)
        return 1

    try:
        tree = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        print(f"ERROR: npm ls output is not valid JSON: {e}", file=sys.stderr)
        return 1
    if not isinstance(tree, dict):
        print("ERROR: npm ls output is not a JSON object", file=sys.stderr)
        return 1

    lockfile_sha = hashlib.sha256(lockfile.read_bytes()).hexdigest()
    generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

    tree["_meta"] = {
        "lockfile_sha": lockfile_sha,
        "lockfile_path": "backend/package-lock.json",
        "schema": "umoja-dep-tree.v1",
        "generated_at_utc": generated_at,
        "generated_by": "scripts/ci/regen-dep-tree.py",
    }

    tree_path.parent.mkdir(parents=True, exist_ok=True)
    tree_path.write_text(json.dumps(tree, indent=2) + "\n")
    print(f"WROTE {tree_path}")
    print(f"  lockfile_sha: {lockfile_sha}")
    print(f"  generated_at_utc: {generated_at}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
