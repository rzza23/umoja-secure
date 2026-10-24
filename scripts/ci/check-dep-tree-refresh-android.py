#!/usr/bin/env python3
"""
check-dep-tree-refresh-android.py -- verify artifacts/dep-tree-android.json
freshness against the three gradle input files.

Two rules:

  287. If any of the three gradle input files changed in this PR,
       artifacts/dep-tree-android.json must also change. Catches
       "forgot to regenerate."

  288. The tree's _meta.lockfile_sha must match the combined sha256
       of the current gradle inputs (see gradle_lockfile_sha.py for
       the file set and rationale).

The backend analog (check-dep-tree-refresh.py) uses one lockfile; the
Android analog uses three gradle files because Gradle has no single
lockfile in this project (no dependencyLocking). Both scripts share
the same two rules.

Regenerate the tree with:
  cd android && python3 ../scripts/ci/regen-dep-tree-android.py

Usage (from repo root -- matches the workflow step's cwd):
  python3 scripts/ci/check-dep-tree-refresh-android.py \\
      [--no-git] [--base-ref=<ref>]

Exit 0 on pass, 1 on fail, 2 on usage error.

Task: TASK-P1-027b (Z-28 implementation)
ADR:  ADR-CI-GATE-001 §4 (staged rollout, Android half)
"""

import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gradle_lockfile_sha import GRADLE_LOCKFILE_FILES, compute_lockfile_sha

TREE_REL_IN_REPO = "artifacts/dep-tree-android.json"


def detect_repo_root() -> Path:
    """cwd is repo root; anchor on docker-compose.yml."""
    cwd = Path.cwd()
    if not (cwd / "docker-compose.yml").exists():
        raise RuntimeError(
            f"cwd {cwd} does not look like repo root (no docker-compose.yml)"
        )
    return cwd


def git_diff_names(base_ref: str, repo_root: Path) -> set:
    """git diff --name-only base...HEAD; triple-dot is merge-base diff."""
    result = subprocess.run(
        ["git", "diff", "--name-only", f"{base_ref}...HEAD"],
        cwd=repo_root, capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"git diff --name-only {base_ref}...HEAD failed: "
            f"{result.stderr.strip() or '(no stderr)'}"
        )
    return {line.strip() for line in result.stdout.splitlines() if line.strip()}


def main() -> int:
    skip_git = "--no-git" in sys.argv
    base_ref = None
    for arg in sys.argv[1:]:
        if arg.startswith("--base-ref="):
            base_ref = arg.split("=", 1)[1]

    if base_ref is None:
        github_base = os.environ.get("GITHUB_BASE_REF")
        base_ref = f"origin/{github_base}" if github_base else "origin/main"

    try:
        repo_root = detect_repo_root()
    except RuntimeError as e:
        print(f"::error::{e}", file=sys.stderr)
        return 1

    tree_path = repo_root / TREE_REL_IN_REPO
    if not tree_path.exists():
        print(f"::error::committed dep-tree not found: {tree_path}",
              file=sys.stderr)
        return 1

    if skip_git:
        print("::notice::--no-git: skipping git diff (local smoke only)")
        gradle_inputs_changed = False
        tree_changed = False
    else:
        try:
            changed = git_diff_names(base_ref, repo_root)
        except RuntimeError as e:
            print(f"::error::{e}", file=sys.stderr)
            return 1
        gradle_inputs_changed = any(
            f in changed for f in GRADLE_LOCKFILE_FILES
        )
        tree_changed = TREE_REL_IN_REPO in changed
        print(
            f"git diff {base_ref}...HEAD: {len(changed)} file(s) changed; "
            f"gradle_inputs_changed={gradle_inputs_changed}, "
            f"tree_changed={tree_changed}"
        )

    # Rule 287
    if gradle_inputs_changed and not tree_changed:
        changed_inputs = [f for f in GRADLE_LOCKFILE_FILES if f in changed]
        print(
            f"::error::gradle input(s) changed {changed_inputs} but "
            f"{TREE_REL_IN_REPO} did not. Regenerate with: "
            f"cd android && python3 ../scripts/ci/regen-dep-tree-android.py",
            file=sys.stderr,
        )
        return 1

    # Rule 288
    try:
        tree = json.loads(tree_path.read_bytes())
    except json.JSONDecodeError as e:
        print(f"::error::committed dep-tree is not valid JSON: {e}",
              file=sys.stderr)
        return 1
    if not isinstance(tree, dict):
        print("::error::committed dep-tree is not a JSON object",
              file=sys.stderr)
        return 1

    meta = tree.get("_meta")
    if not isinstance(meta, dict):
        print(
            "::error::committed dep-tree has no _meta block. "
            "Regenerate with: cd android && "
            "python3 ../scripts/ci/regen-dep-tree-android.py",
            file=sys.stderr,
        )
        return 1

    expected_sha = meta.get("lockfile_sha")
    if not isinstance(expected_sha, str) or len(expected_sha) != 64:
        print(
            f"::error::committed dep-tree _meta.lockfile_sha is missing "
            f"or malformed (expected 64-char hex, got {expected_sha!r})",
            file=sys.stderr,
        )
        return 1

    try:
        actual_sha, _ = compute_lockfile_sha(repo_root)
    except RuntimeError as e:
        print(f"::error::{e}", file=sys.stderr)
        return 1

    if expected_sha != actual_sha:
        print(
            f"::error::dep-tree is stale: _meta.lockfile_sha="
            f"{expected_sha[:16]}... but current gradle inputs hash="
            f"{actual_sha[:16]}... Regenerate with: cd android && "
            f"python3 ../scripts/ci/regen-dep-tree-android.py",
            file=sys.stderr,
        )
        return 1

    print("PASS: dep-tree _meta.lockfile_sha matches current gradle inputs")
    if tree_changed and not gradle_inputs_changed and not skip_git:
        print(
            "::warning::tree changed but no gradle input changed -- "
            "review if intentional (expected on the initial commit of "
            "this tree)",
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())