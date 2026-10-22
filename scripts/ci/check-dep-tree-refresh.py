#!/usr/bin/env python3
"""
check-dep-tree-refresh.py -- verify artifacts/dep-tree.json freshness.

Two rules:

  287. If backend/package-lock.json changed in this PR,
       artifacts/dep-tree.json must also change. Catches "forgot to
       regenerate."

  288. The tree's _meta.lockfile_sha must match sha256 of the current
       backend/package-lock.json. Catches "stale tree."

Rule 288 was originally "byte-identical to a fresh npm ls regeneration."
That is infeasible cross-platform: npm ls --all --json includes optional,
os-constrained deps (fsevents on macOS, @esbuild/darwin-arm64 vs
@esbuild/linux-x64, lightningcss-*, etc.) whose presence differs by
operating system. --omit=optional drops only those declared as
optionalDependencies (7 of 51 in the current tree); the rest are regular
deps with os constraints. No enumeration makes byte or semantic
comparison achievable. The lockfile_sha check is deterministic and
platform-independent, and catches the same class of error.

Regenerate the tree with:
  cd backend && python3 ../scripts/ci/regen-dep-tree.py

Usage (from backend/ cwd -- matches the workflow's working-directory):
  python3 ../scripts/ci/check-dep-tree-refresh.py [--no-git] [--base-ref=<ref>]

Exit 0 on pass, 1 on fail, 2 on usage error.

Task: TASK-P1-027b (implementation, Z-26-B)
ADR:  ADR-CI-GATE-001 section 5 (amended 2026-10-22, see Z-26-B close)
"""

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

TREE_REL_FROM_BACKEND = "../artifacts/dep-tree.json"
LOCKFILE_REL_IN_REPO = "backend/package-lock.json"
TREE_REL_IN_REPO = "artifacts/dep-tree.json"


def detect_repo_root() -> Path:
    """cwd is backend/; repo root is its parent. Anchor on docker-compose.yml."""
    cwd = Path.cwd()
    if not (cwd / "package.json").exists():
        raise RuntimeError(f"cwd {cwd} does not look like backend/ (no package.json)")
    repo_root = cwd.parent
    if not (repo_root / "docker-compose.yml").exists():
        raise RuntimeError(
            f"repo root anchor not found: {repo_root}/docker-compose.yml"
        )
    return repo_root


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

    tree_path = Path.cwd() / TREE_REL_FROM_BACKEND
    if not tree_path.exists():
        print(f"::error::committed dep-tree not found: {tree_path}", file=sys.stderr)
        return 1

    if skip_git:
        print("::notice::--no-git: skipping git diff (local smoke only)")
        lockfile_changed = False
        tree_changed = False
    else:
        try:
            changed = git_diff_names(base_ref, repo_root)
        except RuntimeError as e:
            print(f"::error::{e}", file=sys.stderr)
            return 1
        lockfile_changed = LOCKFILE_REL_IN_REPO in changed
        tree_changed = TREE_REL_IN_REPO in changed
        print(
            f"git diff {base_ref}...HEAD: {len(changed)} file(s) changed; "
            f"lockfile_changed={lockfile_changed}, tree_changed={tree_changed}"
        )

    # Rule 287
    if lockfile_changed and not tree_changed:
        print(
            f"::error::{LOCKFILE_REL_IN_REPO} changed but {TREE_REL_IN_REPO} "
            f"did not. Regenerate with: cd backend && "
            f"python3 ../scripts/ci/regen-dep-tree.py",
            file=sys.stderr,
        )
        return 1

    # Rule 288
    try:
        tree = json.loads(tree_path.read_bytes())
    except json.JSONDecodeError as e:
        print(f"::error::committed dep-tree is not valid JSON: {e}", file=sys.stderr)
        return 1
    if not isinstance(tree, dict):
        print("::error::committed dep-tree is not a JSON object", file=sys.stderr)
        return 1

    meta = tree.get("_meta")
    if not isinstance(meta, dict):
        print(
            "::error::committed dep-tree has no _meta block. "
            "Regenerate with: cd backend && python3 ../scripts/ci/regen-dep-tree.py",
            file=sys.stderr,
        )
        return 1

    expected_sha = meta.get("lockfile_sha")
    if not isinstance(expected_sha, str) or len(expected_sha) != 64:
        print(
            f"::error::committed dep-tree _meta.lockfile_sha is missing or "
            f"malformed (expected 64-char hex, got {expected_sha!r})",
            file=sys.stderr,
        )
        return 1

    lockfile_path = repo_root / "backend" / "package-lock.json"
    if not lockfile_path.exists():
        print(f"::error::lockfile not found: {lockfile_path}", file=sys.stderr)
        return 1
    actual_sha = hashlib.sha256(lockfile_path.read_bytes()).hexdigest()

    if expected_sha != actual_sha:
        print(
            f"::error::dep-tree is stale: _meta.lockfile_sha={expected_sha[:16]}... "
            f"but current package-lock.json hash={actual_sha[:16]}... "
            f"Regenerate with: cd backend && python3 ../scripts/ci/regen-dep-tree.py",
            file=sys.stderr,
        )
        return 1

    print("PASS: dep-tree _meta.lockfile_sha matches current lockfile")
    if tree_changed and not lockfile_changed and not skip_git:
        print(
            "::warning::tree changed but lockfile did not -- spurious "
            "refresh, review if intentional",
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
