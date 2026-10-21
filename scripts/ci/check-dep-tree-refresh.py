#!/usr/bin/env python3
"""
check-dep-tree-refresh.py -- fail-closed dep-tree refresh discipline check.

Verifies that artifacts/dep-tree.json is consistent with
backend/package-lock.json: if the lockfile changed in the PR, the tree
must have been regenerated; and the committed tree must be byte-
identical to a fresh `npm ls --all --json` output.

Usage (from backend/ cwd -- matches the workflow's working-directory):
  python3 ../scripts/ci/check-dep-tree-refresh.py [--no-git] [--base-ref=<ref>]

Exit 0 on pass, 1 on fail, 2 on usage error. Emits ::error:: workflow
annotations on failure with a first-differing-line excerpt for triage.

Implements ADR-CI-GATE-001 §5 lines 284-289:

  1. git diff --name-only <base>...HEAD.
  2. If package-lock.json changed but dep-tree.json did not → fail
     (rule 287: refresh discipline violated).
  3. Regenerate with `npm ls --all --json`; if byte-identical to
     committed → pass; if not byte-identical AND lockfile did not
     change → fail (rule 288: spurious refresh or unpinned state).
  4. Print a first-differing-line excerpt on failure.

ADR AMBIGUITY, RESOLVED FAIL-CLOSED:
  The ADR does not explicitly state the outcome for "lockfile changed
  AND tree changed AND not byte-identical to regenerated". Three
  interpretations exist: (a) pass because the developer touched the
  tree; (b) fail because the tree is stale; (c) fail because the diff
  is unverifiable. This implementation takes (b): if the committed
  tree differs from what the current lockfile would produce, it is
  stale or partially refreshed. Fail-closed. Flagged for Z-26-B's
  close commit — ADR §5 line 287-288 may need softening if real-world
  PRs hit this case legitimately.

BASE REF RESOLUTION:
  --base-ref=<ref>  explicit override (highest precedence)
  GITHUB_BASE_REF   CI env var (GitHub Actions sets this on
                    pull_request runs); prefixed with origin/
  fallback          origin/main

LOCAL MODE --no-git:
  Skips git diff (and both rule-287 and rule-288's lockfile branches),
  runs only the byte comparison. For local smoke testing without
  requiring throwaway git state. NOT used in CI. Does NOT weaken the
  byte comparison check.

FAIL-CLOSED ON META-FAILURES: missing tree file, missing
docker-compose.yml anchor (cwd not backend/), invalid JSON in
regenerated output, npm ls exit != 0, git diff failure (base ref
missing, etc.) -- all exit 1. Zero-diff PRs (HEAD == base) pass the
git diff but still run byte comparison: a tree that mismatches with
no changes is drift-not-tracked, fail-closed.

Task: TASK-P1-027b (implementation, Z-26-A block 3c)
ADR:  ADR-CI-GATE-001 §5
"""

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
    """Run git diff --name-only base...HEAD, return set of paths.

    Triple-dot = merge-base diff (shows PR's changes only, not drift on
    base since the branch point). Fails closed on git error (missing
    remote ref, no history, non-git cwd).
    """
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


def regenerate_tree() -> bytes:
    """Run npm ls --all --json, return stdout bytes.

    Fails closed on non-zero exit. `npm ci` runs before this in CI, so
    the environment is clean and exit should be 0. Exit != 0 in CI
    means the lockfile/node_modules pair is inconsistent, which is
    itself a defect the byte comparison might miss if the committed
    tree was regenerated from the same broken state.
    """
    result = subprocess.run(
        ["npm", "ls", "--all", "--json"],
        capture_output=True,
    )
    if result.returncode != 0:
        stderr_excerpt = result.stderr.decode("utf-8", errors="replace").strip()[:500]
        raise RuntimeError(
            f"npm ls --all --json exited {result.returncode}: {stderr_excerpt}"
        )
    return result.stdout


def emit_diff(committed: bytes, regenerated: bytes) -> None:
    """Print first-differing-line context to stderr (first 100 chars each)."""
    a = committed.decode("utf-8", errors="replace").splitlines()
    b = regenerated.decode("utf-8", errors="replace").splitlines()
    for i, (la, lb) in enumerate(zip(a, b)):
        if la != lb:
            print(f"  first diff at line {i+1}:", file=sys.stderr)
            print(f"    committed:   {la[:100]}", file=sys.stderr)
            print(f"    regenerated: {lb[:100]}", file=sys.stderr)
            return
    # One is a prefix of the other
    shorter = min(len(a), len(b))
    longer_label = "committed" if len(a) > len(b) else "regenerated"
    longer_lines = a if len(a) > len(b) else b
    extra = longer_lines[shorter][:100] if shorter < len(longer_lines) else ""
    print(
        f"  line count differs: committed={len(a)} regenerated={len(b)}; "
        f"{longer_label} extra line at {shorter+1}: {extra!r}",
        file=sys.stderr,
    )


def main() -> int:
    # Parse CLI
    skip_git = "--no-git" in sys.argv
    base_ref = None
    for arg in sys.argv[1:]:
        if arg.startswith("--base-ref="):
            base_ref = arg.split("=", 1)[1]

    if base_ref is None:
        github_base = os.environ.get("GITHUB_BASE_REF")
        base_ref = f"origin/{github_base}" if github_base else "origin/main"

    # Resolve paths
    try:
        repo_root = detect_repo_root()
    except RuntimeError as e:
        print(f"::error::{e}", file=sys.stderr)
        return 1

    tree_path = Path.cwd() / TREE_REL_FROM_BACKEND
    if not tree_path.exists():
        print(f"::error::committed dep-tree not found: {tree_path}",
              file=sys.stderr)
        return 1

    # Determine changed files
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

    # Regenerate
    try:
        regenerated = regenerate_tree()
    except RuntimeError as e:
        print(f"::error::{e}", file=sys.stderr)
        return 1

    # Reject empty regen as fail-closed (npm ls always emits at least "{}")
    try:
        parsed = json.loads(regenerated)
    except json.JSONDecodeError as e:
        print(f"::error::npm ls output is not valid JSON: {e}", file=sys.stderr)
        return 1
    if not isinstance(parsed, dict):
        print("::error::npm ls output is not a JSON object", file=sys.stderr)
        return 1

    committed = tree_path.read_bytes()
    byte_identical = (regenerated == committed)

    print(
        f"committed: {len(committed)} bytes; "
        f"regenerated: {len(regenerated)} bytes; "
        f"byte_identical={byte_identical}"
    )

    # Rule 287: lockfile changed but tree didn't → fail
    if lockfile_changed and not tree_changed:
        print(
            f"::error::{LOCKFILE_REL_IN_REPO} changed but "
            f"{TREE_REL_IN_REPO} did not. Regenerate with: "
            f"cd backend && npm ls --all --json > ../artifacts/dep-tree.json",
            file=sys.stderr,
        )
        return 1

    # Byte comparison
    if byte_identical:
        print("PASS: committed tree is byte-identical to regenerated")
        return 0

    # Not byte-identical: fail-closed in all remaining cases
    if skip_git:
        reason = "--no-git: committed tree differs from regenerated"
    elif lockfile_changed:
        reason = (
            "lockfile changed, tree changed, but regenerated tree differs — "
            "tree is stale or partially refreshed (fail-closed per ADR §5 "
            "line 287-288 ambiguity)"
        )
    elif tree_changed:
        reason = (
            "tree changed but lockfile did not — spurious refresh or "
            "unpinned state"
        )
    else:
        reason = (
            "tree differs from regenerated with no lockfile or tree changes "
            "in the PR — drift not tracked"
        )

    print(f"::error::{reason}", file=sys.stderr)
    emit_diff(committed, regenerated)
    return 1


if __name__ == "__main__":
    sys.exit(main())