#!/usr/bin/env python3
"""
regen-dep-tree-android.py -- regenerate artifacts/dep-tree-android.json.

Runs `./gradlew :app:dependencies --configuration clientReleaseRuntimeClasspath`
from android/ cwd, parses the flat group:artifact:version triples out of
the tree-format output, and writes artifacts/dep-tree-android.json with
a _meta block carrying the combined gradle-input sha256 (see
gradle_lockfile_sha.py for the file set and rationale).

Why clientReleaseRuntimeClasspath (not releaseRuntimeClasspath): the
client/signing flavor split landed at Session Z-17. There is no
flavor-agnostic runtime classpath. The client flavor is what reaches a
user device, so that is the surface §11 cares about. The signing flavor
ships only to ceremony devices (air-gapped, no network, no user data),
so its dependency surface is not part of the user-device threat model.

Known limitation: gradle/wrapper/gradle-wrapper.properties is NOT in
the hash. A Gradle version bump can change resolution behavior without
touching any gradle file, so a tree regenerated after a wrapper bump
would look fresh but potentially differ. The backend has the same gap
for Node version (engines in package.json, not in the lockfile sha).
Recorded honestly, not fixed -- a future task if the gap proves
load-bearing.

Gradle output format (--console=plain):
  clientReleaseRuntimeClasspath - Runtime classpath of compilation ...
  +--- group:artifact:version
  |    +--- group:artifact:requested -> resolved
  |    \--- group:artifact:version (*)
  \--- ...

Parse rules:
  - Lines with no 'group:artifact:version' triple are skipped
    (project deps, section separators, legend lines).
  - '(*)', '(n)', '(c)' suffix markers mean "repeated / not-latest /
    constraint, not a real dep" -- skipped. The selected version of
    such a module appears elsewhere in the tree without a marker and
    is captured there.
  - ' -> resolved' takes the post-arrow version (the resolved one is
    what ships).
  - Deduplicated by (group, artifact, resolved), sorted for stable
    diffs.
  - Stop only on BUILD SUCCESSFUL / BUILD FAILED. The first-draft
    parser broke on the first non-matching line and captured 27 of
    118 deps; the fix is continue-not-break, with end-of-tree detection
    by build-status lines (see ADR-CI-GATE-001 §4 amendment).

Usage (from android/ cwd):
  python3 ../scripts/ci/regen-dep-tree-android.py

Task: TASK-P1-027b (Z-28 implementation)
ADR:  ADR-CI-GATE-001 §4 (staged rollout, Android half)
"""

import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gradle_lockfile_sha import compute_lockfile_sha

CONFIGURATION = "clientReleaseRuntimeClasspath"

TREE_LINE_RE = re.compile(
    r"^[\s|+\\\-]*"
    r"([\w.\-]+):([\w.\-]+):([\w.\-]+)"
    r"(?:\s+->\s+([\w.\-]+))?"
    r"(\s+\((?:n|\*|c)\))?\s*$"
)


def parse_gradle_output(stdout: str) -> list:
    lines = stdout.splitlines()
    start = None
    for i, line in enumerate(lines):
        if line.startswith(CONFIGURATION + " - ") or line.startswith(CONFIGURATION + " (n)"):
            start = i
            break
    if start is None:
        raise RuntimeError(
            f"could not find section header for configuration {CONFIGURATION} "
            f"in gradle output; expected a line starting with "
            f"'{CONFIGURATION} - '; run with --console=plain"
        )

    i = start + 1
    while i < len(lines) and not lines[i].strip():
        i += 1

    deps = []
    seen = set()
    for line in lines[i:]:
        if line.startswith("BUILD SUCCESSFUL") or line.startswith("BUILD FAILED"):
            break
        m = TREE_LINE_RE.match(line)
        if not m:
            continue
        if m.group(5) is not None:
            continue
        group, artifact, requested = m.group(1), m.group(2), m.group(3)
        resolved = m.group(4) or requested
        key = (group, artifact, resolved)
        if key in seen:
            continue
        seen.add(key)
        deps.append({"group": group, "artifact": artifact, "version": resolved})

    if not deps:
        raise RuntimeError(
            f"parsed zero dependencies from {CONFIGURATION}; gradle "
            f"output format may have changed or the configuration name "
            f"is wrong for this AGP version"
        )

    deps.sort(key=lambda d: (d["group"], d["artifact"], d["version"]))
    return deps


def main() -> int:
    android = Path.cwd()
    if not (android / "app/build.gradle.kts").exists():
        print(f"ERROR: cwd {android} does not look like android/ "
              f"(no app/build.gradle.kts)", file=sys.stderr)
        return 2

    repo_root = android.parent
    tree_path = repo_root / "artifacts" / "dep-tree-android.json"

    try:
        lockfile_sha, lockfile_files = compute_lockfile_sha(repo_root)
    except RuntimeError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    print(f"Running: ./gradlew :app:dependencies "
          f"--configuration {CONFIGURATION} --console=plain")
    result = subprocess.run(
        ["./gradlew", ":app:dependencies",
         "--configuration", CONFIGURATION,
         "--console=plain"],
        capture_output=True,
    )
    if result.returncode != 0:
        print(f"ERROR: gradle exited {result.returncode}", file=sys.stderr)
        sys.stderr.buffer.write(result.stderr)
        return 1

    stdout = result.stdout.decode("utf-8", errors="replace")
    try:
        deps = parse_gradle_output(stdout)
    except RuntimeError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        print("--- first 40 lines of gradle stdout ---", file=sys.stderr)
        for line in stdout.splitlines()[:40]:
            print(f"  {line}", file=sys.stderr)
        return 1

    generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    tree = {
        "_meta": {
            "lockfile_sha": lockfile_sha,
            "lockfile_files": lockfile_files,
            "schema": "umoja-dep-tree-android.v1",
            "configuration": CONFIGURATION,
            "generated_at_utc": generated_at,
            "generated_by": "scripts/ci/regen-dep-tree-android.py",
        },
        "dependencies": deps,
    }

    tree_path.parent.mkdir(parents=True, exist_ok=True)
    tree_path.write_text(json.dumps(tree, indent=2) + "\n")
    print(f"WROTE {tree_path}")
    print(f"  dependencies: {len(deps)}")
    print(f"  lockfile_sha: {lockfile_sha}")
    print(f"  lockfile_files: {', '.join(lockfile_files)}")
    print(f"  generated_at_utc: {generated_at}")
    return 0


if __name__ == "__main__":
    sys.exit(main())