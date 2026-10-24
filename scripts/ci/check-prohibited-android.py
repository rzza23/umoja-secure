#!/usr/bin/env python3
"""
check-prohibited-android.py -- fail-closed §11 check on the Android
runtime dependency tree.

Reads artifacts/dep-tree-android.json (produced by regen-dep-tree-
android.py from `:app:dependencies --configuration clientRelease-
RuntimeClasspath`), matches every group:artifact against §11's
prohibited list, and fails if any prohibited package lacks an
exact-version carve-out entry in DEPENDENCY-EXCEPTIONS.md §2.

Usage (from repo root -- matches the workflow step's cwd):
  python3 scripts/ci/check-prohibited-android.py \\
      artifacts/dep-tree-android.json \\
      [docs/security/DEPENDENCY-EXCEPTIONS.md]

Exit 0 on pass, 1 on fail, 2 on usage error. Emits ::error:: /
::notice:: workflow annotations so a failing CI run names the
offending component.

ADR-CI-GATE-001 §7 (test matrix): TEST-ANDROID-DEP-PARSE -- add a
com.google.* dep to the runtime classpath; gate fails at this
parse. Remove; gate goes green. Both directions exercised (batch F
of the Z-28 session).

Task: TASK-P1-027b (Z-28 implementation)
ADR:  ADR-CI-GATE-001 §4 (staged rollout, Android half) and §7
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from prohibited_common import PROHIBITED, load_carveouts


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: check-prohibited-android.py <dep-tree.json> "
              "[exceptions.md]", file=sys.stderr)
        return 2
    tree_path = Path(sys.argv[1])
    exceptions_path = Path(
        sys.argv[2] if len(sys.argv) >= 3
        else "docs/security/DEPENDENCY-EXCEPTIONS.md"
    )

    if not tree_path.exists():
        print(f"::error::dep-tree not found: {tree_path}", file=sys.stderr)
        return 1

    try:
        tree = json.loads(tree_path.read_text())
    except json.JSONDecodeError as e:
        print(f"::error::dep-tree is not valid JSON: {e}", file=sys.stderr)
        return 1

    if not isinstance(tree, dict):
        print("::error::dep-tree is not a JSON object", file=sys.stderr)
        return 1

    deps = tree.get("dependencies")
    if not isinstance(deps, list):
        print("::error::dep-tree is missing a 'dependencies' list -- "
              "regenerate with scripts/ci/regen-dep-tree-android.py",
              file=sys.stderr)
        return 1

    # Fail-closed on zero deps. An empty tree is not a passing gate --
    # it means the regen captured nothing, or the format changed under
    # the parser. Same discipline as check-prohibited.py's zero-
    # runtime-components check (Z-26 discovery #1: cyclonedx-npm
    # changed its scope marking; fail-closed caught it).
    if not deps:
        print("::error::dep-tree has zero dependencies -- check "
              "regen-dep-tree-android.py output (expected: 80+ deps "
              "for a Compose + libsignal + zxing runtime classpath) -- "
              "FAIL", file=sys.stderr)
        return 1

    meta = tree.get("_meta", {})
    if not isinstance(meta, dict):
        print("::error::dep-tree _meta is not an object -- regenerate",
              file=sys.stderr)
        return 1
    configuration = meta.get("configuration") or "<unspecified>"

    carveouts = load_carveouts(exceptions_path)

    print(f"Dep-tree: {len(deps)} dependencies in {configuration}, "
          f"{len(carveouts)} §2 carve-out(s) parsed")

    violations = []
    notices = []
    for dep in deps:
        if not isinstance(dep, dict):
            continue
        group = (dep.get("group") or "").strip()
        artifact = (dep.get("artifact") or "").strip()
        version = (dep.get("version") or "").strip() or "<unversioned>"
        if not group or not artifact:
            continue
        full = f"{group}:{artifact}"
        for label, matcher in PROHIBITED:
            if matcher(full):
                key = f"{full}@{version}"
                if key in carveouts:
                    notices.append((full, version, label))
                else:
                    violations.append((full, version, label))
                break

    for full, version, label in notices:
        print(f"::notice::{full}@{version} matches §11 '{label}' "
              f"but has carve-out entry -- allowed")

    if violations:
        print("", file=sys.stderr)
        for full, version, label in violations:
            print(f"::error::{full}@{version} matches §11 prohibited "
                  f"'{label}' and has no carve-out entry in "
                  f"DEPENDENCY-EXCEPTIONS.md §2", file=sys.stderr)
        print(f"\n{len(violations)} prohibited package(s) without "
              f"carve-out -- FAIL", file=sys.stderr)
        return 1

    print(f"No prohibited runtime packages (checked {len(deps)} "
          f"dependencies against §11 list) -- PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())