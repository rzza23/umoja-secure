#!/usr/bin/env python3
"""
check-prohibited.py -- fail-closed check for Build Master §11 packages.

Reads a CycloneDX SBOM (JSON), filters to runtime-scope components,
matches each against §11's prohibited list, and fails if any prohibited
package lacks an exact-version carve-out entry in DEPENDENCY-EXCEPTIONS.md §2.

Usage (from backend/ cwd -- matches the workflow's working-directory):
  python3 ../scripts/ci/check-prohibited.py sbom.json \\
      [../docs/security/DEPENDENCY-EXCEPTIONS.md]

Exit 0 on pass, 1 on fail, 2 on usage error. Emits ::error:: workflow
annotations so a failing CI run names the offending component.

Implements ADR-CI-GATE-001 §5 lines 265-272:

  1. Filter to runtime components. cyclonedx-npm@6.0.1 does not use
     the `scope: "required"` convention: runtime deps are implicit (no
     marker), dev deps carry `cdx:npm:package:development: true` in
     their `properties`, optional deps carry `scope: "optional"`. For
     §11 (absolute), optional deps ARE included -- any dep that could
     be installed in any environment is a risk. Only dev-marked
     components are excluded.
  2. Match group+name against §11 list (structural, not grep).
  3. On match, look up DEPENDENCY-EXCEPTIONS.md §2 for exact
     `<artifact>@<version>`.
  4. No carve-out → exit 1, name the offending component.
  5. Structural parse, not grep -- build identifiers from JSON fields,
     never substring-match the SBOM file content.

Carve-outs are exact-version: a carve-out for @3.4.1 does not allow
@3.5.0. A version bump forces a new §2 review -- correct fail-closed
behavior.

Fail-closed on meta-failures: missing SBOM, invalid JSON, missing
exceptions file, or ZERO runtime-scope components all exit 1. A gate
that cannot run is not a gate that passed. The zero-runtime case is
deliberately fail-closed -- if cyclonedx-npm's scope marking changes,
the gate fails loudly rather than passing vacuously.

PROHIBITED patterns and load_carveouts live in prohibited_common.py,
shared with check-prohibited-android.py (Session Z-28). The SBOM-
specific helpers (component_full_name, is_runtime_component) stay
here because the Android Gradle tree has a different shape.

Task: TASK-P1-027b (implementation, Z-26-A block 3a; refactored Z-28)
ADR:  ADR-CI-GATE-001 §5
"""

import json
import sys
from pathlib import Path

# Ensure the sibling shared module is importable regardless of the
# invocation cwd. When invoked as `python3 ../scripts/ci/check-
# prohibited.py` from backend/, sys.path[0] is already this directory;
# the insert is belt-and-suspenders for IDE runners and unusual cwds.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from prohibited_common import PROHIBITED, load_carveouts


def component_full_name(c: dict) -> str:
    """Build the structural identifier for a CycloneDX component.

    npm scoped:   group="@noble", name="ed25519" -> "@noble/ed25519"
    npm unscoped: group absent, name="lodash"    -> "lodash"
    Maven-style:  group="com.google.zxing", name="core"
                  -> "com.google.zxing:core"
                  (won't appear in npm SBOM but the check stays robust)
    """
    name = (c.get("name") or "").strip()
    group = (c.get("group") or "").strip()
    if not name:
        return ""
    if not group:
        return name
    if group.startswith("@"):
        return f"{group}/{name}"
    return f"{group}:{name}"


def is_runtime_component(c: dict) -> bool:
    """Return True if this component ships at runtime.

    cyclonedx-npm@6.0.1 does not emit scope="required" for runtime
    deps. Its actual convention:

      - Runtime deps: no `cdx:npm:package:development` property.
        Implicit rather than explicit.
      - Dev deps: carry `properties` entry with
        name="cdx:npm:package:development", value="true".
      - Optional deps: carry scope="optional" (no dev marker).

    For §11's absolute prohibition, optional deps ARE runtime-reachable
    -- any dep that a user's environment could install is a risk. Only
    explicit dev-marked components are excluded.

    Discovered at PR #1: the original filter assumed scope="required"
    per the CycloneDX spec; cyclonedx-npm@6.0.1 doesn't emit that.
    The gate failed-closed on zero components, which is what caught it.
    """
    for prop in c.get("properties", []):
        if (prop.get("name") == "cdx:npm:package:development"
                and str(prop.get("value")).lower() == "true"):
            return False
    return True


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: check-prohibited.py <sbom.json> [exceptions.md]",
              file=sys.stderr)
        return 2
    sbom_path = Path(sys.argv[1])
    exceptions_path = Path(
        sys.argv[2] if len(sys.argv) >= 3
        else "../docs/security/DEPENDENCY-EXCEPTIONS.md"
    )

    if not sbom_path.exists():
        print(f"::error::SBOM not found: {sbom_path}", file=sys.stderr)
        return 1

    try:
        sbom = json.loads(sbom_path.read_text())
    except json.JSONDecodeError as e:
        print(f"::error::SBOM is not valid JSON: {e}", file=sys.stderr)
        return 1

    components = sbom.get("components", [])
    if not isinstance(components, list):
        print("::error::SBOM components is not a list", file=sys.stderr)
        return 1

    carveouts = load_carveouts(exceptions_path)

    runtime = [c for c in components
               if isinstance(c, dict) and is_runtime_component(c)]

    # Fail-closed on the meta-case: no runtime components means the
    # filter cannot run. If cyclonedx-npm's output format changes, this
    # check should fail loudly, not pass vacuously.
    if not runtime:
        print("::error::no runtime components in SBOM -- check "
              "cyclonedx-npm output format (expected: dev deps marked "
              "with cdx:npm:package:development property) -- FAIL",
              file=sys.stderr)
        return 1

    print(f"SBOM: {len(components)} components total, "
          f"{len(runtime)} runtime-scope, "
          f"{len(carveouts)} §2 carve-out(s) parsed")

    violations = []
    for c in runtime:
        full = component_full_name(c)
        if not full:
            continue
        version = (c.get("version") or "").strip() or "<unversioned>"
        for label, matcher in PROHIBITED:
            if matcher(full):
                key = f"{full}@{version}"
                if key in carveouts:
                    print(f"::notice::{full}@{version} matches §11 '{label}' "
                          f"but has carve-out entry -- allowed")
                else:
                    violations.append((full, version, label))
                break

    if violations:
        print("", file=sys.stderr)
        for full, version, label in violations:
            print(f"::error::{full}@{version} matches §11 prohibited "
                  f"'{label}' and has no carve-out entry in "
                  f"DEPENDENCY-EXCEPTIONS.md §2", file=sys.stderr)
        print(f"\n{len(violations)} prohibited package(s) without "
              f"carve-out -- FAIL", file=sys.stderr)
        return 1

    print(f"No prohibited runtime packages (checked {len(runtime)} "
          f"components against §11 list) -- PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())