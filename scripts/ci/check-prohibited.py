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

  1. Filter to runtime-scope components (scope == "required";
     dev-only deps don't ship -- §11 is about runtime reachability).
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

Task: TASK-P1-027b (implementation, Z-26-A block 3a)
ADR:  ADR-CI-GATE-001 §5
"""

import json
import re
import sys
from pathlib import Path

# Build Master §11 prohibited patterns. Each entry is (label, matcher)
# where matcher(full_name) -> bool. Matching is structural (startswith /
# exact / prefix-wildcard), not substring. Per ADR §5 line 272,
# "com.google.zxing:core cannot be silently passed by grepping 'google'"
# -- that is a statement about the matching method, so the identifier is
# built from JSON fields and compared structurally.
PROHIBITED = [
    ("@google/*",           lambda n: n.startswith("@google/")),
    ("com.google.*",        lambda n: n.startswith("com.google.")),
    ("googleapis",          lambda n: n == "googleapis"),
    ("gaxios",              lambda n: n == "gaxios"),
    ("google-auth-library", lambda n: n == "google-auth-library"),
    # firebase* -- §11's wildcard on the "firebase" prefix. All actual
    # npm firebase packages are `firebase` or `firebase-*`; matching
    # startswith("firebase-") or exact "firebase" avoids false positives
    # like a hypothetical "firebasefoo" (not a real package).
    ("firebase*",           lambda n: n == "firebase" or n.startswith("firebase-")),
    ("tink",                lambda n: n == "tink"),
]

# Carve-out entry format in DEPENDENCY-EXCEPTIONS.md §2:
#   ### `<artifact>` @ <version>
# e.g. ### `com.google.zxing:core` @ 3.4.1
CARVEOUT_RE = re.compile(r"^###\s+`([^`]+)`\s+@\s+(\S+)\s*$")


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


def load_carveouts(path: Path) -> set:
    """Parse DEPENDENCY-EXCEPTIONS.md §2 for exact-version carve-outs.

    Returns a set of strings "artifact@version". Only §2 entries count
    here -- §1 CVE exceptions are a different mechanism (handled by
    check-cve-exceptions.py).
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
               if isinstance(c, dict) and c.get("scope") == "required"]

    # Fail-closed on the meta-case: no runtime components means the
    # filter cannot run. If cyclonedx-npm's scope marking changes, this
    # check should fail loudly, not pass vacuously.
    if not runtime:
        print("::error::no runtime-scope components in SBOM -- check "
              "cyclonedx-npm scope marking (expected scope: \"required\") -- "
              "FAIL", file=sys.stderr)
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