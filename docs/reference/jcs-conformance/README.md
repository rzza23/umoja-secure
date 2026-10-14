# JCS Conformance Corpus — Provenance

Source: https://github.com/cyberphone/json-canonicalization
License: Apache License 2.0 (Copyright 2018 Anders Rundgren)
Vendored: 2026-10-14
Upstream commit: clone --depth 1, fetched 2026-10-14

## What this is

Input/output pairs for JSON Canonicalization Scheme (RFC 8785). Each file
in `input/` has a corresponding file in `output/` with the same name. The
output is the expected byte-exact canonicalization of the input.

These are the de facto conformance vectors for JCS. Every serious
implementation validates against them.

## Contract

- Files in `input/` and `output/` are byte-exact as upstream.
- The output files have **no trailing newline**. Preserve that.
- Do not "fix" whitespace, reorder keys, or reformat. Any modification
  invalidates the vectors.
- If upstream publishes new vectors, re-vendor; do not edit in place.

## Corpus contents

| Pair | Exercises |
|---|---|
| arrays.json | array order preservation |
| french.json | non-ASCII characters, accented text |
| structures.json | nested object key sorting |
| unicode.json | Unicode escaping rules |
| values.json | mixed scalar types |
| weird.json | pathological key ordering, control chars |

## Relationship to Umoja

The Umoja authorization-matrix signing protocol (Build Master §3.8) uses
JCS over the wrapper `{"domain":"umoja.authorization-matrix.v1","matrix":{...}}`.
Both the TypeScript reference implementation (backend) and the Kotlin
verifier (Android) must pass every vector in this corpus before any
sign/verify code is written. This is a TASK-P1-026 acceptance criterion.

Number-serialization edge cases live separately in
`docs/reference/rfc8785-number-samples.json` (RFC 8785 Appendix B), because
the cyberphone corpus does not stress the number boundary.

## License notice

The files in `input/` and `output/` are Copyright 2018 Anders Rundgren
and licensed under the Apache License, Version 2.0. A copy of the license
is at https://www.apache.org/licenses/LICENSE-2.0

They are vendored here unmodified for conformance testing only.
