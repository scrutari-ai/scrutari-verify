# Evidence Pack v2 — golden test vectors

Fixtures for third-party implementers of the
[Evidence Pack v2 format](../docs/EVIDENCE_PACK_V2.md): emitters that produce
packs, and independent verifiers that check them. Everything here is fully
synthetic (fictional tenant `demo-clinic`, throwaway keys generated at build
time) and licensed Apache-2.0 like the rest of the repository.

## The conformance contract

A conforming verifier MUST report PASS on `valid.jsonl` and MUST report FAIL
on every `fail-*.jsonl`, failing at least the check the table names. Checks
are named as `scrutari-verify --json` reports them.

| File | Expected result | Failing check(s) |
|---|---|---|
| `valid.jsonl` | PASS | none |
| `fail-structure-truncated.jsonl` | FAIL | `structure.manifest_terminal` (pack ends without its manifest) |
| `fail-integrity-row-payload.jsonl` | FAIL | `row_integrity` (payload edited, stale `payload_hash`) |
| `fail-row-signature.jsonl` | FAIL | `row_signature` (row signature corrupted) |
| `fail-anchor-signature.jsonl` | FAIL | `anchor_signature` (anchor signature corrupted) |
| `fail-sovereign-root.jsonl` | FAIL | `sovereign_recompute` (wrong Merkle root, validly re-signed — only recompute can catch it) |
| `fail-fleet-inclusion.jsonl` | FAIL | `fleet_inclusion` (inclusion-proof sibling corrupted) |
| `fail-coverage-missing-anchor.jsonl` | FAIL | `coverage`, and consequently `fleet_inclusion` (the anchor rows reference is absent; manifest counts adjusted so structure still passes) |

Reproduce the table with the reference verifier:

```
cargo run -- --pack vectors/valid.jsonl
for f in vectors/fail-*.jsonl; do cargo run -- --pack "$f" --json; done
```

## Regenerating

```
cargo run --example make_test_vectors -- vectors
```

Keys are generated per run, so regenerated files differ byte-for-byte from
these; the committed files are the canonical fixtures. Regenerate only when
the format changes, and update this table from the verifier's actual output.
