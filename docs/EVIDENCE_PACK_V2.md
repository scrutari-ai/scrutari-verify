# Scrutari Evidence Pack v2 — format specification

Status: public specification of the export format verified by `scrutari-verify`.
Source of truth: the verifier's own parser (`src/pack.rs`) and checks (`src/verify.rs`);
if this document and the verifier ever disagree, the verifier wins.

## What an evidence pack is

An evidence pack is one JSONL file: one JSON object per line, each carrying a
`"record"` discriminator. It is a self-contained export of a tenant's AI audit
trail, carrying everything needed to verify it offline: the rows, the signed
Merkle anchors that cover them, the public keys, and a terminal manifest with
counts. An air-gapped machine running `scrutari-verify` can establish that the
pack is complete, untampered, included under signed anchors, and signed by the
declared keys, without contacting Scrutari.

A verifier that predates a record kind ignores it and still verifies what it
understands; unknown record kinds are tolerated by design, so packs are
forward-compatible.

## Record kinds

Every line is one of:

| `record` | Purpose |
|---|---|
| `header` | Opens the pack: `format_version` (2) and `tenant_id`. |
| `signing_keys` | The public keys the pack verifies under (see Keys). |
| `audit` | Admin audit rows. Counted in the manifest; not cryptographically verified in v2. |
| `ai_audit` | One AI request's audit row: the signed, hashed unit of evidence. |
| `anchor` | A signed Merkle anchor covering a contiguous range of rows. |
| `manifest` | Terminal record: counts, key ids, optional genesis handoff. |

## The `ai_audit` row

| Field | Meaning |
|---|---|
| `id` | Row id (monotonic within the tenant). |
| `created_at` | RFC 3339. With `id`, defines the Merkle leaf order `(created_at, id)`. |
| `payload` | The exact canonical bytes that were hashed, as a string, hashed verbatim. |
| `payload_hash` | Lower-hex SHA-256 of `payload`. |
| `signature`, `signing_key_id`, `sig_alg`, `signed` | Per-row Ed25519 signature, when the row is signed. |
| `covered_by` | `{anchor_id, chain}` — the anchor this row sits under. |
| `inclusion_proof` | Present for fleet-chain rows: `{leaf_index, leaf_count, path}` — ordered sibling hashes from the leaf level upward. Absent for sovereign rows, which are verified by full root recomputation. |

`chain` is either `fleet` (the shared pre-sovereign chain) or `tenant:<id>`
(the tenant's own sovereign chain).

### The canonical payload

`payload` is not opaque in practice: the gateway's canonical AI payload (v1)
is a deterministic JSON object whose fields pin what happened and what
produced it — a payload version byte (`v`), `request_id`, `tenant_id`,
`workload`, `provider`, `model`, `input_tokens`, `output_tokens`,
`model_iterations`, `tools_called` (the tool invocations an agent made),
`latency_ms`, `outcome_code`, and `outcome`. Because `provider` and `model`
sit inside the signed, anchored bytes, a verified row is evidence of which
model produced the recorded outcome — the audit-trail half of attested
inference, and the record shape EU AI Act Article 12 logging asks for
(period of use, reference data, and outcome are all present per request).
Prompt and response text are deliberately not in the payload. A policy
identifier (which redaction mode, quota policy, and routing configuration
were in force) is planned for a future payload version; today those are
deployment-level facts, not per-row fields.

## Anchors

An anchor signs a contiguous row range on one chain:

| Field | Meaning |
|---|---|
| `id`, `chain` | Anchor id and the chain it belongs to. |
| `from_id`, `to_id`, `row_count` | The covered range. |
| `merkle_root` | Root over the covered rows in `(created_at, id)` leaf order. |
| `prev_anchor_id`, `prev_root` | Link to the preceding anchor on the same chain (absent at genesis). |
| `signature`, `signing_key_id`, `sig_alg` | Anchor signature: `ed25519`, `ES256`, or `ML-DSA-87`. |

The prev-links make the anchor sequence itself tamper-evident: replacing or
reordering an anchor breaks continuity.

## Keys

Each `signing_keys` entry declares `key_id`, `sig_alg` (`ed25519` | `ES256`),
`usage` (`row` | `anchor`), `key_origin`, and `public_key_hex`. `key_origin`
states who controls the key:

- `fleet` — Scrutari's fleet key.
- `managed` — a per-tenant key Scrutari operates.
- `customer` — a key in the customer's own HSM. Scrutari cannot forge anchors
  signed by a customer-origin key.

The keys travel in the pack so verification is self-contained. To rule out a
wholesale forgery of pack plus keys, compare the key fingerprints the verifier
prints against fingerprints obtained out of band (dashboard, contract, or your
own HSM).

## Manifest and genesis handoff

The terminal `manifest` repeats `format_version` and `tenant_id`, lists the
`signing_key_ids` used, and carries `counts` — `audit`, `ai_audit`,
`ai_signed`, `anchors` — which must reconcile with what the pack contains; a
truncated pack fails structure checking.

A tenant that started on the shared fleet chain and later moved to a sovereign
chain carries a `genesis_handoff` — `{handoff_cursor_id,
sovereign_first_from_id}` — and the verifier checks the seam: no gap, no
double-coverage between the fleet window and the sovereign window.

## What the verifier establishes

In order: structure and completeness against the manifest; per-row integrity
(`payload_hash == SHA-256(payload)` recomputed from canonical bytes); per-row
Ed25519 signatures; anchor signatures under keys the manifest lists; full
Merkle recomputation of each sovereign chain; inclusion-proof verification for
fleet rows; per-chain prev-link continuity; the genesis-handoff seam; and
coverage — every row references an anchor present in the pack.

## What a PASS does not prove

A PASS proves integrity, inclusion, and signature validity of the exported
pack against the declared keys. It does not prove that every event was logged
in the first place: anchoring makes after-the-fact deletion or alteration of
logged rows detectable; it cannot conjure rows that were never written. Admin
`audit` rows are counted but not cryptographically verified in v2. An
ML-DSA-87 anchor passing means exactly what an Ed25519 anchor passing means —
the signature verifies under the declared key; it is not a certification of
the deployment's post-quantum posture.

## Related: chain/v1 packs

Hash-chained control-plane tables (for example the admin audit log) export as
a distinct `chain/v1` pack, where integrity is carried by per-row
`entry_hash = SHA-256(prev_hash || canonical_row)` and one valid anchor
signature attests the entire prefix below it. `scrutari-verify` verifies both
formats; this document specifies v2 (Merkle).

## Spec status, versioning, and license

This document specifies format v2, the version the `header` and `manifest`
records declare. The specification text is licensed Apache-2.0, the same as
the verifier, and third-party implementations — emitters that produce packs,
or independent verifiers — are welcome and require no permission. The
normative conformance suite is the verifier's own test suite, which exercises
each tamper class against the checks above; exported golden test vectors (one
valid pack and one per tamper class, generated from the synthetic demo
generator in `examples/`) are planned so emitters can test without running
Rust. Changes to the format bump the version; existing verifiers ignore
record kinds they predate rather than failing.

## Verifying a pack

```
cargo install scrutari-verify
scrutari-verify evidence-pack.jsonl
```

The build is small (five direct dependencies) and runs with no network. Read
the checks, build it yourself, and trust the math, not us.
