# scrutari-verify

Offline verifier for Scrutari audit-export packs (format v2).

Scrutari customers can export their AI audit trail as a signed, Merkle-anchored
evidence pack (a single `.jsonl` file). This tool proves, on an air-gapped
machine with no network and no Scrutari services, that the pack is complete,
untampered, included under signed anchors, and signed by the declared keys.

The verifier is open source so you can read every check it performs, build it
yourself, and run it without trusting Scrutari's binaries or infrastructure.

## What a PASS proves

Given only an export pack, `scrutari-verify` establishes:

1. **Completeness of the pack.** The pack is not truncated: the terminal
   manifest is present and its record counts match what the pack contains.
2. **Integrity.** No exported row was altered: every row's `payload_hash`
   equals `SHA-256(payload)` recomputed from the row's canonical bytes.
3. **Inclusion.** Every row sits under a signed anchor: by full Merkle root
   recomputation on the tenant's own (sovereign) chain, or by a Merkle
   inclusion proof against the shared fleet chain.
4. **Signature validity.** Each signed row and each anchor verifies under the
   public key the pack declares, with an explicit `key_origin` (`fleet`,
   `customer`, or `managed`) telling you who controls that key.
5. **Continuity.** Within each chain, anchors link back to their predecessor
   (`prev_anchor_id` and `prev_root`), and the genesis-handoff seam between the
   fleet window and the sovereign window has no gap and no double-coverage.

## What a PASS does not prove

Be precise about the trust boundary:

* It proves integrity, inclusion, and signature validity of the exported pack
  against the public keys embedded in the export (and printed in the report).
  It does **not** prove the completeness of what Scrutari chose to log in the
  first place. If an event was never written to the audit trail, no export can
  surface it. Anchoring makes after-the-fact deletion and alteration of logged
  rows detectable; it cannot conjure rows that were never logged.
* The public keys come from the pack itself. To rule out a wholesale forgery
  of pack plus keys, compare the key fingerprints in the report against the
  fingerprints you obtained out of band (from your dashboard, your contract
  documentation, or your own HSM, for customer-held keys). For a
  `customer`-origin key, the signing key is in your HSM and Scrutari could not
  have forged those anchors at all.
* Verification covers the AI audit rows and anchors. Admin audit records in
  the pack are counted but not cryptographically verified in format v2.
* An ML-DSA-87 anchor passing proves exactly what an Ed25519 or ES256 anchor
  passing proves: the signature verifies under the declared key. It does not
  make the whole pack "post-quantum": per-row signatures stay Ed25519 in
  every posture, and a PASS is not a certification of the deployment's
  CNSA 2.0 compliance, only of the signatures actually in the pack.

## Install

All install paths need a Rust toolchain (1.93 or newer) and a C compiler for
the aws-lc-rs crypto backend.

From crates.io (the simplest path, and a second independent install channel
with its own supply-chain provenance):

```
cargo install scrutari-verify
```

From source:

```
git clone https://github.com/scrutari-ai/scrutari-verify
cd scrutari-verify
cargo install --path .
```

Prebuilt binaries for Linux (x86_64), macOS (Apple Silicon), and Windows
(x86_64) are attached to each tagged GitHub release, together with a
`SHA-256SUMS` file. Verify the checksum before running a prebuilt binary (see
"Verifying a release" below), or build from source; the build is small and has
five direct dependencies (`aws-lc-rs`, `fips204`, `serde`, `serde_json`,
`clap`).

### Verifying a release

Each release attaches, next to the binaries:

* `SHA-256SUMS`: checksums of every archive.
* `SHA-256SUMS.sig` and `SHA-256SUMS.pem`: a keyless Sigstore signature over
  the checksums file, made by the release workflow with cosign. The
  certificate binds the signature to this repository's GitHub Actions
  identity; there is no long-lived signing key anywhere.
* `scrutari-verify-<tag>.intoto.jsonl`: SLSA build provenance over all
  artifacts, produced by the slsa-github-generator generic generator.

First verify the signature on the checksums file with
[cosign](https://github.com/sigstore/cosign):

```
cosign verify-blob \
  --certificate SHA-256SUMS.pem \
  --signature SHA-256SUMS.sig \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/scrutari-ai/scrutari-verify/\.github/workflows/release\.yml@refs/tags/v' \
  SHA-256SUMS
```

Then check the binary you downloaded against the now-trusted checksums:

```
sha256sum -c SHA-256SUMS --ignore-missing
```

Optionally, verify the build provenance with
[slsa-verifier](https://github.com/slsa-framework/slsa-verifier), replacing
the tag and archive name with the ones you downloaded:

```
slsa-verifier verify-artifact \
  --provenance-path scrutari-verify-v1.0.0.intoto.jsonl \
  --source-uri github.com/scrutari-ai/scrutari-verify \
  --source-tag v1.0.0 \
  scrutari-verify-v1.0.0-x86_64-unknown-linux-gnu.tar.gz
```

A PASS on all three means the artifact you hold is byte-identical to what
this repository's release workflow built from the tagged commit.

## Usage

```
scrutari-verify --pack export.jsonl          # human-readable report
scrutari-verify --pack export.jsonl --json   # machine-readable report
cat export.jsonl | scrutari-verify           # reads stdin when --pack omitted
```

Exit codes: `0` means PASS, `1` means verification failed, `2` means the pack
could not be read or the report could not be serialized.

Example PASS output:

```
Scrutari audit-export verification (pack format v2)
====================================================
[PASS] structure.parse        all lines parsed
[PASS] structure.header       v2 header, tenant acme
[PASS] structure.manifest_terminal terminal manifest present (pack not truncated)
[PASS] structure.counts       manifest counts {audit:0, ai_audit:5, ai_signed:5, anchors:2} vs actual {audit:0, ai_audit:5, ai_signed:5, anchors:2}
[PASS] structure.identity     header tenant acme / manifest tenant acme (v2)
[PASS] signing_keys           3 key(s) well-formed
[PASS] row_integrity          5 row(s) hash-match their payload
[PASS] row_signature          5 signed row(s) verified
[PASS] anchor_signature       2 anchor signature(s) verified
[PASS] sovereign_recompute    1 sovereign anchor root(s) recomputed
[PASS] fleet_inclusion        3 pre-sovereign row(s) proven included
[PASS] chain_continuity       all chains link cleanly
[PASS] genesis_seam           seam clean at cursor 5
[PASS] coverage               all 5 row(s) covered by a present anchor
----------------------------------------------------
RESULT: PASS (pack is complete, untampered, and correctly signed)
```

On any failed check the matching line reads `[FAIL]` with the offending row or
anchor ids, the final line reads `RESULT: FAIL`, and the exit code is 1.

## Pack format v2

A pack is JSONL: one JSON object per line, one tenant and one time window per
pack. Each line carries a `"record"` discriminator. Record order is
streaming-friendly (keys appear before the anchors that need them):

| record | meaning |
| --- | --- |
| `header` | `format_version: 2`, `tenant_id`, export window |
| `signing_keys` | every public key the verifier needs (public material only, never private keys) |
| `audit` | admin audit-log rows (counted, not crypto-verified in v2) |
| `ai_audit` | per-inference rows; pre-sovereign rows carry an `inclusion_proof` |
| `anchor` | chain-labelled Merkle anchors with signatures |
| `manifest` | terminal record; its presence proves the pack was not truncated |

Unknown record kinds are ignored, so an older verifier still checks everything
it understands in a newer pack.

### Two chains and the genesis handoff

A tenant's history can span two chains:

* **Fleet chain** (`chain: "fleet"`): before a tenant moves to their own
  signing key, their rows are batched into anchors shared with other tenants.
  Recomputing such a root would require other tenants' data, so each of the
  tenant's rows instead carries a **Merkle inclusion proof**: the sibling-hash
  path from the row's leaf up to the signed root. The path is a list of opaque
  32-byte hashes and reveals nothing about any other tenant's rows.
* **Sovereign chain** (`chain: "tenant:<id>"`): after the handoff, the
  tenant's rows live in their own chain. Each anchor's root covers only their
  rows, all of which are in the pack, so the verifier recomputes the entire
  root from scratch.

The manifest's `genesis_handoff` records the row-id cursor at which the tenant
became sovereign. The verifier asserts that every row at or below the cursor
is proven by fleet inclusion, every row above it is proven by sovereign
recompute, and the sovereign chain starts exactly one row past the cursor, so
the seam has no gap and no double-coverage.

### Key records

```json
{ "record": "signing_keys", "keys": [
  { "key_id": "0123456789abcdef", "sig_alg": "ed25519", "usage": "row",
    "key_origin": "fleet", "public_key_hex": "..." },
  { "key_id": "fedcba9876543210", "sig_alg": "ES256", "usage": "anchor",
    "key_origin": "managed", "public_key_hex": "04..." }
] }
```

Rows are signed with Ed25519 over the row's SHA-256 payload hash. Anchors are
signed with Ed25519, ES256 (ECDSA P-256 with SHA-256, raw 64-byte r||s
signatures), or ML-DSA-87 (FIPS 204, the post-quantum scheme Scrutari's
CNSA 2.0 posture uses for anchors; raw FIPS 204 encodings, a 2592-byte public
key and a 4627-byte signature, with an empty context string) over the SHA-256
of a canonical JSON projection of the anchor:
`{"v":1,"from_id":...,"to_id":...,"row_count":...,"merkle_root":"...",
"prev_anchor_id":...,"prev_root":...}` with exactly that field order and
`null` for absent links. The signed message is the same 32-byte payload hash
for all three schemes, so a posture change swaps only the algorithm, never
the signed content; each anchor's `sig_alg` says which scheme produced it,
and a single pack can mix them across a posture change. The verifier rebuilds
those bytes and checks the signature; any drift in the canonical form, and
any `sig_alg` this verifier does not implement, fails the check by design.

### Merkle tree shape

Trees are binary Merkle trees in the style of RFC 6962 (Certificate
Transparency): leaves are hashed as `SHA-256(0x00 || leaf)`, internal nodes as
`SHA-256(0x01 || left || right)`, and a lone trailing node at any level is
promoted unchanged. Leaf order is `(created_at, id)`. The domain-separation
tags prevent an internal node from being presented as a leaf.

## Threat model

Covered (a tampered pack fails verification):

* Altering any exported row's payload, even by one byte.
* Forging a row or anchor signature without the private key.
* Deleting, inserting, or reordering rows under an anchored batch.
* Substituting a different Merkle root or a corrupted inclusion path.
* Truncating the pack or splicing anchors across the chain (broken
  prev-links, broken handoff seam, miscounted manifest).

Not covered:

* Events that were never logged (see "What a PASS does not prove").
* A forged pack verified against forged keys, if you never compare the key
  fingerprints out of band. Do the comparison; it takes a minute.
* Compromise of the signing keys themselves before the rows were signed. For
  `customer`-origin keys that risk sits in your HSM, not with Scrutari.
* The semantic truth of payload contents. The verifier proves the bytes are
  what was signed, not that the model's recorded behavior was correct.

The verifier itself never needs or handles private key material, performs no
network I/O, and treats every malformed input as a failed finding rather than
a crash.

## Why open source

An audit trail you can only check with the vendor's closed tool is not really
verifiable: you would be trusting the same party the audit is supposed to hold
accountable. Publishing the verifier removes Scrutari from your trust path.
You can read each check, build the binary yourself, run it in an air-gapped
enclave, and, because the wire format is documented above, reimplement the
whole verifier independently and get the same answer. This implementation is a
reference, not the only possible one.

## License

Apache-2.0. See [LICENSE](LICENSE).
