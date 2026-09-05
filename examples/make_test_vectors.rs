//! Generate `vectors/`: golden test vectors for Evidence Pack v2 implementers.
//!
//! One fully valid synthetic pack, plus one variant per tamper class, each
//! constructed so that exactly one verification dimension fails. Third-party
//! emitters and independent verifiers can test against these files without
//! running any Rust: a conforming verifier must PASS `valid.jsonl` and FAIL
//! each `fail-*.jsonl` on the check its name declares (see vectors/README.md,
//! which is generated alongside by scripts, not by this example).
//!
//!     cargo run --example make_test_vectors            # writes ./vectors
//!     cargo run --example make_test_vectors -- outdir  # custom directory
//!
//! Construction mirrors `examples/make_demo_pack.rs` (throwaway keys, the
//! fictional tenant `demo-clinic`, nothing real). Most variants are surgical
//! post-mutations of the valid pack; the tampered-sovereign-root variant is
//! rebuilt with a valid signature over the wrong root, so that recompute —
//! not the anchor signature — is what fails, exactly as in production
//! tampering where the signer is the attacker.

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, Ed25519KeyPair, KeyPair,
};
use serde_json::{Value, json};

use scrutari_verify::canonical::anchor_payload_hash;
use scrutari_verify::crypto::{hex_lower, merkle_audit_path, merkle_root, sha256};

fn key_id_for(public_key: &[u8]) -> String {
    hex_lower(&sha256(public_key))[..16].to_string()
}

struct VecEd25519 {
    pair: Ed25519KeyPair,
    public: Vec<u8>,
    key_id: String,
}

impl VecEd25519 {
    fn generate() -> Self {
        let doc = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .expect("vector keygen (example only)");
        let pair = Ed25519KeyPair::from_pkcs8(doc.as_ref()).expect("vector key parse");
        let public = pair.public_key().as_ref().to_vec();
        let key_id = key_id_for(&public);
        Self {
            pair,
            public,
            key_id,
        }
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.pair.sign(message).as_ref().to_vec()
    }
}

struct VecEs256 {
    pair: EcdsaKeyPair,
    public: Vec<u8>,
    key_id: String,
    rng: SystemRandom,
}

impl VecEs256 {
    fn generate() -> Self {
        let rng = SystemRandom::new();
        let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .expect("vector keygen (example only)");
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, doc.as_ref())
            .expect("vector key parse");
        let public = pair.public_key().as_ref().to_vec();
        let key_id = key_id_for(&public);
        Self {
            pair,
            public,
            key_id,
            rng,
        }
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.pair
            .sign(&self.rng, message)
            .expect("vector sign")
            .as_ref()
            .to_vec()
    }
}

fn row_payload(id: i64, workload: &str, model: &str, in_tok: u64, out_tok: u64) -> String {
    format!(
        r#"{{"v":1,"request_id":"req_vec_{id:04}","tenant_id":"demo-clinic","workload":"{workload}","provider":"anthropic.direct","model":"{model}","input_tokens":{in_tok},"output_tokens":{out_tok},"model_iterations":1,"tools_called":[],"latency_ms":842,"outcome_code":"success","outcome":{{"kind":"success"}}}}"#
    )
}

fn path_hex(leaves: &[[u8; 32]], target: usize) -> Vec<String> {
    merkle_audit_path(leaves, target)
        .iter()
        .map(|node| hex_lower(node))
        .collect()
}

/// Flip one hex nibble so the string stays valid lower-hex of equal length.
fn corrupt_hex(hex: &str) -> String {
    let mut chars: Vec<char> = hex.chars().collect();
    chars[0] = if chars[0] == '0' { '1' } else { '0' };
    chars.into_iter().collect()
}

fn write_pack(dir: &std::path::Path, name: &str, records: &[Value]) {
    let mut out = String::new();
    for record in records {
        out.push_str(&serde_json::to_string(record).expect("serialize record"));
        out.push('\n');
    }
    std::fs::write(dir.join(name), out).expect("write vector file");
    eprintln!("wrote {}", dir.join(name).display());
}

fn main() {
    let out_dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "vectors".to_string());
    let out_dir = std::path::PathBuf::from(out_dir);
    std::fs::create_dir_all(&out_dir).expect("create output dir");

    let row_key = VecEd25519::generate();
    let fleet_key = VecEd25519::generate();
    let tenant_key = VecEs256::generate();

    // ── Base pack: 3 fleet rows (with inclusion proofs) + 2 sovereign rows ──
    let workloads = [
        ("intake-summarizer", "claude-sonnet-4-6", 1874u64, 312u64),
        ("coding-assistant", "gpt-4o", 951, 220),
        ("denial-letter-drafts", "claude-sonnet-4-6", 2310, 540),
    ];

    let mut fleet_rows = Vec::new();
    let mut fleet_hashes = Vec::new();
    for (i, (workload, model, in_tok, out_tok)) in workloads.iter().enumerate() {
        let id = (i + 1) as i64;
        let payload = row_payload(id, workload, model, *in_tok, *out_tok);
        let hash = sha256(payload.as_bytes());
        let sig = row_key.sign(&hash);
        fleet_rows.push(json!({
            "record": "ai_audit",
            "id": id,
            "created_at": format!("2026-09-01T14:0{}:00Z", i),
            "payload": payload,
            "payload_hash": hex_lower(&hash),
            "signature": hex_lower(&sig),
            "signing_key_id": row_key.key_id,
            "sig_alg": "ed25519",
            "signed": true,
            "covered_by": { "anchor_id": 100, "chain": "fleet" },
        }));
        fleet_hashes.push(hash);
    }
    let other_a = sha256(b"another-tenant-leaf-A");
    let other_b = sha256(b"another-tenant-leaf-B");
    let fleet_leaves = [
        fleet_hashes[0],
        other_a,
        fleet_hashes[1],
        other_b,
        fleet_hashes[2],
    ];
    for (row, leaf_index) in fleet_rows.iter_mut().zip([0usize, 2, 4]) {
        row["inclusion_proof"] = json!({
            "leaf_index": leaf_index,
            "leaf_count": 5,
            "path": path_hex(&fleet_leaves, leaf_index),
        });
    }
    let fleet_root_hex = hex_lower(&merkle_root(&fleet_leaves));

    let mut sovereign_rows = Vec::new();
    let mut sovereign_hashes = Vec::new();
    for (i, (workload, model, in_tok, out_tok)) in [
        ("intake-summarizer", "claude-sonnet-4-6", 1502u64, 287u64),
        ("denial-letter-drafts", "claude-sonnet-4-6", 1980, 466),
    ]
    .iter()
    .enumerate()
    {
        let id = (i + 6) as i64;
        let payload = row_payload(id, workload, model, *in_tok, *out_tok);
        let hash = sha256(payload.as_bytes());
        let sig = row_key.sign(&hash);
        sovereign_rows.push(json!({
            "record": "ai_audit",
            "id": id,
            "created_at": format!("2026-09-01T15:0{}:00Z", i),
            "payload": payload,
            "payload_hash": hex_lower(&hash),
            "signature": hex_lower(&sig),
            "signing_key_id": row_key.key_id,
            "sig_alg": "ed25519",
            "signed": true,
            "covered_by": { "anchor_id": 200, "chain": "tenant:demo-clinic" },
        }));
        sovereign_hashes.push(hash);
    }
    let tenant_root_hex = hex_lower(&merkle_root(&sovereign_hashes));

    let fleet_hash = anchor_payload_hash(1, 5, 5, &fleet_root_hex, None, None).expect("canonical");
    let fleet_anchor = json!({
        "record": "anchor", "id": 100, "chain": "fleet",
        "from_id": 1, "to_id": 5, "row_count": 5,
        "merkle_root": fleet_root_hex, "prev_anchor_id": null, "prev_root": null,
        "signature": hex_lower(&fleet_key.sign(&fleet_hash)),
        "signing_key_id": fleet_key.key_id, "sig_alg": "ed25519",
    });
    let tenant_hash =
        anchor_payload_hash(6, 7, 2, &tenant_root_hex, None, None).expect("canonical");
    let tenant_anchor = json!({
        "record": "anchor", "id": 200, "chain": "tenant:demo-clinic",
        "from_id": 6, "to_id": 7, "row_count": 2,
        "merkle_root": tenant_root_hex, "prev_anchor_id": null, "prev_root": null,
        "signature": hex_lower(&tenant_key.sign(&tenant_hash)),
        "signing_key_id": tenant_key.key_id, "sig_alg": "ES256",
    });

    let header = json!({ "record": "header", "format_version": 2, "tenant_id": "demo-clinic" });
    let signing_keys = json!({
        "record": "signing_keys",
        "keys": [
            { "key_id": row_key.key_id, "sig_alg": "ed25519", "usage": "row",
              "key_origin": "fleet", "public_key_hex": hex_lower(&row_key.public) },
            { "key_id": fleet_key.key_id, "sig_alg": "ed25519", "usage": "anchor",
              "key_origin": "fleet", "public_key_hex": hex_lower(&fleet_key.public) },
            { "key_id": tenant_key.key_id, "sig_alg": "ES256", "usage": "anchor",
              "key_origin": "managed", "public_key_hex": hex_lower(&tenant_key.public) },
        ]
    });
    let manifest = json!({
        "record": "manifest", "format_version": 2, "tenant_id": "demo-clinic",
        "counts": { "audit": 0, "ai_audit": 5, "ai_signed": 5, "anchors": 2 },
        "signing_key_ids": [fleet_key.key_id, tenant_key.key_id],
        "genesis_handoff": { "handoff_cursor_id": 5, "sovereign_first_from_id": 6 },
    });

    let mut base: Vec<Value> = vec![header, signing_keys];
    base.extend(fleet_rows.iter().cloned());
    base.extend(sovereign_rows.iter().cloned());
    base.push(fleet_anchor.clone());
    base.push(tenant_anchor.clone());
    base.push(manifest.clone());

    // Indices into `base` for surgical mutation.
    let first_fleet_row = 2usize;
    let first_sovereign_row = 5usize;
    let fleet_anchor_idx = 7usize;
    let tenant_anchor_idx = 8usize;
    let manifest_idx = 9usize;

    // ── valid.jsonl ──
    write_pack(&out_dir, "valid.jsonl", &base);

    // ── fail-structure-truncated.jsonl: manifest missing ──
    let truncated: Vec<Value> = base[..manifest_idx].to_vec();
    write_pack(&out_dir, "fail-structure-truncated.jsonl", &truncated);

    // ── fail-integrity-row-payload.jsonl: payload edited, hash left stale ──
    let mut v = base.clone();
    {
        let payload = v[first_sovereign_row]["payload"]
            .as_str()
            .expect("payload string")
            .replace("\"latency_ms\":842", "\"latency_ms\":13");
        v[first_sovereign_row]["payload"] = Value::String(payload);
    }
    write_pack(&out_dir, "fail-integrity-row-payload.jsonl", &v);

    // ── fail-row-signature.jsonl: row signature corrupted ──
    let mut v = base.clone();
    {
        let sig = v[first_sovereign_row]["signature"]
            .as_str()
            .expect("sig")
            .to_string();
        v[first_sovereign_row]["signature"] = Value::String(corrupt_hex(&sig));
    }
    write_pack(&out_dir, "fail-row-signature.jsonl", &v);

    // ── fail-anchor-signature.jsonl: anchor signature corrupted ──
    let mut v = base.clone();
    {
        let sig = v[tenant_anchor_idx]["signature"]
            .as_str()
            .expect("sig")
            .to_string();
        v[tenant_anchor_idx]["signature"] = Value::String(corrupt_hex(&sig));
    }
    write_pack(&out_dir, "fail-anchor-signature.jsonl", &v);

    // ── fail-sovereign-root.jsonl: wrong root, VALIDLY signed, so only
    //    Merkle recompute can catch it ──
    let mut v = base.clone();
    {
        let bad_root = corrupt_hex(&tenant_root_hex);
        let bad_hash = anchor_payload_hash(6, 7, 2, &bad_root, None, None).expect("canonical");
        v[tenant_anchor_idx] = json!({
            "record": "anchor", "id": 200, "chain": "tenant:demo-clinic",
            "from_id": 6, "to_id": 7, "row_count": 2,
            "merkle_root": bad_root, "prev_anchor_id": null, "prev_root": null,
            "signature": hex_lower(&tenant_key.sign(&bad_hash)),
            "signing_key_id": tenant_key.key_id, "sig_alg": "ES256",
        });
    }
    write_pack(&out_dir, "fail-sovereign-root.jsonl", &v);

    // ── fail-fleet-inclusion.jsonl: one sibling in an inclusion path corrupted ──
    let mut v = base.clone();
    {
        let node = v[first_fleet_row]["inclusion_proof"]["path"][0]
            .as_str()
            .expect("path node")
            .to_string();
        v[first_fleet_row]["inclusion_proof"]["path"][0] = Value::String(corrupt_hex(&node));
    }
    write_pack(&out_dir, "fail-fleet-inclusion.jsonl", &v);

    // ── fail-coverage-missing-anchor.jsonl: fleet anchor removed; manifest
    //    count adjusted so structure passes and coverage is what fails ──
    let mut v = base.clone();
    v.remove(fleet_anchor_idx);
    {
        let last = v.len() - 1;
        v[last]["counts"]["anchors"] = json!(1);
    }
    write_pack(&out_dir, "fail-coverage-missing-anchor.jsonl", &v);

    eprintln!("done: 1 valid + 7 tamper vectors in {}", out_dir.display());
}
