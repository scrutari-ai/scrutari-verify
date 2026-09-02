//! Generate `sample/demo-evidence-pack.jsonl`: a fully synthetic,
//! fully verifiable Scrutari evidence pack for the fictional tenant
//! `demo-clinic`.
//!
//! Why this exists: a real export cannot be published (its signatures
//! cover real metadata, so scrubbing breaks verification, and not
//! scrubbing leaks it). This example builds a pack from nothing —
//! throwaway keys generated at run time, fictional workloads — that
//! passes every check the verifier runs. It doubles as documentation
//! of how a pack is constructed.
//!
//!     cargo run --example make_demo_pack > sample/demo-evidence-pack.jsonl
//!     cargo run -- --pack sample/demo-evidence-pack.jsonl
//!
//! Nothing here touches production keys. The `key_id` values are
//! derived from the throwaway public keys, exactly as production does.

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

struct DemoEd25519 {
    pair: Ed25519KeyPair,
    public: Vec<u8>,
    key_id: String,
}

impl DemoEd25519 {
    fn generate() -> Self {
        let doc = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .expect("demo keygen (example only)");
        let pair = Ed25519KeyPair::from_pkcs8(doc.as_ref()).expect("demo key parse");
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

struct DemoEs256 {
    pair: EcdsaKeyPair,
    public: Vec<u8>,
    key_id: String,
    rng: SystemRandom,
}

impl DemoEs256 {
    fn generate() -> Self {
        let rng = SystemRandom::new();
        let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .expect("demo keygen (example only)");
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, doc.as_ref())
            .expect("demo key parse");
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
            .expect("demo sign")
            .as_ref()
            .to_vec()
    }
}

/// One realistic (and entirely fictional) v1 row payload. The verifier
/// treats the payload as opaque signed bytes; the shape shown here
/// matches what the gateway actually writes.
fn row_payload(id: i64, workload: &str, model: &str, in_tok: u64, out_tok: u64) -> String {
    format!(
        r#"{{"v":1,"request_id":"req_demo_{id:04}","tenant_id":"demo-clinic","workload":"{workload}","provider":"anthropic.direct","model":"{model}","input_tokens":{in_tok},"output_tokens":{out_tok},"model_iterations":1,"tools_called":[],"latency_ms":842,"outcome_code":"success","outcome":{{"kind":"success"}}}}"#
    )
}

fn path_hex(leaves: &[[u8; 32]], target: usize) -> Vec<String> {
    merkle_audit_path(leaves, target)
        .iter()
        .map(|node| hex_lower(node))
        .collect()
}

fn main() {
    let row_key = DemoEd25519::generate();
    let fleet_key = DemoEd25519::generate();
    let tenant_key = DemoEs256::generate();

    let workloads = [
        ("intake-summarizer", "claude-sonnet-4-6", 1874u64, 312u64),
        ("coding-assistant", "gpt-4o", 951, 220),
        ("denial-letter-drafts", "claude-sonnet-4-6", 2310, 540),
    ];

    // Three pre-sovereign rows in a shared fleet batch, interleaved with
    // two other tenants' opaque leaves.
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

    // Two sovereign rows under the tenant's own ES256 anchor key.
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

    let mut records: Vec<Value> = vec![
        json!({ "record": "header", "format_version": 2, "tenant_id": "demo-clinic" }),
        json!({
            "record": "signing_keys",
            "keys": [
                { "key_id": row_key.key_id, "sig_alg": "ed25519", "usage": "row",
                  "key_origin": "fleet", "public_key_hex": hex_lower(&row_key.public) },
                { "key_id": fleet_key.key_id, "sig_alg": "ed25519", "usage": "anchor",
                  "key_origin": "fleet", "public_key_hex": hex_lower(&fleet_key.public) },
                { "key_id": tenant_key.key_id, "sig_alg": "ES256", "usage": "anchor",
                  "key_origin": "managed", "public_key_hex": hex_lower(&tenant_key.public) },
            ]
        }),
    ];
    records.extend(fleet_rows);
    records.extend(sovereign_rows);
    records.push(fleet_anchor);
    records.push(tenant_anchor);
    records.push(json!({
        "record": "manifest", "format_version": 2, "tenant_id": "demo-clinic",
        "counts": { "audit": 0, "ai_audit": 5, "ai_signed": 5, "anchors": 2 },
        "signing_key_ids": [fleet_key.key_id, tenant_key.key_id],
        "genesis_handoff": { "handoff_cursor_id": 5, "sovereign_first_from_id": 6 },
    }));

    for record in &records {
        println!(
            "{}",
            serde_json::to_string(record).expect("serialize record")
        );
    }
}
