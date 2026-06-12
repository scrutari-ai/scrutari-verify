//! Battle-tests for the verifier against hand-built v2 packs.
//!
//! A valid pack is constructed with REAL signatures (Ed25519 rows + a fleet
//! Ed25519 anchor + a sovereign ES256 anchor), a real multi-tenant fleet Merkle
//! tree with inclusion proofs for the tenant's pre-sovereign rows, and a real
//! sovereign tree over the tenant's own rows. A second variant swaps the fleet
//! anchor key for ML-DSA-87 (FIPS 204), mirroring a pack exported under the
//! gateway's CNSA 2.0 posture. Then each tamper test perturbs one dimension and
//! asserts the matching check fails — proving the checks bite.

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, Ed25519KeyPair, KeyPair,
};
use scrutari_verify::canonical::anchor_payload_hash;
use scrutari_verify::crypto::{hex_lower, merkle_root, sha256};
use scrutari_verify::verify::{Report, verify};
use serde_json::{Value, json};

// ── Test signers (fixture generation only; the verifier never signs) ──
//
// These mirror the signing side: rows and fleet anchors are Ed25519, sovereign
// anchors are ES256 (ECDSA P-256, raw 64-byte P1363 signatures), and a key id
// is the first 8 bytes of SHA-256(public_key), lower-hex.

fn key_id_for(public_key: &[u8]) -> String {
    let hash = sha256(public_key);
    hex_lower(&hash[..8])
}

struct Ed25519TestKey {
    key_pair: Ed25519KeyPair,
    public: Vec<u8>,
    key_id: String,
}

impl Ed25519TestKey {
    fn generate() -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("generate ed25519 key");
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("load ed25519 key");
        let public = key_pair.public_key().as_ref().to_vec();
        let key_id = key_id_for(&public);
        Self {
            key_pair,
            public,
            key_id,
        }
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.key_pair.sign(message).as_ref().to_vec()
    }
}

struct Es256TestKey {
    key_pair: EcdsaKeyPair,
    public: Vec<u8>,
    key_id: String,
}

impl Es256TestKey {
    fn generate() -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .expect("generate es256 key");
        let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref())
            .expect("load es256 key");
        let public = key_pair.public_key().as_ref().to_vec();
        let key_id = key_id_for(&public);
        Self {
            key_pair,
            public,
            key_id,
        }
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        let rng = SystemRandom::new();
        self.key_pair
            .sign(&rng, message)
            .expect("es256 sign")
            .as_ref()
            .to_vec()
    }
}

/// ML-DSA-87 (FIPS 204) fixture signer, mirroring the gateway's CNSA 2.0
/// anchor signer: raw FIPS 204 key/signature encodings, empty context, and
/// the same first-8-bytes-of-SHA-256(public_key) key id as the other keys.
struct MlDsa87TestKey {
    private: fips204::ml_dsa_87::PrivateKey,
    public: Vec<u8>,
    key_id: String,
}

impl MlDsa87TestKey {
    fn generate() -> Self {
        use fips204::traits::SerDes;
        let (pk, sk) = fips204::ml_dsa_87::try_keygen().expect("generate ml-dsa-87 key");
        let public = pk.into_bytes().to_vec();
        let key_id = key_id_for(&public);
        Self {
            private: sk,
            public,
            key_id,
        }
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        use fips204::traits::Signer;
        // Same sign input as the gateway: the raw message bytes (the
        // 32-byte anchor payload hash) with the empty FIPS 204 context.
        self.private
            .try_sign(message, &[])
            .expect("ml-dsa-87 sign")
            .to_vec()
    }
}

/// The fleet anchor key under test: Ed25519 (the software default) or
/// ML-DSA-87 (the CNSA 2.0 posture). Lets one pack builder produce both
/// variants without duplicating the fixture. The ML-DSA-87 variant is
/// boxed: a FIPS 204 private key is ~23 KiB against Ed25519's handful of
/// bytes (clippy::large_enum_variant).
enum FleetAnchorKey {
    Ed25519(Ed25519TestKey),
    MlDsa87(Box<MlDsa87TestKey>),
}

impl FleetAnchorKey {
    fn sig_alg(&self) -> &'static str {
        match self {
            FleetAnchorKey::Ed25519(_) => "ed25519",
            FleetAnchorKey::MlDsa87(_) => "ML-DSA-87",
        }
    }

    fn key_id(&self) -> &str {
        match self {
            FleetAnchorKey::Ed25519(key) => &key.key_id,
            FleetAnchorKey::MlDsa87(key) => &key.key_id,
        }
    }

    fn public(&self) -> &[u8] {
        match self {
            FleetAnchorKey::Ed25519(key) => &key.public,
            FleetAnchorKey::MlDsa87(key) => &key.public,
        }
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        match self {
            FleetAnchorKey::Ed25519(key) => key.sign(message),
            FleetAnchorKey::MlDsa87(key) => key.sign(message),
        }
    }
}

// ── RFC 6962 helpers (mirror the exporter) for fleet-tree proof gen ──

fn leaf_hash(leaf: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 33];
    buf[0] = 0x00;
    buf[1..].copy_from_slice(leaf);
    sha256(&buf)
}

fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 65];
    buf[0] = 0x01;
    buf[1..33].copy_from_slice(left);
    buf[33..].copy_from_slice(right);
    sha256(&buf)
}

/// Sibling audit path for `target`, mirroring `merkle_root`'s level build and
/// lone-node promotion. Identical to the generator the export builder runs.
fn inclusion_path(leaves: &[[u8; 32]], target: usize) -> Vec<[u8; 32]> {
    let mut level: Vec<[u8; 32]> = leaves.iter().map(leaf_hash).collect();
    let mut idx = target;
    let mut path: Vec<[u8; 32]> = Vec::new();
    while level.len() > 1 {
        let mut next: Vec<[u8; 32]> = Vec::new();
        let mut i = 0;
        while i < level.len() {
            if i + 1 < level.len() {
                if i == idx {
                    path.push(level[i + 1]);
                } else if i + 1 == idx {
                    path.push(level[i]);
                }
                next.push(node_hash(&level[i], &level[i + 1]));
                i += 2;
            } else {
                next.push(level[i]);
                i += 1;
            }
        }
        idx /= 2;
        level = next;
    }
    path
}

fn path_hex(leaves: &[[u8; 32]], target: usize) -> Vec<String> {
    inclusion_path(leaves, target)
        .iter()
        .map(|n| hex_lower(n))
        .collect()
}

// ── Pack builder ─────────────────────────────────────────────────────

/// Build the ordered v2 records of a valid pack for tenant `acme`:
/// 3 pre-sovereign rows under a shared fleet anchor (with inclusion proofs) +
/// 2 sovereign rows under the tenant's own ES256-signed anchor. The fleet
/// anchor key is Ed25519 here; [`build_records_with`] takes any
/// [`FleetAnchorKey`] (the ML-DSA-87 tests pass the CNSA 2.0 key).
fn build_records() -> Vec<Value> {
    build_records_with(FleetAnchorKey::Ed25519(Ed25519TestKey::generate()))
}

fn build_records_with(fleet_key: FleetAnchorKey) -> Vec<Value> {
    let row_key = Ed25519TestKey::generate();
    let tenant_key = Es256TestKey::generate();

    // A signed ai_audit row: opaque canonical payload string + its hash + sig.
    let make_row = |id: i64, created: &str, anchor_id: i64, chain: &str| -> (Value, [u8; 32]) {
        let payload = format!(r#"{{"v":1,"request_id":"req-{id}","tenant_id":"acme"}}"#);
        let hash = sha256(payload.as_bytes());
        let sig = row_key.sign(&hash);
        // Inclusion proof, when needed (fleet rows), is added by the caller once
        // the surrounding Merkle tree exists.
        let row = json!({
            "record": "ai_audit",
            "id": id,
            "created_at": created,
            "payload": payload,
            "payload_hash": hex_lower(&hash),
            "signature": hex_lower(&sig),
            "signing_key_id": row_key.key_id,
            "sig_alg": "ed25519",
            "signed": true,
            "covered_by": { "anchor_id": anchor_id, "chain": chain },
        });
        (row, hash)
    };

    // Pre-sovereign rows (acme ids 1,2,3) live in a fleet batch interleaved with
    // two OTHER tenants' opaque leaves → leaf_count 5, acme at indices 0,2,4.
    let (mut r1, h1) = make_row(1, "2026-06-09T00:00:01Z", 100, "fleet");
    let (mut r2, h2) = make_row(2, "2026-06-09T00:00:02Z", 100, "fleet");
    let (mut r3, h3) = make_row(3, "2026-06-09T00:00:03Z", 100, "fleet");
    let other_a = sha256(b"other-tenant-row-A");
    let other_b = sha256(b"other-tenant-row-B");
    let fleet_leaves = [h1, other_a, h2, other_b, h3];
    let fleet_root = merkle_root(&fleet_leaves);

    r1["inclusion_proof"] =
        json!({ "leaf_index": 0, "leaf_count": 5, "path": path_hex(&fleet_leaves, 0) });
    r2["inclusion_proof"] =
        json!({ "leaf_index": 2, "leaf_count": 5, "path": path_hex(&fleet_leaves, 2) });
    r3["inclusion_proof"] =
        json!({ "leaf_index": 4, "leaf_count": 5, "path": path_hex(&fleet_leaves, 4) });

    // Sovereign rows (acme ids 6,7) — their OWN anchor, root over only them.
    let (r6, h6) = make_row(6, "2026-06-09T00:00:06Z", 200, "tenant:acme");
    let (r7, h7) = make_row(7, "2026-06-09T00:00:07Z", 200, "tenant:acme");
    let tenant_root = merkle_root(&[h6, h7]);

    // Anchors.
    let fleet_root_hex = hex_lower(&fleet_root);
    let fleet_payload_hash = anchor_payload_hash(1, 5, 5, &fleet_root_hex, None, None).unwrap();
    let fleet_sig = fleet_key.sign(&fleet_payload_hash);
    let fleet_anchor = json!({
        "record": "anchor", "id": 100, "chain": "fleet",
        "from_id": 1, "to_id": 5, "row_count": 5,
        "merkle_root": fleet_root_hex, "prev_anchor_id": null, "prev_root": null,
        "signature": hex_lower(&fleet_sig),
        "signing_key_id": fleet_key.key_id(), "sig_alg": fleet_key.sig_alg(),
    });

    let tenant_root_hex = hex_lower(&tenant_root);
    let tenant_payload_hash = anchor_payload_hash(6, 7, 2, &tenant_root_hex, None, None).unwrap();
    let tenant_sig = tenant_key.sign(&tenant_payload_hash);
    let tenant_anchor = json!({
        "record": "anchor", "id": 200, "chain": "tenant:acme",
        "from_id": 6, "to_id": 7, "row_count": 2,
        "merkle_root": tenant_root_hex, "prev_anchor_id": null, "prev_root": null,
        "signature": hex_lower(&tenant_sig),
        "signing_key_id": tenant_key.key_id, "sig_alg": "ES256",
    });

    let header = json!({ "record": "header", "format_version": 2, "tenant_id": "acme" });
    let signing_keys = json!({
        "record": "signing_keys",
        "keys": [
            { "key_id": row_key.key_id, "sig_alg": "ed25519", "usage": "row",
              "key_origin": "fleet", "public_key_hex": hex_lower(&row_key.public) },
            { "key_id": fleet_key.key_id(), "sig_alg": fleet_key.sig_alg(), "usage": "anchor",
              "key_origin": "fleet", "public_key_hex": hex_lower(fleet_key.public()) },
            { "key_id": tenant_key.key_id, "sig_alg": "ES256", "usage": "anchor",
              "key_origin": "managed", "public_key_hex": hex_lower(&tenant_key.public) },
        ]
    });
    let manifest = json!({
        "record": "manifest", "format_version": 2, "tenant_id": "acme",
        "counts": { "audit": 0, "ai_audit": 5, "ai_signed": 5, "anchors": 2 },
        "signing_key_ids": [fleet_key.key_id(), tenant_key.key_id],
        "genesis_handoff": { "handoff_cursor_id": 5, "sovereign_first_from_id": 6 },
    });

    vec![
        header,
        signing_keys,
        r1,
        r2,
        r3,
        r6,
        r7,
        fleet_anchor,
        tenant_anchor,
        manifest,
    ]
}

fn to_jsonl(records: &[Value]) -> String {
    records
        .iter()
        .map(|r| serde_json::to_string(r).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
}

fn check(report: &Report, name: &str) -> bool {
    report
        .findings
        .iter()
        .find(|f| f.check == name)
        .map(|f| f.ok)
        .unwrap_or_else(|| panic!("no finding named {name}; findings: {:?}", report.findings))
}

// ── The valid pack passes every check ────────────────────────────────

#[test]
fn valid_pack_passes_all_checks() {
    let report = verify(&to_jsonl(&build_records()));
    assert!(
        report.passed(),
        "valid pack must pass; findings: {:?}",
        report.findings
    );
}

// ── Each tamper trips exactly the right check ─────────────────────────

#[test]
fn tampered_row_payload_trips_integrity() {
    let mut recs = build_records();
    // Index 2 is row id 1. Forge its payload; its recorded hash now mismatches.
    recs[2]["payload"] = json!(r#"{"v":1,"request_id":"FORGED","tenant_id":"acme"}"#);
    let report = verify(&to_jsonl(&recs));
    assert!(
        !check(&report, "row_integrity"),
        "forged payload must fail integrity"
    );
    assert!(!report.passed());
}

#[test]
fn corrupted_row_signature_trips_row_signature() {
    let mut recs = build_records();
    // Flip the row signature to a valid-hex but wrong value.
    recs[2]["signature"] = json!("00".repeat(64));
    let report = verify(&to_jsonl(&recs));
    assert!(!check(&report, "row_signature"), "bad row sig must fail");
    assert!(!report.passed());
}

#[test]
fn corrupted_anchor_signature_trips_anchor_signature() {
    let mut recs = build_records();
    // Index 7 is the fleet anchor. Corrupt its signature.
    recs[7]["signature"] = json!("11".repeat(64));
    let report = verify(&to_jsonl(&recs));
    assert!(
        !check(&report, "anchor_signature"),
        "bad anchor sig must fail"
    );
    assert!(!report.passed());
}

#[test]
fn tampered_sovereign_root_trips_recompute() {
    let mut recs = build_records();
    // Index 8 is the tenant anchor. Swap in a different (well-formed) root.
    recs[8]["merkle_root"] = json!(hex_lower(&sha256(b"not-the-real-root")));
    let report = verify(&to_jsonl(&recs));
    assert!(
        !check(&report, "sovereign_recompute"),
        "wrong sovereign root must fail recompute"
    );
    assert!(!report.passed());
}

#[test]
fn tampered_inclusion_path_trips_fleet_inclusion() {
    let mut recs = build_records();
    // Index 2 is fleet row id 1. Corrupt the first sibling on its proof path.
    recs[2]["inclusion_proof"]["path"][0] = json!(hex_lower(&sha256(b"forged-sibling")));
    let report = verify(&to_jsonl(&recs));
    assert!(
        !check(&report, "fleet_inclusion"),
        "bad inclusion path must fail"
    );
    assert!(!report.passed());
}

#[test]
fn missing_manifest_trips_structure() {
    let mut recs = build_records();
    recs.pop(); // drop the terminal manifest → truncated pack
    let report = verify(&to_jsonl(&recs));
    assert!(
        !check(&report, "structure.manifest_terminal"),
        "no manifest must fail"
    );
    assert!(!report.passed());
}

#[test]
fn broken_seam_trips_genesis_seam() {
    let mut recs = build_records();
    // Move the handoff cursor to 6 so sovereign row id 6 should be on the fleet
    // chain — a seam contradiction.
    recs[9]["genesis_handoff"]["handoff_cursor_id"] = json!(6);
    let report = verify(&to_jsonl(&recs));
    assert!(
        !check(&report, "genesis_seam"),
        "seam contradiction must fail"
    );
    assert!(!report.passed());
}

// ── ML-DSA-87 (CNSA 2.0 posture) packs ────────────────────────────────

#[test]
fn ml_dsa_87_fleet_anchor_pack_passes_all_checks() {
    let recs = build_records_with(FleetAnchorKey::MlDsa87(
        Box::new(MlDsa87TestKey::generate()),
    ));
    let report = verify(&to_jsonl(&recs));
    assert!(
        report.passed(),
        "valid ML-DSA-87 pack must pass; findings: {:?}",
        report.findings
    );
}

#[test]
fn tampered_ml_dsa_87_anchor_trips_anchor_signature() {
    let mut recs = build_records_with(FleetAnchorKey::MlDsa87(
        Box::new(MlDsa87TestKey::generate()),
    ));
    // Index 7 is the fleet anchor. Widen its signed window by one row: the
    // real ML-DSA-87 signature no longer covers the rebuilt payload hash.
    recs[7]["to_id"] = json!(6);
    let report = verify(&to_jsonl(&recs));
    assert!(
        !check(&report, "anchor_signature"),
        "tampered ML-DSA-87 anchor must fail its signature check"
    );
    assert!(!report.passed());
}

#[test]
fn unknown_sig_alg_fails_closed() {
    let mut recs = build_records();
    // An algorithm this verifier does not implement must be a FAIL, never a
    // skip: a pack cannot pass on the strength of a check that never ran.
    recs[7]["sig_alg"] = json!("FALCON-1024");
    let report = verify(&to_jsonl(&recs));
    assert!(
        !check(&report, "anchor_signature"),
        "unknown sig_alg must fail closed"
    );
    assert!(!report.passed());
}

#[test]
fn miscounted_manifest_trips_counts() {
    let mut recs = build_records();
    recs[9]["counts"]["ai_audit"] = json!(99);
    let report = verify(&to_jsonl(&recs));
    assert!(
        !check(&report, "structure.counts"),
        "wrong counts must fail"
    );
    assert!(!report.passed());
}
