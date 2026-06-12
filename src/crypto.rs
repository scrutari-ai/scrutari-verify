//! Verification primitives over aws-lc-rs (Ed25519, ES256, SHA-256) and
//! fips204 (ML-DSA-87).
//!
//! These functions are vendored verbatim from the crypto module the Scrutari
//! gateway signs with, so a PASS from this verifier is byte-for-byte the same
//! math the gateway performed. Only the verify-side surface is included: no
//! signing, no key generation, no private-key handling of any kind.
//!
//! # Merkle tree shape
//!
//! The tree is a domain-separated binary Merkle tree in the style of RFC 6962
//! (Certificate Transparency): a leaf is hashed with a `0x00` tag, an internal
//! node with a `0x01` tag. The tags put leaf and node hashes in disjoint
//! domains, which blocks the classic second-preimage attack (presenting an
//! internal node as if it were a leaf). A lone trailing node at any level is
//! promoted unchanged (not duplicated). Leaf order is significant and fixed by
//! the exporter as `(created_at, id)`.

use aws_lc_rs::digest;
use aws_lc_rs::signature::{self, UnparsedPublicKey};

/// Verify an Ed25519 `signature` over `message` with a raw 32-byte
/// `public_key`. Returns `true` iff the signature is valid. Intentionally
/// boolean: callers branch on validity, they do not need backend error detail.
pub fn verify_ed25519(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    UnparsedPublicKey::new(&signature::ED25519, public_key)
        .verify(message, signature)
        .is_ok()
}

/// Verify an ES256 (ECDSA P-256 + SHA-256) `signature` over `message` with an
/// uncompressed SEC1 `public_key` (`0x04 || x || y`, 65 bytes). The signature
/// is the raw 64-byte IEEE P1363 `r || s` encoding, not ASN.1/DER. The
/// algorithm hashes `message` with SHA-256 internally, so callers pass the raw
/// signed bytes, never a pre-computed digest.
pub fn verify_es256(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, public_key)
        .verify(message, signature)
        .is_ok()
}

/// FIPS 204 context string for every ML-DSA-87 signature the gateway
/// produces: empty. A verifier must supply the same context bytes or
/// verification fails, so this constant mirrors the signing side exactly.
const ML_DSA_87_CTX: &[u8] = &[];

/// Verify an ML-DSA-87 (FIPS 204, Category 5) `signature` over `message`.
///
/// `public_key` is the raw 2592-byte FIPS 204 public-key encoding (no
/// PKCS#8 or other container, exactly as the pack's `public_key_hex`
/// decodes); `signature` is the raw 4627-byte FIPS 204 signature encoding.
/// The gateway signs anchor payload hashes with this scheme under its
/// CNSA 2.0 posture (`sig_alg` `"ML-DSA-87"`), passing the 32-byte SHA-256
/// payload hash as the message with the empty context above, so callers
/// here pass the same payload-hash bytes the classical arms receive.
/// Returns `true` iff the signature is valid; wrong-length inputs are a
/// clean `false`, never a panic, matching [`verify_ed25519`] /
/// [`verify_es256`]'s boolean posture.
pub fn verify_ml_dsa_87(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    use fips204::ml_dsa_87::{PK_LEN, PublicKey, SIG_LEN};
    use fips204::traits::{SerDes, Verifier};

    if public_key.len() != PK_LEN || signature.len() != SIG_LEN {
        return false;
    }
    let mut pk_arr = [0u8; PK_LEN];
    pk_arr.copy_from_slice(public_key);
    let pk = match PublicKey::try_from_bytes(pk_arr) {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    let mut sig_arr = [0u8; SIG_LEN];
    sig_arr.copy_from_slice(signature);
    pk.verify(message, &sig_arr, ML_DSA_87_CTX)
}

/// SHA-256 of `bytes` via aws-lc-rs, returned as a fixed 32-byte array.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let computed = digest::digest(&digest::SHA256, bytes);
    let mut out = [0u8; 32];
    // SHA-256 is always 32 bytes, so the lengths match by construction.
    out.copy_from_slice(computed.as_ref());
    out
}

/// Lower-hex encode `bytes` without pulling in a hex crate. Used for key ids
/// and for comparing recomputed digests against the hex fields a pack carries.
pub fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}

/// Domain tag prefixed before a leaf's data when hashing.
const MERKLE_LEAF_TAG: u8 = 0x00;
/// Domain tag prefixed before a node's two children when hashing.
const MERKLE_NODE_TAG: u8 = 0x01;

/// Compute the Merkle root over `leaves` (each a 32-byte row hash).
///
/// Leaf order is significant — the caller fixes it (the exporter orders by
/// `(created_at, id)`), so the root is deterministic for a given ordered
/// batch. An empty input returns `SHA-256("")`, the conventional empty-tree
/// root; in practice an exported anchor never covers an empty batch.
pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return sha256(&[]);
    }

    let mut level: Vec<[u8; 32]> = leaves.iter().map(leaf_hash).collect();
    while level.len() > 1 {
        let mut next: Vec<[u8; 32]> = Vec::new();
        let mut index = 0;
        while index < level.len() {
            match (level.get(index), level.get(index + 1)) {
                (Some(left), Some(right)) => {
                    next.push(node_hash(left, right));
                    index += 2;
                }
                // Lone trailing node: promote unchanged (RFC 6962).
                (Some(left), None) => {
                    next.push(*left);
                    index += 1;
                }
                // `index < level.len()` guarantees a left child exists.
                (None, _) => break,
            }
        }
        level = next;
    }

    // The loop reduces a non-empty `level` to exactly one element. The
    // default is unreachable for non-empty input (the empty case returned
    // early above) but keeps the function total and panic-free.
    level.first().copied().unwrap_or_else(|| sha256(&[]))
}

/// Generate the Merkle inclusion (audit) path for the leaf at `index` in the
/// tree [`merkle_root`] builds over `leaves` — same domain tags and lone-node
/// promotion. Feeding the result to [`merkle_inclusion_verify`] with the same
/// `index` and `leaves.len()` folds back to the root.
///
/// The verifier itself only consumes proofs; this generator is included so the
/// test suite (and any third party building conformance fixtures) can produce
/// proofs with exactly the tree shape the exporter uses. Returns an empty path
/// for a single-leaf tree (the root IS the leaf hash) and for an out-of-range
/// index (there is no such leaf).
pub fn merkle_audit_path(leaves: &[[u8; 32]], index: usize) -> Vec<[u8; 32]> {
    if index >= leaves.len() {
        return Vec::new();
    }
    let mut level: Vec<[u8; 32]> = leaves.iter().map(leaf_hash).collect();
    let mut idx = index;
    let mut path: Vec<[u8; 32]> = Vec::new();
    while level.len() > 1 {
        let mut next: Vec<[u8; 32]> = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            match (level.get(i), level.get(i + 1)) {
                (Some(left), Some(right)) => {
                    if i == idx {
                        path.push(*right);
                    } else if i + 1 == idx {
                        path.push(*left);
                    }
                    next.push(node_hash(left, right));
                    i += 2;
                }
                // Lone trailing node promoted unchanged — contributes no sibling.
                (Some(left), None) => {
                    next.push(*left);
                    i += 1;
                }
                (None, _) => break,
            }
        }
        idx /= 2;
        level = next;
    }
    path
}

/// Hash a leaf: `SHA-256(0x00 || leaf)`.
fn leaf_hash(leaf: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 33];
    buf[0] = MERKLE_LEAF_TAG;
    buf[1..].copy_from_slice(leaf);
    sha256(&buf)
}

/// Hash an internal node: `SHA-256(0x01 || left || right)`.
fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 65];
    buf[0] = MERKLE_NODE_TAG;
    buf[1..33].copy_from_slice(left);
    buf[33..].copy_from_slice(right);
    sha256(&buf)
}

/// Verify a Merkle inclusion (audit) proof for one leaf in a tree of
/// `leaf_count` leaves built by [`merkle_root`] — same domain tags and same
/// lone-node promotion. `leaf` is the raw 32-byte row hash; `leaf_index` is
/// its 0-based position in the ordered leaf set; `path` is the ordered sibling
/// node hashes from the leaf level upward. Returns `true` iff folding the path
/// reproduces `expected_root` AND the path is exactly the right length (no
/// extra or missing siblings).
///
/// This is the single-leaf proof an export pack carries for a pre-sovereign
/// row: it lets an offline verifier prove the row sits under a signed
/// shared-fleet root without ever seeing another tenant's rows — only opaque
/// sibling hashes on the path are revealed. The same lone-node rule
/// `merkle_root` uses is reproduced here: a left child that is the last node
/// at its level (odd count) is promoted unchanged and contributes no path
/// entry.
pub fn merkle_inclusion_verify(
    leaf: &[u8; 32],
    leaf_index: usize,
    leaf_count: usize,
    path: &[[u8; 32]],
    expected_root: &[u8; 32],
) -> bool {
    // An out-of-range index cannot be a leaf of this tree.
    if leaf_count == 0 || leaf_index >= leaf_count {
        return false;
    }

    let mut current = leaf_hash(leaf);
    let mut index = leaf_index;
    let mut count = leaf_count;
    let mut path_pos: usize = 0;

    while count > 1 {
        if index.is_multiple_of(2) {
            // Left child: it has a right sibling UNLESS it is the lone trailing
            // node at this level (the last node, with an odd count) — which
            // `merkle_root` promotes unchanged, contributing no path entry.
            if index + 1 < count {
                let sibling = match path.get(path_pos) {
                    Some(node) => node,
                    None => return false,
                };
                path_pos += 1;
                current = node_hash(&current, sibling);
            }
        } else {
            // Right child: a left sibling always exists.
            let sibling = match path.get(path_pos) {
                Some(node) => node,
                None => return false,
            };
            path_pos += 1;
            current = node_hash(sibling, &current);
        }
        index /= 2;
        count = count.div_ceil(2);
    }

    // The path must be fully consumed (an over-long path is a malformed proof)
    // and the fold must land exactly on the signed root.
    path_pos == path.len() && &current == expected_root
}

#[cfg(test)]
mod tests {
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{
        ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, Ed25519KeyPair, KeyPair,
    };

    use super::*;

    #[test]
    fn sha256_is_32_bytes_and_distinct() {
        assert_eq!(sha256(b"").len(), 32);
        assert_ne!(sha256(b"a"), sha256(b"b"));
    }

    #[test]
    fn hex_lower_encodes() {
        assert_eq!(hex_lower(&[0x00, 0xff, 0x10]), "00ff10");
        assert_eq!(hex_lower(&[]), "");
    }

    #[test]
    fn ed25519_verify_roundtrip_and_tamper() {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("generate key");
        let key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("load key");
        let public = key.public_key().as_ref().to_vec();
        let message = sha256(b"canonical-audit-payload");
        let signature = key.sign(&message);

        assert!(verify_ed25519(&public, &message, signature.as_ref()));
        let tampered = sha256(b"canonical-audit-payload-edited");
        assert!(
            !verify_ed25519(&public, &tampered, signature.as_ref()),
            "a signature must not verify against a tampered message"
        );
    }

    #[test]
    fn es256_verify_roundtrip_and_wrong_key() {
        let rng = SystemRandom::new();
        let make = || {
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                .expect("generate key");
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref())
                .expect("load key")
        };
        let key_a = make();
        let key_b = make();
        let public_a = key_a.public_key().as_ref().to_vec();
        let public_b = key_b.public_key().as_ref().to_vec();
        let message = b"anchor-payload-bytes";
        let signature = key_a.sign(&rng, message).expect("sign");

        assert_eq!(signature.as_ref().len(), 64, "P1363 r||s is 64 bytes");
        assert!(verify_es256(&public_a, message, signature.as_ref()));
        assert!(
            !verify_es256(&public_b, message, signature.as_ref()),
            "a signature must not verify under a different key"
        );
    }

    #[test]
    fn ml_dsa_87_verify_roundtrip_tamper_and_wrong_lengths() {
        use fips204::ml_dsa_87::{SIG_LEN, try_keygen};
        use fips204::traits::{SerDes, Signer};

        let (pk, sk) = try_keygen().expect("generate ml-dsa-87 key");
        let public = pk.into_bytes().to_vec();
        // Same sign input as the gateway's CNSA 2.0 anchor path: the
        // 32-byte SHA-256 payload hash, empty FIPS 204 context.
        let message = sha256(b"canonical-anchor-payload");
        let signature = sk.try_sign(&message, &[]).expect("ml-dsa-87 sign").to_vec();

        assert_eq!(signature.len(), SIG_LEN, "raw FIPS 204 signature length");
        assert!(verify_ml_dsa_87(&public, &message, &signature));
        let tampered = sha256(b"canonical-anchor-payload-edited");
        assert!(
            !verify_ml_dsa_87(&public, &tampered, &signature),
            "a signature must not verify against a tampered message"
        );
        // Truncated key / signature must be a clean false, never a panic.
        assert!(!verify_ml_dsa_87(
            &public[..public.len() - 1],
            &message,
            &signature
        ));
        assert!(!verify_ml_dsa_87(
            &public,
            &message,
            &signature[..SIG_LEN - 1]
        ));
    }

    #[test]
    fn merkle_single_leaf_is_its_leaf_hash() {
        let leaf = sha256(b"row-1");
        assert_eq!(merkle_root(&[leaf]), leaf_hash(&leaf));
    }

    #[test]
    fn merkle_two_leaves_combine() {
        let first = sha256(b"row-a");
        let second = sha256(b"row-b");
        let expected = node_hash(&leaf_hash(&first), &leaf_hash(&second));
        assert_eq!(merkle_root(&[first, second]), expected);
    }

    #[test]
    fn merkle_is_order_sensitive() {
        // Reordering anchored rows must change the root (the anchor's
        // whole purpose: detect reordering).
        let first = sha256(b"row-a");
        let second = sha256(b"row-b");
        assert_ne!(merkle_root(&[first, second]), merkle_root(&[second, first]));
    }

    #[test]
    fn merkle_odd_count_promotes_lone_node() {
        let leaf_a = sha256(b"a");
        let leaf_b = sha256(b"b");
        let leaf_c = sha256(b"c");
        // Level 1: node(lh(a), lh(b)), lh(c) promoted unchanged.
        // Root: node(node(lh(a), lh(b)), lh(c)).
        let expected = node_hash(
            &node_hash(&leaf_hash(&leaf_a), &leaf_hash(&leaf_b)),
            &leaf_hash(&leaf_c),
        );
        assert_eq!(merkle_root(&[leaf_a, leaf_b, leaf_c]), expected);
    }

    #[test]
    fn merkle_is_deterministic_and_detects_tamper() {
        let leaves = [sha256(b"x"), sha256(b"y"), sha256(b"z"), sha256(b"w")];
        assert_eq!(merkle_root(&leaves), merkle_root(&leaves));

        let mut tampered = leaves;
        tampered[2] = sha256(b"z-edited");
        assert_ne!(
            merkle_root(&leaves),
            merkle_root(&tampered),
            "editing any anchored row must change the root"
        );
    }

    #[test]
    fn inclusion_proof_verifies_every_leaf_across_tree_shapes() {
        // Cover balanced (2,4,8) and lone-node-promoting (1,3,5,7) shapes.
        for &n in &[1usize, 2, 3, 4, 5, 7, 8] {
            let leaves: Vec<[u8; 32]> = (0..n)
                .map(|i| sha256(format!("row-{i}").as_bytes()))
                .collect();
            let root = merkle_root(&leaves);
            for target in 0..n {
                let path = merkle_audit_path(&leaves, target);
                assert!(
                    merkle_inclusion_verify(&leaves[target], target, n, &path, &root),
                    "leaf {target} of {n} must verify against the root"
                );
            }
        }
    }

    #[test]
    fn inclusion_proof_rejects_tampered_leaf_wrong_index_and_bad_path() {
        let leaves: Vec<[u8; 32]> = (0..5).map(|i| sha256(&[i as u8])).collect();
        let root = merkle_root(&leaves);
        let path = merkle_audit_path(&leaves, 2);

        // Correct proof passes.
        assert!(merkle_inclusion_verify(&leaves[2], 2, 5, &path, &root));
        // A tampered leaf no longer lands on the root.
        let tampered = sha256(b"forged");
        assert!(!merkle_inclusion_verify(&tampered, 2, 5, &path, &root));
        // The right leaf at the wrong index folds left/right the wrong way.
        assert!(!merkle_inclusion_verify(&leaves[2], 3, 5, &path, &root));
        // An over-long path (extra sibling) is a malformed proof.
        let mut long_path = path.clone();
        long_path.push(sha256(b"extra"));
        assert!(!merkle_inclusion_verify(
            &leaves[2], 2, 5, &long_path, &root
        ));
        // An out-of-range index can't be a leaf.
        assert!(!merkle_inclusion_verify(&leaves[2], 5, 5, &path, &root));
    }
}
