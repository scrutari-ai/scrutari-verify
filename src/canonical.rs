//! Re-derive the exact bytes the exporter signed for an anchor.
//!
//! This MUST match the signing side byte-for-byte: the same struct, the same
//! field order, the same `serde_json::to_string`, then SHA-256. `Option::None`
//! serialises to `null` (no `skip_serializing_if`), matching the signer. If
//! this drifts, every anchor-signature check fails — which is the point: the
//! format is pinned.

use serde::Serialize;

use crate::crypto::sha256;

/// Schema version stamped into the signed anchor payload (matches the value
/// the signing side stamps).
pub const ANCHOR_PAYLOAD_VERSION: u8 = 1;

/// Canonical, signable projection of one anchor. Field order is significant —
/// serde emits declaration order, and the signer hashed exactly these bytes.
#[derive(Serialize)]
struct AnchorPayload<'a> {
    v: u8,
    from_id: i64,
    to_id: i64,
    row_count: i64,
    merkle_root: &'a str,
    prev_anchor_id: Option<i64>,
    prev_root: Option<&'a str>,
}

/// Rebuild the anchor's signed payload hash from the values an export pack
/// carries. Returns the 32-byte SHA-256 of the canonical JSON (the value the
/// anchor signature is over).
pub fn anchor_payload_hash(
    from_id: i64,
    to_id: i64,
    row_count: i64,
    merkle_root_hex: &str,
    prev_anchor_id: Option<i64>,
    prev_root_hex: Option<&str>,
) -> Result<[u8; 32], String> {
    let payload = AnchorPayload {
        v: ANCHOR_PAYLOAD_VERSION,
        from_id,
        to_id,
        row_count,
        merkle_root: merkle_root_hex,
        prev_anchor_id,
        prev_root: prev_root_hex,
    };
    let canonical =
        serde_json::to_string(&payload).map_err(|e| format!("serialize anchor payload: {e}"))?;
    Ok(sha256(canonical.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_shape_is_pinned() {
        // Genesis anchor (no prev): null links, fixed field order.
        let payload = AnchorPayload {
            v: 1,
            from_id: 1,
            to_id: 10,
            row_count: 10,
            merkle_root: "abcd",
            prev_anchor_id: None,
            prev_root: None,
        };
        let json = serde_json::to_string(&payload).unwrap();
        assert_eq!(
            json,
            r#"{"v":1,"from_id":1,"to_id":10,"row_count":10,"merkle_root":"abcd","prev_anchor_id":null,"prev_root":null}"#
        );
    }

    #[test]
    fn hash_is_sha256_of_canonical() {
        let h = anchor_payload_hash(1, 10, 10, "abcd", Some(7), Some("ef01")).unwrap();
        let expected = sha256(
            r#"{"v":1,"from_id":1,"to_id":10,"row_count":10,"merkle_root":"abcd","prev_anchor_id":7,"prev_root":"ef01"}"#
                .as_bytes(),
        );
        assert_eq!(h, expected);
    }
}
