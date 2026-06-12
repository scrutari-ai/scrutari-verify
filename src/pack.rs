//! Typed view of the v2 export pack (JSONL, one record per line).
//!
//! Each line is a JSON object with a `"record"` discriminator. We model the set
//! as an internally-tagged enum; unknown future record kinds are tolerated via
//! the `Other` catch-all so an older verifier degrades to "ignore + still verify
//! what it understands" rather than hard-failing on a forward-compatible pack.

use serde::Deserialize;

/// One pack line.
#[derive(Debug, Deserialize)]
#[serde(tag = "record", rename_all = "snake_case")]
pub enum Record {
    Header(Header),
    SigningKeys(SigningKeys),
    /// Admin audit-log rows — opaque here (counted, not crypto-verified in v2).
    Audit(serde_json::Value),
    AiAudit(AiAudit),
    Anchor(Anchor),
    Manifest(Manifest),
    /// Forward-compatibility: a record kind this verifier version predates.
    #[serde(other)]
    Other,
}

#[derive(Debug, Deserialize)]
pub struct Header {
    pub format_version: u32,
    pub tenant_id: String,
}

#[derive(Debug, Deserialize)]
pub struct SigningKeys {
    pub keys: Vec<KeyEntry>,
}

#[derive(Debug, Deserialize)]
pub struct KeyEntry {
    pub key_id: String,
    /// `ed25519` | `ES256`.
    pub sig_alg: String,
    /// `row` | `anchor`.
    pub usage: String,
    /// `fleet` | `customer` | `managed`.
    pub key_origin: String,
    pub public_key_hex: String,
}

#[derive(Debug, Deserialize)]
pub struct AiAudit {
    pub id: i64,
    /// RFC 3339; used to reconstruct the `(created_at, id)` Merkle leaf order.
    pub created_at: String,
    /// The EXACT canonical bytes that were hashed (a string, hashed verbatim).
    pub payload: String,
    /// Lower-hex SHA-256 of `payload`.
    pub payload_hash: String,
    #[serde(default)]
    pub signature: Option<String>,
    #[serde(default)]
    pub signing_key_id: Option<String>,
    #[serde(default)]
    pub sig_alg: Option<String>,
    #[serde(default)]
    pub signed: bool,
    pub covered_by: Covered,
    /// Present for fleet (pre-sovereign) rows; absent for sovereign rows.
    #[serde(default)]
    pub inclusion_proof: Option<InclusionProof>,
}

#[derive(Debug, Deserialize)]
pub struct Covered {
    pub anchor_id: i64,
    /// `fleet` | `tenant:<id>`.
    pub chain: String,
}

#[derive(Debug, Deserialize)]
pub struct InclusionProof {
    pub leaf_index: usize,
    pub leaf_count: usize,
    /// Ordered sibling node hashes (lower-hex) from the leaf level upward.
    pub path: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct Anchor {
    pub id: i64,
    /// `fleet` | `tenant:<id>`.
    pub chain: String,
    pub from_id: i64,
    pub to_id: i64,
    pub row_count: i64,
    pub merkle_root: String,
    #[serde(default)]
    pub prev_anchor_id: Option<i64>,
    #[serde(default)]
    pub prev_root: Option<String>,
    pub signature: String,
    pub signing_key_id: String,
    pub sig_alg: String,
}

#[derive(Debug, Deserialize)]
pub struct Manifest {
    pub format_version: u32,
    pub tenant_id: String,
    pub counts: Counts,
    #[serde(default)]
    pub signing_key_ids: Vec<String>,
    #[serde(default)]
    pub genesis_handoff: Option<GenesisHandoff>,
}

#[derive(Debug, Deserialize)]
pub struct Counts {
    pub audit: u64,
    pub ai_audit: u64,
    pub ai_signed: u64,
    pub anchors: u64,
}

#[derive(Debug, Deserialize)]
pub struct GenesisHandoff {
    pub handoff_cursor_id: i64,
    pub sovereign_first_from_id: i64,
}
