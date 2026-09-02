//! chain/v1 pack verification — hash-CHAINED audit tables
//! (control_plane_audit_log, scrutari-auth's authz_decision_log), anchored
//! by the chain_anchor_worker.
//!
//! A chain pack differs from an RFC-008 v2 (Merkle) pack in what carries
//! the integrity: every row's `entry_hash` is SHA-256(prev_hash ||
//! canonical_row), so the pack is verified by RECOMPUTING the chain end to
//! end, then checking each signed anchor against the head it attests.
//! Because `entry_hash` transitively commits to every prior row, one valid
//! anchor signature attests the entire prefix below it.
//!
//! Checks, in order:
//!
//! 1. **Structure** — parse JSONL; require a chain/v1 `header` + terminal
//!    `manifest`; reconcile counts; load `signing_keys` by `key_id`.
//! 2. **Row recompute** — for every row, `entry_hash ==
//!    SHA-256(prev_hash || canonical)` (the exact trigger computation).
//! 3. **Linkage** — rows ordered by `chain_seq` are gapless, start at the
//!    genesis marker (`prev_hash = 00`, seq 1) and every row's `prev_hash`
//!    equals its predecessor's `entry_hash`. A fork cannot pass this.
//! 4. **Anchor signatures** — rebuild the canonical `ChainAnchorPayload`
//!    (which pins `kind` + `table`, so signatures cannot be replayed
//!    across protocols or tables) → SHA-256 → verify by `sig_alg`
//!    (`ed25519` / `ES256` / `ML-DSA-87`).
//! 5. **Head binding** — each anchor's `chain_head` equals the
//!    `entry_hash` of the pack row at its `to_seq`; anchor ranges tile the
//!    pack contiguously (`from_seq` = previous `to_seq` + 1, first = 1).
//! 6. **Anchor continuity** — `prev_anchor_id` / `prev_head` chain each
//!    anchor to its predecessor, making the anchor sequence itself signed.
//! 7. **Coverage** — every exported row up to the last anchor is inside
//!    exactly one anchored range; rows past the last anchor must match the
//!    manifest's declared `unanchored_tail` (reported, not silently
//!    accepted).
//!
//! This module deliberately duplicates the worker's payload struct — the
//! same pinning-by-duplication `canonical.rs` uses for the Merkle anchor
//! payload. If the shapes drift, every signature check fails, which is the
//! point.

use std::collections::HashMap;

use crate::crypto::{hex_lower, sha256, verify_ed25519, verify_es256, verify_ml_dsa_87};
use serde::{Deserialize, Serialize};

use crate::hexutil;
use crate::verify::Report;

/// Mirrors the worker's `CHAIN_ANCHOR_PAYLOAD_VERSION`.
pub const CHAIN_ANCHOR_PAYLOAD_VERSION: u8 = 1;

/// Mirrors the worker's `CHAIN_ANCHOR_KIND`.
pub const CHAIN_ANCHOR_KIND: &str = "chain_head";

/// The profile tag a chain/v1 header carries.
pub const CHAIN_PACK_PROFILE: &str = "chain/v1";

/// Canonical, signable projection of one chain anchor. MUST match the
/// worker's `ChainAnchorPayload` byte-for-byte: same struct, same field
/// order, same `serde_json::to_string`, then SHA-256.
#[derive(Serialize)]
struct ChainAnchorPayload<'a> {
    v: u8,
    kind: &'a str,
    table: &'a str,
    from_seq: i64,
    to_seq: i64,
    row_count: i64,
    chain_head: &'a str,
    prev_anchor_id: Option<i64>,
    prev_head: Option<&'a str>,
}

/// Rebuild the signed payload hash from the values a chain pack carries.
pub fn chain_anchor_payload_hash(
    table: &str,
    from_seq: i64,
    to_seq: i64,
    row_count: i64,
    chain_head_hex: &str,
    prev_anchor_id: Option<i64>,
    prev_head_hex: Option<&str>,
) -> Result<[u8; 32], String> {
    let payload = ChainAnchorPayload {
        v: CHAIN_ANCHOR_PAYLOAD_VERSION,
        kind: CHAIN_ANCHOR_KIND,
        table,
        from_seq,
        to_seq,
        row_count,
        chain_head: chain_head_hex,
        prev_anchor_id,
        prev_head: prev_head_hex,
    };
    let canonical = serde_json::to_string(&payload)
        .map_err(|e| format!("serialize chain anchor payload: {e}"))?;
    Ok(sha256(canonical.as_bytes()))
}

// ── chain/v1 pack records ────────────────────────────────────────────

/// One chain-pack line.
#[derive(Debug, Deserialize)]
#[serde(tag = "record", rename_all = "snake_case")]
pub enum ChainRecord {
    Header(ChainHeader),
    SigningKeys(ChainSigningKeys),
    ChainRow(ChainRow),
    ChainAnchor(ChainAnchor),
    Manifest(ChainManifest),
    /// Forward-compatibility: a record kind this verifier version predates.
    #[serde(other)]
    Other,
}

#[derive(Debug, Deserialize)]
pub struct ChainHeader {
    pub format_version: u32,
    pub profile: String,
    pub table: String,
}

#[derive(Debug, Deserialize)]
pub struct ChainSigningKeys {
    pub keys: Vec<ChainKeyEntry>,
}

#[derive(Debug, Deserialize)]
pub struct ChainKeyEntry {
    pub key_id: String,
    /// `ed25519` | `ES256` | `ML-DSA-87`.
    pub sig_alg: String,
    /// `anchor` (chain packs carry no per-row signatures — the chain is
    /// the row integrity).
    pub usage: String,
    /// `product` | `fleet` | `customer` | `managed`.
    pub key_origin: String,
    pub public_key_hex: String,
}

#[derive(Debug, Deserialize)]
pub struct ChainRow {
    pub chain_seq: i64,
    /// Lower-hex; `00` on the genesis row.
    pub prev_hash: String,
    /// Lower-hex SHA-256.
    pub entry_hash: String,
    /// The EXACT canonical bytes the trigger hashed (hashed verbatim).
    pub canonical: String,
}

#[derive(Debug, Deserialize)]
pub struct ChainAnchor {
    pub id: i64,
    pub from_seq: i64,
    pub to_seq: i64,
    pub row_count: i64,
    /// Lower-hex entry_hash of the row at `to_seq`.
    pub chain_head: String,
    #[serde(default)]
    pub prev_anchor_id: Option<i64>,
    #[serde(default)]
    pub prev_head: Option<String>,
    pub signature: String,
    pub signing_key_id: String,
    pub sig_alg: String,
}

#[derive(Debug, Deserialize)]
pub struct ChainManifest {
    pub format_version: u32,
    pub profile: String,
    pub table: String,
    pub counts: ChainCounts,
    #[serde(default)]
    pub seq_range: Option<(i64, i64)>,
    #[serde(default)]
    pub unanchored_tail: u64,
    #[serde(default)]
    pub signing_key_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct ChainCounts {
    pub rows: u64,
    pub anchors: u64,
}

/// Does this JSONL look like a chain/v1 pack? (Cheap first-line probe used
/// by the CLI to dispatch between the two verification engines.)
pub fn is_chain_pack(jsonl: &str) -> bool {
    for line in jsonl.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        return match serde_json::from_str::<serde_json::Value>(trimmed) {
            Ok(value) => value.get("profile").and_then(|p| p.as_str()) == Some(CHAIN_PACK_PROFILE),
            Err(_) => false,
        };
    }
    false
}

/// Verify a chain/v1 JSONL pack. Never panics — every error becomes a
/// failed finding.
pub fn verify_chain(jsonl: &str) -> Report {
    let mut report = Report::default();

    // ── Parse ────────────────────────────────────────────────────────
    let mut header: Option<ChainHeader> = None;
    let mut keys: Vec<ChainKeyEntry> = Vec::new();
    let mut rows: Vec<ChainRow> = Vec::new();
    let mut anchors: Vec<ChainAnchor> = Vec::new();
    let mut manifest: Option<ChainManifest> = None;
    let mut parse_errors: Vec<String> = Vec::new();
    let mut last_was_manifest = false;

    for (lineno, line) in jsonl.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut this_is_manifest = false;
        match serde_json::from_str::<ChainRecord>(trimmed) {
            Ok(ChainRecord::Header(h)) => {
                if header.is_none() {
                    header = Some(h);
                }
            }
            Ok(ChainRecord::SigningKeys(s)) => keys.extend(s.keys),
            Ok(ChainRecord::ChainRow(r)) => rows.push(r),
            Ok(ChainRecord::ChainAnchor(a)) => anchors.push(a),
            Ok(ChainRecord::Manifest(m)) => {
                manifest = Some(m);
                this_is_manifest = true;
            }
            Ok(ChainRecord::Other) => {}
            Err(e) => parse_errors.push(format!("line {}: {e}", lineno + 1)),
        }
        last_was_manifest = this_is_manifest;
    }

    // ── Check 1: structure ───────────────────────────────────────────
    report.record(
        "structure.parse",
        parse_errors.is_empty(),
        if parse_errors.is_empty() {
            "all lines parsed".to_string()
        } else {
            format!(
                "{} malformed line(s): {}",
                parse_errors.len(),
                trunc(&parse_errors)
            )
        },
    );
    let table: String = match &header {
        Some(h) if h.format_version == 1 && h.profile == CHAIN_PACK_PROFILE => {
            report.ok(
                "structure.header",
                format!("chain/v1 header, table {}", h.table),
            );
            h.table.clone()
        }
        Some(h) => {
            report.fail(
                "structure.header",
                format!(
                    "unexpected format_version {} / profile '{}'",
                    h.format_version, h.profile
                ),
            );
            h.table.clone()
        }
        None => {
            report.fail("structure.header", "missing chain/v1 header record");
            String::new()
        }
    };
    report.record(
        "structure.manifest_terminal",
        manifest.is_some() && last_was_manifest,
        match (&manifest, last_was_manifest) {
            (Some(_), true) => "terminal manifest present (pack not truncated)".to_string(),
            (Some(_), false) => {
                "manifest present but not the last line (possible truncation)".to_string()
            }
            (None, _) => "no manifest line — pack is truncated or incomplete".to_string(),
        },
    );
    if let Some(m) = &manifest {
        let counts_ok = m.counts.rows == rows.len() as u64
            && m.counts.anchors == anchors.len() as u64
            && m.table == table
            && m.profile == CHAIN_PACK_PROFILE;
        report.record(
            "structure.counts",
            counts_ok,
            format!(
                "manifest {{rows:{}, anchors:{}, table:{}}} vs actual {{rows:{}, anchors:{}, table:{}}}",
                m.counts.rows,
                m.counts.anchors,
                m.table,
                rows.len(),
                anchors.len(),
                table
            ),
        );
    }
    {
        let mut bad: Vec<String> = Vec::new();
        for k in &keys {
            if k.usage != "anchor" {
                bad.push(format!("key {} unknown usage '{}'", k.key_id, k.usage));
            }
            if !matches!(
                k.key_origin.as_str(),
                "product" | "fleet" | "customer" | "managed"
            ) {
                bad.push(format!(
                    "key {} unknown key_origin '{}'",
                    k.key_id, k.key_origin
                ));
            }
            if hexutil::decode(&k.public_key_hex).is_err() {
                bad.push(format!("key {} public_key_hex is not valid hex", k.key_id));
            }
        }
        report.record(
            "signing_keys",
            bad.is_empty(),
            if bad.is_empty() {
                format!("{} key(s) well-formed", keys.len())
            } else {
                trunc(&bad)
            },
        );
    }

    let key_by_id: HashMap<&str, &ChainKeyEntry> =
        keys.iter().map(|k| (k.key_id.as_str(), k)).collect();

    // Rows in chain order for everything below.
    rows.sort_by_key(|r| r.chain_seq);

    // ── Check 2 + 3: row recompute and linkage ───────────────────────
    {
        let mut recompute_bad: Vec<String> = Vec::new();
        let mut linkage_bad: Vec<String> = Vec::new();
        let mut expected_seq = rows.first().map(|r| r.chain_seq);
        // A pack normally starts at genesis (seq 1, prev 00); a windowed
        // pack starting mid-chain is a boundary note, not a failure.
        let mut boundary: Vec<String> = Vec::new();
        if let Some(first) = rows.first() {
            if first.chain_seq == 1 {
                if first.prev_hash != "00" {
                    linkage_bad.push(format!(
                        "genesis row (seq 1) prev_hash '{}' \u{2260} '00'",
                        first.prev_hash
                    ));
                }
            } else {
                boundary.push(format!(
                    "pack starts at chain_seq {} (windowed export)",
                    first.chain_seq
                ));
            }
        }
        let mut prev_entry_hex: Option<String> = None;
        for r in &rows {
            match expected_seq {
                Some(expected) if r.chain_seq == expected => {}
                Some(expected) => {
                    linkage_bad.push(format!(
                        "chain_seq gap: expected {expected}, found {}",
                        r.chain_seq
                    ));
                }
                None => {}
            }
            expected_seq = Some(r.chain_seq + 1);

            // Recompute: entry = SHA-256(prev || canonical) — exactly the
            // trigger's computation, from the pack's own bytes.
            match hexutil::decode(&r.prev_hash) {
                Ok(prev_bytes) => {
                    let mut message: Vec<u8> = prev_bytes;
                    message.extend_from_slice(r.canonical.as_bytes());
                    let recomputed = hex_lower(&sha256(&message));
                    if !recomputed.eq_ignore_ascii_case(&r.entry_hash) {
                        recompute_bad.push(format!("seq {}", r.chain_seq));
                    }
                }
                Err(e) => recompute_bad.push(format!("seq {} (prev_hash hex: {e})", r.chain_seq)),
            }

            let breaks_link = prev_entry_hex
                .as_deref()
                .is_some_and(|prev_hex| !r.prev_hash.eq_ignore_ascii_case(prev_hex));
            if breaks_link {
                linkage_bad.push(format!(
                    "prev-link break at seq {}: prev_hash != predecessor entry_hash",
                    r.chain_seq
                ));
            }
            prev_entry_hex = Some(r.entry_hash.clone());
        }
        report.record(
            "row_recompute",
            recompute_bad.is_empty(),
            if recompute_bad.is_empty() {
                format!("{} row(s) recompute from their canonical bytes", rows.len())
            } else {
                format!("entry_hash mismatches: {}", trunc(&recompute_bad))
            },
        );
        let linkage_detail = if linkage_bad.is_empty() {
            if boundary.is_empty() {
                "chain links cleanly end to end".to_string()
            } else {
                format!("chain links cleanly; boundary notes: {}", trunc(&boundary))
            }
        } else {
            format!("linkage breaks: {}", trunc(&linkage_bad))
        };
        report.record("linkage", linkage_bad.is_empty(), linkage_detail);
    }

    let entry_by_seq: HashMap<i64, &str> = rows
        .iter()
        .map(|r| (r.chain_seq, r.entry_hash.as_str()))
        .collect();

    // ── Check 4: anchor signatures ───────────────────────────────────
    {
        let mut bad: Vec<String> = Vec::new();
        for a in &anchors {
            match anchor_signature_ok(a, &table, &key_by_id) {
                Ok(()) => {}
                Err(why) => bad.push(format!("anchor {} ({why})", a.id)),
            }
        }
        report.record(
            "anchor_signature",
            bad.is_empty(),
            if bad.is_empty() {
                format!("{} anchor signature(s) verified", anchors.len())
            } else {
                format!("anchor failures: {}", trunc(&bad))
            },
        );
    }

    // ── Check 5: head binding + range tiling ─────────────────────────
    {
        let mut bad: Vec<String> = Vec::new();
        let mut sorted: Vec<&ChainAnchor> = anchors.iter().collect();
        sorted.sort_by_key(|a| a.id);
        let mut expected_from: Option<i64> = rows.first().map(|r| r.chain_seq);
        for a in &sorted {
            if a.row_count != a.to_seq - a.from_seq + 1 {
                bad.push(format!(
                    "anchor {} row_count {} != range width {}",
                    a.id,
                    a.row_count,
                    a.to_seq - a.from_seq + 1
                ));
            }
            match expected_from {
                Some(expected) if a.from_seq == expected => {}
                Some(expected) => bad.push(format!(
                    "anchor {} from_seq {} does not tile (expected {expected})",
                    a.id, a.from_seq
                )),
                None => {}
            }
            expected_from = Some(a.to_seq + 1);
            match entry_by_seq.get(&a.to_seq) {
                Some(entry_hex) => {
                    if !a.chain_head.eq_ignore_ascii_case(entry_hex) {
                        bad.push(format!(
                            "anchor {} chain_head != entry_hash of row {}",
                            a.id, a.to_seq
                        ));
                    }
                }
                None => bad.push(format!(
                    "anchor {} covers to_seq {} but that row is not in the pack",
                    a.id, a.to_seq
                )),
            }
        }
        report.record(
            "head_binding",
            bad.is_empty(),
            if bad.is_empty() {
                format!(
                    "{} anchor(s) bind to their pack rows and tile the range",
                    anchors.len()
                )
            } else {
                format!("head-binding failures: {}", trunc(&bad))
            },
        );
    }

    // ── Check 6: anchor continuity ───────────────────────────────────
    {
        let mut bad: Vec<String> = Vec::new();
        let mut notes: Vec<String> = Vec::new();
        let mut sorted: Vec<&ChainAnchor> = anchors.iter().collect();
        sorted.sort_by_key(|a| a.id);
        let by_id: HashMap<i64, &ChainAnchor> = anchors.iter().map(|a| (a.id, a)).collect();
        for (pos, a) in sorted.iter().enumerate() {
            if pos == 0 {
                match a.prev_anchor_id {
                    None => {}
                    Some(pid) if by_id.contains_key(&pid) => {}
                    Some(pid) => notes.push(format!(
                        "first anchor {} links to {pid} outside the pack (boundary)",
                        a.id
                    )),
                }
                continue;
            }
            let prev = sorted[pos - 1];
            if a.prev_anchor_id != Some(prev.id) {
                bad.push(format!(
                    "anchor {} prev_anchor_id {:?} != {}",
                    a.id, a.prev_anchor_id, prev.id
                ));
            }
            let prev_head_ok = a
                .prev_head
                .as_deref()
                .map(|ph| ph.eq_ignore_ascii_case(&prev.chain_head))
                .is_some_and(|ok| ok);
            if !prev_head_ok {
                bad.push(format!(
                    "anchor {} prev_head != anchor {} chain_head",
                    a.id, prev.id
                ));
            }
        }
        let detail = if bad.is_empty() {
            if notes.is_empty() {
                "anchor sequence links cleanly".to_string()
            } else {
                format!(
                    "anchor sequence links cleanly; boundary notes: {}",
                    trunc(&notes)
                )
            }
        } else {
            format!("anchor continuity breaks: {}", trunc(&bad))
        };
        report.record("anchor_continuity", bad.is_empty(), detail);
    }

    // ── Check 7: coverage ────────────────────────────────────────────
    {
        let last_anchored = anchors.iter().map(|a| a.to_seq).max();
        let last_row = rows.last().map(|r| r.chain_seq);
        let declared_tail = manifest.as_ref().map(|m| m.unanchored_tail);
        let (ok, detail) = match (last_anchored, last_row) {
            (Some(anchored), Some(row_head)) if row_head <= anchored => {
                (true, format!("all rows ≤ anchored head {anchored}"))
            }
            (Some(anchored), Some(row_head)) => {
                // Compare in i64 space (Result == Result), which needs
                // neither `.ok()` (disallowed) nor a manual-ok match.
                let tail = row_head - anchored;
                match declared_tail {
                    Some(declared) if i64::try_from(declared) == Ok(tail) => (
                        true,
                        format!(
                            "{tail} row(s) past anchored head {anchored} — declared unanchored_tail (awaiting the next anchor tick)"
                        ),
                    ),
                    _ => (
                        false,
                        format!(
                            "{tail} row(s) past anchored head {anchored} but manifest declares unanchored_tail {declared_tail:?}"
                        ),
                    ),
                }
            }
            (None, Some(_)) => (false, "rows present but no anchor in the pack".to_string()),
            (_, None) => (true, "empty row set".to_string()),
        };
        report.record("coverage", ok, detail);
    }

    report
}

fn anchor_signature_ok(
    a: &ChainAnchor,
    table: &str,
    keys: &HashMap<&str, &ChainKeyEntry>,
) -> Result<(), String> {
    let key = keys
        .get(a.signing_key_id.as_str())
        .ok_or_else(|| format!("no key {} in signing_keys", a.signing_key_id))?;
    let pubkey = hexutil::decode(&key.public_key_hex).map_err(|e| format!("pubkey hex: {e}"))?;
    let sig = hexutil::decode(&a.signature).map_err(|e| format!("signature hex: {e}"))?;
    let payload_hash = chain_anchor_payload_hash(
        table,
        a.from_seq,
        a.to_seq,
        a.row_count,
        &a.chain_head,
        a.prev_anchor_id,
        a.prev_head.as_deref(),
    )?;
    let valid = match a.sig_alg.as_str() {
        "ed25519" => verify_ed25519(&pubkey, &payload_hash, &sig),
        "ES256" => verify_es256(&pubkey, &payload_hash, &sig),
        "ML-DSA-87" => verify_ml_dsa_87(&pubkey, &payload_hash, &sig),
        other => return Err(format!("unknown sig_alg {other}")),
    };
    if valid {
        Ok(())
    } else {
        Err("signature did not verify".to_string())
    }
}

fn trunc(items: &[String]) -> String {
    const MAX: usize = 5;
    if items.len() <= MAX {
        items.join("; ")
    } else {
        format!(
            "{} … (+{} more)",
            items[..MAX].join("; "),
            items.len() - MAX
        )
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods, clippy::disallowed_macros)]
mod tests {
    use super::*;

    #[test]
    fn chain_anchor_canonical_shape_is_pinned() {
        // The exact bytes the worker signs. If this drifts from the
        // worker's ChainAnchorPayload, every anchor signature fails —
        // which is the point: the format is pinned (same discipline as
        // canonical.rs for the Merkle anchor payload).
        let payload = ChainAnchorPayload {
            v: 1,
            kind: CHAIN_ANCHOR_KIND,
            table: "authz_decision_log",
            from_seq: 1,
            to_seq: 3,
            row_count: 3,
            chain_head: "abcd",
            prev_anchor_id: None,
            prev_head: None,
        };
        let json = serde_json::to_string(&payload).unwrap();
        assert_eq!(
            json,
            r#"{"v":1,"kind":"chain_head","table":"authz_decision_log","from_seq":1,"to_seq":3,"row_count":3,"chain_head":"abcd","prev_anchor_id":null,"prev_head":null}"#
        );
    }

    #[test]
    fn kind_and_table_bind_the_signature_domain() {
        // Cross-table / cross-protocol replay is blocked because the
        // signed bytes name both the payload kind and the table.
        let one = chain_anchor_payload_hash("authz_decision_log", 1, 3, 3, "abcd", None, None);
        let two = chain_anchor_payload_hash("control_plane_audit_log", 1, 3, 3, "abcd", None, None);
        assert_ne!(one.unwrap(), two.unwrap());
    }

    #[test]
    fn is_chain_pack_dispatches_on_the_header_profile() {
        assert!(is_chain_pack(
            r#"{"record":"header","format_version":1,"profile":"chain/v1","table":"t","generated_at":"now"}"#
        ));
        // RFC-008 v2 headers have no profile field.
        assert!(!is_chain_pack(
            r#"{"record":"header","format_version":2,"tenant_id":"acme"}"#
        ));
        assert!(!is_chain_pack("not json"));
        assert!(!is_chain_pack(""));
    }
}
