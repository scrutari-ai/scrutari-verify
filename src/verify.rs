//! The verification engine: parse a v2 pack and run the checks.
//!
//! Every check appends a [`Finding`]; the pack PASSES iff every finding is `ok`.
//! All crypto goes through [`crate::crypto`] (the same primitives the signing
//! side uses), so a PASS here is byte-for-byte the same math the signer did.

use std::collections::HashMap;

use serde::Serialize;

use crate::canonical::anchor_payload_hash;
use crate::crypto::{
    hex_lower, merkle_inclusion_verify, merkle_root, sha256, verify_ed25519, verify_es256,
    verify_ml_dsa_87,
};
use crate::hexutil;
use crate::pack::{AiAudit, Anchor, Header, KeyEntry, Manifest, Record};

/// One check's outcome.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub check: String,
    pub ok: bool,
    pub detail: String,
}

/// The whole verification result.
#[derive(Debug, Default)]
pub struct Report {
    pub findings: Vec<Finding>,
}

impl Report {
    /// `true` iff every check passed.
    pub fn passed(&self) -> bool {
        !self.findings.is_empty() && self.findings.iter().all(|f| f.ok)
    }

    fn ok(&mut self, check: &str, detail: impl Into<String>) {
        self.findings.push(Finding {
            check: check.to_string(),
            ok: true,
            detail: detail.into(),
        });
    }

    fn fail(&mut self, check: &str, detail: impl Into<String>) {
        self.findings.push(Finding {
            check: check.to_string(),
            ok: false,
            detail: detail.into(),
        });
    }

    fn record(&mut self, check: &str, ok: bool, detail: impl Into<String>) {
        if ok {
            self.ok(check, detail);
        } else {
            self.fail(check, detail);
        }
    }
}

/// Verify a v2 JSONL pack. Never panics — every error becomes a failed finding.
pub fn verify(jsonl: &str) -> Report {
    let mut report = Report::default();

    // ── Parse ────────────────────────────────────────────────────────
    let mut header: Option<Header> = None;
    let mut keys: Vec<KeyEntry> = Vec::new();
    let mut ai: Vec<AiAudit> = Vec::new();
    let mut anchors: Vec<Anchor> = Vec::new();
    let mut manifest: Option<Manifest> = None;
    let mut audit_count: u64 = 0;
    let mut parse_errors: Vec<String> = Vec::new();
    let mut last_was_manifest = false;

    for (lineno, line) in jsonl.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut this_is_manifest = false;
        match serde_json::from_str::<Record>(trimmed) {
            Ok(Record::Header(h)) => {
                if header.is_none() {
                    header = Some(h);
                }
            }
            Ok(Record::SigningKeys(s)) => keys.extend(s.keys),
            Ok(Record::Audit(_)) => audit_count += 1,
            Ok(Record::AiAudit(r)) => ai.push(r),
            Ok(Record::Anchor(a)) => anchors.push(a),
            Ok(Record::Manifest(m)) => {
                manifest = Some(m);
                this_is_manifest = true;
            }
            Ok(Record::Other) => {}
            Err(e) => parse_errors.push(format!("line {}: {e}", lineno + 1)),
        }
        last_was_manifest = this_is_manifest;
    }

    // ── Check 1: structure + completeness ────────────────────────────
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
    match &header {
        Some(h) if h.format_version == 2 => {
            report.ok(
                "structure.header",
                format!("v2 header, tenant {}", h.tenant_id),
            );
        }
        Some(h) => report.fail(
            "structure.header",
            format!("unexpected format_version {}", h.format_version),
        ),
        None => report.fail("structure.header", "missing v2 header record"),
    }
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
        let signed = ai.iter().filter(|r| r.signed).count() as u64;
        let counts_ok = m.counts.ai_audit == ai.len() as u64
            && m.counts.anchors == anchors.len() as u64
            && m.counts.audit == audit_count
            && m.counts.ai_signed == signed;
        report.record(
            "structure.counts",
            counts_ok,
            format!(
                "manifest counts {{audit:{}, ai_audit:{}, ai_signed:{}, anchors:{}}} vs actual {{audit:{}, ai_audit:{}, ai_signed:{}, anchors:{}}}",
                m.counts.audit, m.counts.ai_audit, m.counts.ai_signed, m.counts.anchors,
                audit_count, ai.len(), signed, anchors.len()
            ),
        );
    }

    // Header / manifest must agree on tenant + version (a mixed-tenant or
    // mixed-version pack is malformed).
    if let (Some(h), Some(m)) = (&header, &manifest) {
        let ok = h.tenant_id == m.tenant_id && m.format_version == 2;
        report.record(
            "structure.identity",
            ok,
            format!(
                "header tenant {} / manifest tenant {} (v{})",
                h.tenant_id, m.tenant_id, m.format_version
            ),
        );
    }

    // signing_keys well-formed: recognised usage + origin, decodable public key.
    {
        let mut bad: Vec<String> = Vec::new();
        for k in &keys {
            if !matches!(k.usage.as_str(), "row" | "anchor") {
                bad.push(format!("key {} unknown usage '{}'", k.key_id, k.usage));
            }
            if !matches!(k.key_origin.as_str(), "fleet" | "customer" | "managed") {
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

    // Index keys + anchors for the crypto checks.
    let key_by_id: HashMap<&str, &KeyEntry> = keys.iter().map(|k| (k.key_id.as_str(), k)).collect();
    let anchor_by_id: HashMap<i64, &Anchor> = anchors.iter().map(|a| (a.id, a)).collect();

    // ── Check 2: per-row integrity (payload_hash == sha256(payload)) ──
    {
        let mut bad: Vec<i64> = Vec::new();
        for r in &ai {
            let computed = hex_lower(&sha256(r.payload.as_bytes()));
            if !computed.eq_ignore_ascii_case(&r.payload_hash) {
                bad.push(r.id);
            }
        }
        report.record(
            "row_integrity",
            bad.is_empty(),
            if bad.is_empty() {
                format!("{} row(s) hash-match their payload", ai.len())
            } else {
                format!("payload_hash mismatch on row id(s) {}", trunc_ids(&bad))
            },
        );
    }

    // ── Check 3: per-row signature (signed rows, Ed25519) ─────────────
    {
        let mut bad: Vec<String> = Vec::new();
        let mut signed = 0usize;
        for r in ai.iter().filter(|r| r.signed) {
            signed += 1;
            match row_signature_ok(r, &key_by_id) {
                Ok(()) => {}
                Err(why) => bad.push(format!("row {} ({why})", r.id)),
            }
        }
        report.record(
            "row_signature",
            bad.is_empty(),
            if bad.is_empty() {
                format!("{signed} signed row(s) verified")
            } else {
                format!("signature failures: {}", trunc(&bad))
            },
        );
    }

    // ── Check 4: anchor signatures + key listed in manifest ───────────
    {
        let listed: std::collections::HashSet<&str> = manifest
            .as_ref()
            .map(|m| m.signing_key_ids.iter().map(String::as_str).collect())
            .unwrap_or_default();
        let mut bad: Vec<String> = Vec::new();
        for a in &anchors {
            match anchor_signature_ok(a, &key_by_id) {
                Ok(()) => {}
                Err(why) => bad.push(format!("anchor {} ({why})", a.id)),
            }
            if !listed.is_empty() && !listed.contains(a.signing_key_id.as_str()) {
                bad.push(format!(
                    "anchor {} key {} not in manifest signing_key_ids",
                    a.id, a.signing_key_id
                ));
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

    // Group rows by covering anchor for the Merkle checks.
    let mut rows_by_anchor: HashMap<i64, Vec<&AiAudit>> = HashMap::new();
    for r in &ai {
        rows_by_anchor
            .entry(r.covered_by.anchor_id)
            .or_default()
            .push(r);
    }

    // ── Check 5: sovereign-chain full Merkle recompute ────────────────
    {
        let mut bad: Vec<String> = Vec::new();
        let mut checked = 0usize;
        for a in anchors.iter().filter(|a| a.chain.starts_with("tenant:")) {
            checked += 1;
            match sovereign_recompute_ok(a, rows_by_anchor.get(&a.id)) {
                Ok(()) => {}
                Err(why) => bad.push(format!("anchor {} ({why})", a.id)),
            }
        }
        report.record(
            "sovereign_recompute",
            bad.is_empty(),
            if bad.is_empty() {
                format!("{checked} sovereign anchor root(s) recomputed")
            } else {
                format!("recompute failures: {}", trunc(&bad))
            },
        );
    }

    // ── Check 6: fleet-chain inclusion proofs ─────────────────────────
    {
        let mut bad: Vec<String> = Vec::new();
        let mut proven = 0usize;
        for r in ai.iter().filter(|r| r.covered_by.chain == "fleet") {
            match fleet_inclusion_ok(r, anchor_by_id.get(&r.covered_by.anchor_id).copied()) {
                Ok(()) => proven += 1,
                Err(why) => bad.push(format!("row {} ({why})", r.id)),
            }
        }
        report.record(
            "fleet_inclusion",
            bad.is_empty(),
            if bad.is_empty() {
                format!("{proven} pre-sovereign row(s) proven included")
            } else {
                format!("inclusion failures: {}", trunc(&bad))
            },
        );
    }

    // ── Check 7: per-chain prev-link continuity ───────────────────────
    continuity_check(&mut report, &anchors, &anchor_by_id);

    // ── Check 8: genesis-handoff seam ─────────────────────────────────
    seam_check(&mut report, &manifest, &ai, &anchors);

    // ── Check 9: coverage (every row references a present anchor) ─────
    {
        let mut bad: Vec<i64> = Vec::new();
        for r in &ai {
            if !anchor_by_id.contains_key(&r.covered_by.anchor_id) {
                bad.push(r.id);
            }
        }
        report.record(
            "coverage",
            bad.is_empty(),
            if bad.is_empty() {
                format!("all {} row(s) covered by a present anchor", ai.len())
            } else {
                format!("rows referencing a missing anchor: {}", trunc_ids(&bad))
            },
        );
    }

    report
}

// ── Per-item check helpers ───────────────────────────────────────────

fn row_signature_ok(r: &AiAudit, keys: &HashMap<&str, &KeyEntry>) -> Result<(), String> {
    let sig_hex = r
        .signature
        .as_deref()
        .ok_or("signed row has no signature")?;
    let kid = r
        .signing_key_id
        .as_deref()
        .ok_or("signed row has no signing_key_id")?;
    let key = keys
        .get(kid)
        .ok_or_else(|| format!("no key {kid} in signing_keys"))?;
    let pubkey = hexutil::decode(&key.public_key_hex).map_err(|e| format!("pubkey hex: {e}"))?;
    let msg = hexutil::decode32(&r.payload_hash).map_err(|e| format!("payload_hash hex: {e}"))?;
    let sig = hexutil::decode(sig_hex).map_err(|e| format!("signature hex: {e}"))?;
    // Rows are Ed25519-signed in practice. Honour the row's declared alg anyway.
    let alg = r.sig_alg.as_deref().unwrap_or(&key.sig_alg);
    let valid = match alg {
        "ed25519" => verify_ed25519(&pubkey, &msg, &sig),
        "ES256" => verify_es256(&pubkey, &msg, &sig),
        "ML-DSA-87" => verify_ml_dsa_87(&pubkey, &msg, &sig),
        other => return Err(format!("unknown sig_alg {other}")),
    };
    if valid {
        Ok(())
    } else {
        Err("signature did not verify".to_string())
    }
}

fn anchor_signature_ok(a: &Anchor, keys: &HashMap<&str, &KeyEntry>) -> Result<(), String> {
    let key = keys
        .get(a.signing_key_id.as_str())
        .ok_or_else(|| format!("no key {} in signing_keys", a.signing_key_id))?;
    let pubkey = hexutil::decode(&key.public_key_hex).map_err(|e| format!("pubkey hex: {e}"))?;
    let sig = hexutil::decode(&a.signature).map_err(|e| format!("signature hex: {e}"))?;
    let payload_hash = anchor_payload_hash(
        a.from_id,
        a.to_id,
        a.row_count,
        &a.merkle_root,
        a.prev_anchor_id,
        a.prev_root.as_deref(),
    )?;
    // The gateway's CNSA 2.0 posture signs anchors with ML-DSA-87 (FIPS
    // 204); the signed message is the same 32-byte payload hash the
    // classical schemes receive, so all three arms share `payload_hash`.
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

fn sovereign_recompute_ok(a: &Anchor, rows: Option<&Vec<&AiAudit>>) -> Result<(), String> {
    let rows = rows.ok_or("no rows present for this anchor")?;
    if rows.len() as i64 != a.row_count {
        return Err(format!(
            "row_count {} but pack carries {} covered rows",
            a.row_count,
            rows.len()
        ));
    }
    // Reconstruct the exporter's (created_at, id) leaf order.
    let mut ordered: Vec<&AiAudit> = rows.to_vec();
    ordered.sort_by(|x, y| (x.created_at.as_str(), x.id).cmp(&(y.created_at.as_str(), y.id)));
    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(ordered.len());
    for r in ordered {
        leaves.push(
            hexutil::decode32(&r.payload_hash).map_err(|e| format!("row {} hash: {e}", r.id))?,
        );
    }
    let computed = hex_lower(&merkle_root(&leaves));
    if computed.eq_ignore_ascii_case(&a.merkle_root) {
        Ok(())
    } else {
        Err("recomputed Merkle root != anchor.merkle_root".to_string())
    }
}

fn fleet_inclusion_ok(r: &AiAudit, anchor: Option<&Anchor>) -> Result<(), String> {
    let anchor = anchor.ok_or("covering fleet anchor not in pack")?;
    let proof = r
        .inclusion_proof
        .as_ref()
        .ok_or("fleet row has no inclusion_proof")?;
    if proof.leaf_count as i64 != anchor.row_count {
        return Err(format!(
            "proof leaf_count {} != anchor row_count {}",
            proof.leaf_count, anchor.row_count
        ));
    }
    let leaf = hexutil::decode32(&r.payload_hash).map_err(|e| format!("payload_hash: {e}"))?;
    let root = hexutil::decode32(&anchor.merkle_root).map_err(|e| format!("anchor root: {e}"))?;
    let mut path: Vec<[u8; 32]> = Vec::with_capacity(proof.path.len());
    for (i, node) in proof.path.iter().enumerate() {
        path.push(hexutil::decode32(node).map_err(|e| format!("path[{i}]: {e}"))?);
    }
    if merkle_inclusion_verify(&leaf, proof.leaf_index, proof.leaf_count, &path, &root) {
        Ok(())
    } else {
        Err("inclusion proof did not fold to the anchor root".to_string())
    }
}

fn continuity_check(report: &mut Report, anchors: &[Anchor], anchor_by_id: &HashMap<i64, &Anchor>) {
    let mut chains: HashMap<&str, Vec<&Anchor>> = HashMap::new();
    for a in anchors {
        chains.entry(a.chain.as_str()).or_default().push(a);
    }
    let mut bad: Vec<String> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    for (chain, mut list) in chains {
        list.sort_by_key(|a| a.id);
        for (pos, a) in list.iter().enumerate() {
            if pos == 0 {
                // First anchor in the window: genesis (None) or a boundary link
                // to an anchor outside the exported window.
                match a.prev_anchor_id {
                    None => {}
                    Some(pid) if anchor_by_id.contains_key(&pid) => {}
                    Some(pid) => notes.push(format!(
                        "{chain}: first anchor {} links to {pid} outside the window (boundary)",
                        a.id
                    )),
                }
                continue;
            }
            let prev = list[pos - 1];
            if a.prev_anchor_id != Some(prev.id) {
                bad.push(format!(
                    "{chain}: anchor {} prev_anchor_id {:?} != {}",
                    a.id, a.prev_anchor_id, prev.id
                ));
            }
            let prev_root_ok = a
                .prev_root
                .as_deref()
                .map(|pr| pr.eq_ignore_ascii_case(&prev.merkle_root))
                .unwrap_or(false);
            if !prev_root_ok {
                bad.push(format!(
                    "{chain}: anchor {} prev_root != anchor {} root",
                    a.id, prev.id
                ));
            }
        }
    }
    let detail = if bad.is_empty() {
        if notes.is_empty() {
            "all chains link cleanly".to_string()
        } else {
            format!("chains link cleanly; boundary notes: {}", trunc(&notes))
        }
    } else {
        format!("continuity breaks: {}", trunc(&bad))
    };
    report.record("chain_continuity", bad.is_empty(), detail);
}

fn seam_check(
    report: &mut Report,
    manifest: &Option<Manifest>,
    ai: &[AiAudit],
    anchors: &[Anchor],
) {
    let handoff = match manifest.as_ref().and_then(|m| m.genesis_handoff.as_ref()) {
        Some(h) => h,
        None => {
            report.ok(
                "genesis_seam",
                "no genesis handoff (sovereign-only or pre-sovereign-only pack)",
            );
            return;
        }
    };
    let mut bad: Vec<String> = Vec::new();
    for r in ai {
        let on_fleet = r.covered_by.chain == "fleet";
        let on_tenant = r.covered_by.chain.starts_with("tenant:");
        if r.id <= handoff.handoff_cursor_id && !on_fleet {
            bad.push(format!("row {} (id<=cursor) not on the fleet chain", r.id));
        }
        if r.id > handoff.handoff_cursor_id && !on_tenant {
            bad.push(format!(
                "row {} (id>cursor) not on the sovereign chain",
                r.id
            ));
        }
    }
    // The sovereign chain must begin exactly one row past the handoff cursor —
    // no gap, no double-coverage.
    let first_sovereign_from = anchors
        .iter()
        .filter(|a| a.chain.starts_with("tenant:"))
        .map(|a| a.from_id)
        .min();
    match first_sovereign_from {
        Some(from)
            if from == handoff.sovereign_first_from_id && from == handoff.handoff_cursor_id + 1 => {
        }
        Some(from) => bad.push(format!(
            "sovereign chain starts at {from}; expected handoff cursor {}+1 = {}",
            handoff.handoff_cursor_id,
            handoff.handoff_cursor_id + 1
        )),
        None => bad.push("genesis handoff declared but no sovereign anchor present".to_string()),
    }
    report.record(
        "genesis_seam",
        bad.is_empty(),
        if bad.is_empty() {
            format!("seam clean at cursor {}", handoff.handoff_cursor_id)
        } else {
            format!("seam problems: {}", trunc(&bad))
        },
    );
}

// ── Formatting helpers ───────────────────────────────────────────────

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

fn trunc_ids(ids: &[i64]) -> String {
    let as_str: Vec<String> = ids.iter().map(|id| id.to_string()).collect();
    trunc(&as_str)
}
