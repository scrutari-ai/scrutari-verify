//! Browser entry point: the same verification engine, compiled to
//! wasm32 with the pure-Rust backend (`--features wasm`), so a pack
//! can be checked entirely client-side. Nothing is uploaded anywhere;
//! the page hands the JSONL text in, a JSON report comes back.

use wasm_bindgen::prelude::wasm_bindgen;

use crate::chain::{is_chain_pack, verify_chain};
use crate::legacy_export::{LEGACY_EXPORT_NOTICE, LEGACY_EXPORT_PROFILE, is_legacy_export};
use crate::verify::{Report, verify};

/// Verify a pack (Merkle v2 or chain/v1, auto-detected) and return the
/// report as JSON: `{"passed": bool, "findings": [{check, ok, detail}]}`.
///
/// A format v1 audit export is not verified. It comes back with
/// `passed: false`, an `unsupported_format` field, and one finding that
/// explains what the file is.
#[wasm_bindgen]
pub fn verify_pack_json(jsonl: &str) -> String {
    if !is_chain_pack(jsonl) && is_legacy_export(jsonl) {
        return serde_json::json!({
            "passed": false,
            "unsupported_format": LEGACY_EXPORT_PROFILE,
            "findings": [{
                "check": "format",
                "ok": false,
                "detail": LEGACY_EXPORT_NOTICE,
            }],
        })
        .to_string();
    }
    let report: Report = if is_chain_pack(jsonl) {
        verify_chain(jsonl)
    } else {
        verify(jsonl)
    };
    serde_json::json!({
        "passed": report.passed(),
        "findings": report.findings,
    })
    .to_string()
}
