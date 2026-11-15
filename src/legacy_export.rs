//! Recognizing a format v1 audit export.
//!
//! Before the v2 pack existed, audit rows, their signatures and the
//! anchors were exported in an older layout. That file has no header, no
//! public keys, and no record of which anchor covers each row, so there
//! is nothing in it to verify the rows against. It is not a damaged v2
//! pack, and running the v2 checks over it would report one error per
//! line and a failed verification of a file that is in fact intact.
//!
//! Callers check [`is_legacy_export`] first and, when it is true, say
//! what the file is and stop.

use serde_json::Value;

/// Profile name reported for a format v1 audit export.
pub const LEGACY_EXPORT_PROFILE: &str = "audit-export/v1";

/// What to tell the person who handed over a format v1 export.
pub const LEGACY_EXPORT_NOTICE: &str = "This file is a format v1 audit export. It has no header, no public keys and no anchor reference per row, so it cannot be verified offline, and nothing in it was checked. Export the same tenant as a format v2 compliance pack and verify that file.";

const RECORD_FIELD: &str = "record";
const FORMAT_VERSION_FIELD: &str = "format_version";
const RECORD_HEADER: &str = "header";
const RECORD_MANIFEST: &str = "manifest";
const LEGACY_FORMAT_VERSION: u64 = 1;

/// True when the input is a format v1 audit export: it does not open
/// with a `header` record, and it closes with a `manifest` record whose
/// `format_version` is 1.
///
/// Only the first and last non-empty lines are parsed, so this is cheap
/// on a large file. A v1 export cut off before its manifest is not
/// recognized; the v2 checks then report it as truncated, which is true.
pub fn is_legacy_export(jsonl: &str) -> bool {
    let mut non_empty = jsonl.lines().map(str::trim).filter(|line| !line.is_empty());
    let Some(first) = non_empty.next() else {
        return false;
    };
    // A one-line file is both its own first and last line.
    let last = non_empty.next_back().unwrap_or(first);

    if record_kind(first).as_deref() == Some(RECORD_HEADER) {
        return false;
    }
    let Ok(manifest) = serde_json::from_str::<Value>(last) else {
        return false;
    };
    manifest.get(RECORD_FIELD).and_then(Value::as_str) == Some(RECORD_MANIFEST)
        && manifest.get(FORMAT_VERSION_FIELD).and_then(Value::as_u64) == Some(LEGACY_FORMAT_VERSION)
}

fn record_kind(line: &str) -> Option<String> {
    let value: Value = serde_json::from_str(line).ok()?;
    value
        .get(RECORD_FIELD)
        .and_then(Value::as_str)
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    const V1_ROW: &str = r#"{"record":"ai_audit","id":1,"request_id":"req_1","payload":"{}","payload_hash":"00","signed":false}"#;
    const V1_MANIFEST: &str =
        r#"{"record":"manifest","format_version":1,"tenant_id":"t","ai_audit_rows":1}"#;
    const V2_HEADER: &str = r#"{"record":"header","format_version":2,"tenant_id":"t"}"#;
    const V2_MANIFEST: &str = r#"{"record":"manifest","format_version":2,"tenant_id":"t","counts":{"audit":0,"ai_audit":0,"ai_signed":0,"anchors":0}}"#;

    fn lines(parts: &[&str]) -> String {
        parts.join("\n")
    }

    #[test]
    fn a_v1_export_is_recognized() {
        assert!(is_legacy_export(&lines(&[V1_ROW, V1_MANIFEST])));
        assert!(is_legacy_export(&lines(&[
            "",
            V1_ROW,
            "  ",
            V1_MANIFEST,
            ""
        ])));
    }

    #[test]
    fn a_manifest_alone_is_recognized() {
        assert!(is_legacy_export(V1_MANIFEST));
    }

    #[test]
    fn a_v2_pack_is_not_legacy() {
        assert!(!is_legacy_export(&lines(&[V2_HEADER, V2_MANIFEST])));
    }

    #[test]
    fn a_header_rules_out_legacy_even_with_a_v1_manifest() {
        assert!(!is_legacy_export(&lines(&[V2_HEADER, V1_ROW, V1_MANIFEST])));
    }

    #[test]
    fn a_v1_export_without_its_manifest_is_not_recognized() {
        assert!(!is_legacy_export(V1_ROW));
        assert!(!is_legacy_export(&lines(&[V1_ROW, V1_ROW])));
    }

    #[test]
    fn empty_and_non_json_input_is_not_legacy() {
        assert!(!is_legacy_export(""));
        assert!(!is_legacy_export("\n\n"));
        assert!(!is_legacy_export("not json"));
        assert!(!is_legacy_export(&lines(&[V1_ROW, "not json"])));
    }
}
