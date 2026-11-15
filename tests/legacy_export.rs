//! The CLI's behavior on a format v1 audit export: it names the format,
//! exits 2, and prints no verification verdict.

use std::io::Write;
use std::process::{Command, Output};

const V1_EXPORT: &str = concat!(
    r#"{"record":"audit","id":1,"event_type":"login","created_at":"2026-01-01T00:00:00Z"}"#,
    "\n",
    r#"{"record":"ai_audit","id":1,"request_id":"req_1","created_at":"2026-01-01T00:00:01Z","payload":"{}","payload_hash":"00","signed":false}"#,
    "\n",
    r#"{"record":"anchor","id":1,"from_id":1,"to_id":1,"row_count":1,"merkle_root":"00","signature":"00","signing_key_id":"k","sig_alg":"ES256"}"#,
    "\n",
    r#"{"record":"manifest","format_version":1,"tenant_id":"t","audit_rows":1,"ai_audit_rows":1,"anchor_rows":1}"#,
    "\n",
);

fn run_on_v1_export(extra_args: &[&str]) -> Output {
    let mut file = tempfile::NamedTempFile::new().expect("temp file");
    file.write_all(V1_EXPORT.as_bytes()).expect("write fixture");
    Command::new(env!("CARGO_BIN_EXE_scrutari-verify"))
        .arg("--pack")
        .arg(file.path())
        .args(extra_args)
        .output()
        .expect("run scrutari-verify")
}

#[test]
fn a_v1_export_is_named_and_not_reported_as_failed() {
    let output = run_on_v1_export(&[]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(2), "stderr: {stderr}");
    assert!(stderr.contains("audit-export/v1"), "stderr: {stderr}");
    assert!(
        stderr.contains("format v1 audit export"),
        "stderr: {stderr}"
    );
    assert!(
        stderr.contains("format v2 compliance pack"),
        "stderr: {stderr}"
    );
    assert!(stdout.is_empty(), "stdout: {stdout}");
    assert!(!stderr.contains("FAIL"), "stderr: {stderr}");
    assert!(!stderr.contains("malformed"), "stderr: {stderr}");
}

#[test]
fn json_output_marks_a_v1_export_as_unsupported() {
    let output = run_on_v1_export(&["--json"]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_str(&stdout).expect("json report");
    assert_eq!(report["passed"], false);
    assert_eq!(report["unsupported_format"], "audit-export/v1");
    assert!(report.get("findings").is_none());
}

#[test]
fn the_bundled_v2_vector_still_passes() {
    let output = Command::new(env!("CARGO_BIN_EXE_scrutari-verify"))
        .arg("--pack")
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/vectors/valid.jsonl"))
        .output()
        .expect("run scrutari-verify");
    assert_eq!(output.status.code(), Some(0));
}
