use std::collections::BTreeMap;
use std::io::{Cursor, Read};

use serde::{Deserialize, Serialize};

use crate::crypto::{hex_lower, sha256, verify_ed25519};
use crate::hexutil;
use crate::verify::Report;

pub const PROFILE: &str = "scrutari-cbom-report/v1";
const MAX_BUNDLE_BYTES: usize = 128 * 1024 * 1024;
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BundleManifest {
    pub profile: String,
    pub customer_name: String,
    pub report_date: String,
    pub signer_key_id: String,
    pub files: BTreeMap<String, String>,
    pub sig_alg: String,
    pub signature: String,
}

#[derive(Serialize)]
struct SignedPayload<'a> {
    profile: &'a str,
    customer_name: &'a str,
    report_date: &'a str,
    signer_key_id: &'a str,
    files: &'a BTreeMap<String, String>,
    sig_alg: &'a str,
}

pub fn canonical_manifest_hash(manifest: &BundleManifest) -> Result<[u8; 32], String> {
    let payload = SignedPayload {
        profile: &manifest.profile,
        customer_name: &manifest.customer_name,
        report_date: &manifest.report_date,
        signer_key_id: &manifest.signer_key_id,
        files: &manifest.files,
        sig_alg: &manifest.sig_alg,
    };
    let bytes = serde_json::to_vec(&payload).map_err(|error| error.to_string())?;
    Ok(sha256(&bytes))
}

pub fn key_id_for_public_key(public_key: &[u8]) -> String {
    hex_lower(&sha256(public_key)[..8])
}

pub fn verify_bundle(bytes: &[u8], trusted_public_key_hex: &str) -> Report {
    let mut report = Report::default();
    if bytes.len() > MAX_BUNDLE_BYTES {
        report.fail("bundle.size", "bundle exceeds 128 MiB");
        return report;
    }
    let mut archive = match zip::ZipArchive::new(Cursor::new(bytes)) {
        Ok(archive) => archive,
        Err(error) => {
            report.fail("bundle.zip", error.to_string());
            return report;
        }
    };
    if archive.len() != 3 {
        report.fail("bundle.files", "bundle must contain exactly three files");
        return report;
    }
    let mut files = BTreeMap::new();
    for index in 0..archive.len() {
        let mut entry = match archive.by_index(index) {
            Ok(entry) => entry,
            Err(error) => {
                report.fail("bundle.zip", error.to_string());
                return report;
            }
        };
        let name = entry.name().to_owned();
        if !matches!(name.as_str(), "cbom.json" | "report.pdf" | "manifest.json")
            || files.contains_key(&name)
        {
            report.fail("bundle.files", "unexpected or duplicate archive entry");
            return report;
        }
        let limit = if name == "manifest.json" {
            MAX_MANIFEST_BYTES
        } else {
            MAX_FILE_BYTES
        };
        if entry.size() > limit {
            report.fail("bundle.size", format!("{name} exceeds size limit"));
            return report;
        }
        let mut data = Vec::new();
        if let Err(error) = entry.by_ref().take(limit + 1).read_to_end(&mut data) {
            report.fail("bundle.zip", error.to_string());
            return report;
        }
        if data.len() as u64 > limit {
            report.fail("bundle.size", format!("{name} exceeds size limit"));
            return report;
        }
        files.insert(name, data);
    }
    let Some(manifest_bytes) = files.get("manifest.json") else {
        report.fail("bundle.files", "manifest.json is missing");
        return report;
    };
    let manifest: BundleManifest = match serde_json::from_slice(manifest_bytes) {
        Ok(manifest) => manifest,
        Err(error) => {
            report.fail("bundle.manifest", error.to_string());
            return report;
        }
    };
    let structure_ok = manifest.profile == PROFILE
        && !manifest.customer_name.trim().is_empty()
        && valid_report_date(&manifest.report_date)
        && manifest.sig_alg == "ed25519"
        && manifest.files.len() == 2
        && manifest.files.contains_key("cbom.json")
        && manifest.files.contains_key("report.pdf");
    report.record(
        "bundle.manifest",
        structure_ok,
        "profile, customer, date, algorithm, and file list",
    );
    if !structure_ok {
        return report;
    }
    for name in ["cbom.json", "report.pdf"] {
        let expected = manifest.files.get(name).map(String::as_str);
        let actual = files.get(name).map(|data| hex_lower(&sha256(data)));
        let ok = expected
            .zip(actual.as_deref())
            .is_some_and(|(left, right)| left.len() == 64 && left == right);
        report.record("bundle.sha256", ok, format!("{name} SHA-256"));
    }
    let public_key = hexutil::decode(trusted_public_key_hex.trim());
    let trusted_key = public_key.as_ref().ok().filter(|key| key.len() == 32);
    let key_id_ok = trusted_key
        .map(|key| key_id_for_public_key(key) == manifest.signer_key_id)
        .unwrap_or(false);
    report.record(
        "bundle.signer_key_id",
        key_id_ok,
        "matches separately trusted report public key",
    );
    let signature_ok = trusted_key
        .zip(hexutil::decode(&manifest.signature).ok())
        .zip(canonical_manifest_hash(&manifest).ok())
        .is_some_and(|((key, signature), hash)| verify_ed25519(key, &hash, &signature));
    report.record(
        "bundle.signature",
        signature_ok,
        "Ed25519 signature over SHA-256 of canonical manifest payload",
    );
    report
}

pub fn valid_report_date(date: &str) -> bool {
    let bytes = date.as_bytes();
    let shape = bytes.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| index == 4 || index == 7 || byte.is_ascii_digit());
    if !shape {
        return false;
    }
    let month = date[5..7].parse::<u8>().ok();
    let day = date[8..10].parse::<u8>().ok();
    matches!(month, Some(1..=12)) && matches!(day, Some(1..=31))
}
