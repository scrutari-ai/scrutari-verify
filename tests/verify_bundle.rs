#![cfg(feature = "std-crypto")]

use std::collections::BTreeMap;
use std::fs;
use std::io::{Cursor, Write};
use std::process::Command;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use scrutari_verify::bundle::{
    BundleManifest, PROFILE, canonical_manifest_hash, key_id_for_public_key,
};
use scrutari_verify::crypto::{hex_lower, sha256};
use zip::write::FileOptions;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn make_zip(manifest: &[u8], pdf: &[u8]) -> Result<Vec<u8>> {
    let mut cursor = Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut cursor);
        let options = FileOptions::default().compression_method(zip::CompressionMethod::Stored);
        for (name, data) in [
            ("cbom.json", b"{\"bomFormat\":\"CycloneDX\"}".as_slice()),
            ("report.pdf", pdf),
            ("manifest.json", manifest),
        ] {
            writer.start_file(name, options)?;
            writer.write_all(data)?;
        }
        writer.finish()?;
    }
    Ok(cursor.into_inner())
}

#[test]
fn cli_accepts_signed_bundle_and_rejects_pdf_byte_flip() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let key_der = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
        .map_err(|_| "cannot generate test signing key")?;
    let key =
        Ed25519KeyPair::from_pkcs8(key_der.as_ref()).map_err(|_| "cannot load test signing key")?;
    let public_key = key.public_key().as_ref();
    let pdf = b"%PDF-1.7\noriginal report";
    let mut hashes = BTreeMap::new();
    hashes.insert(
        "cbom.json".to_owned(),
        hex_lower(&sha256(b"{\"bomFormat\":\"CycloneDX\"}")),
    );
    hashes.insert("report.pdf".to_owned(), hex_lower(&sha256(pdf)));
    let mut manifest = BundleManifest {
        profile: PROFILE.to_owned(),
        customer_name: "Example Payments".to_owned(),
        report_date: "2026-10-22".to_owned(),
        signer_key_id: key_id_for_public_key(public_key),
        files: hashes,
        sig_alg: "ed25519".to_owned(),
        signature: String::new(),
    };
    manifest.signature = hex_lower(key.sign(&canonical_manifest_hash(&manifest)?).as_ref());
    let manifest_json = serde_json::to_vec(&manifest)?;
    fs::write(temp.path().join("report-key.hex"), hex_lower(public_key))?;
    fs::write(
        temp.path().join("valid.zip"),
        make_zip(&manifest_json, pdf)?,
    )?;
    let valid = Command::new(env!("CARGO_BIN_EXE_scrutari-verify"))
        .args(["--bundle", "valid.zip", "--report-key", "report-key.hex"])
        .current_dir(temp.path())
        .output()?;
    assert_eq!(valid.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&valid.stdout).contains("RESULT: PASS"));
    let mut changed = pdf.to_vec();
    let Some(byte) = changed.get_mut(10) else {
        return Err("test PDF is too short".into());
    };
    *byte ^= 1;
    fs::write(
        temp.path().join("tampered.zip"),
        make_zip(&manifest_json, &changed)?,
    )?;
    let tampered = Command::new(env!("CARGO_BIN_EXE_scrutari-verify"))
        .args(["--bundle", "tampered.zip", "--report-key", "report-key.hex"])
        .current_dir(temp.path())
        .output()?;
    assert_eq!(tampered.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&tampered.stdout).contains("RESULT: FAIL"));
    Ok(())
}
