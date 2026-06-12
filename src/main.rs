//! Thin CLI over the `scrutari_verify` engine.
//!
//! ```text
//! scrutari-verify --pack export.jsonl        # human report, exit 0 = PASS
//! scrutari-verify --pack export.jsonl --json # machine-readable report
//! cat export.jsonl | scrutari-verify         # reads stdin when --pack omitted
//! ```
//!
//! Exit codes: 0 = PASS, 1 = verification FAILED, 2 = could not read / serialize.

use std::io::Read;
use std::path::Path;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use serde::Serialize;

use scrutari_verify::verify::{Finding, Report, verify};

#[derive(Parser)]
#[command(
    name = "scrutari-verify",
    about = "Offline verifier for Scrutari audit-export packs (format v2).",
    version
)]
struct Cli {
    /// Path to the JSONL export pack. Reads stdin when omitted or set to '-'.
    #[arg(long, short)]
    pack: Option<PathBuf>,
    /// Emit a machine-readable JSON report instead of human-readable text.
    #[arg(long)]
    json: bool,
}

#[derive(Serialize)]
struct JsonReport<'a> {
    passed: bool,
    findings: &'a [Finding],
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let input = match read_input(cli.pack.as_deref()) {
        Ok(text) => text,
        Err(why) => {
            eprintln!("scrutari-verify: cannot read pack: {why}");
            return ExitCode::from(2);
        }
    };

    let report = verify(&input);
    let passed = report.passed();

    if cli.json {
        let view = JsonReport {
            passed,
            findings: &report.findings,
        };
        match serde_json::to_string_pretty(&view) {
            Ok(text) => println!("{text}"),
            Err(why) => {
                eprintln!("scrutari-verify: report serialize failed: {why}");
                return ExitCode::from(2);
            }
        }
    } else {
        print_human(&report, passed);
    }

    if passed {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn read_input(path: Option<&Path>) -> Result<String, String> {
    match path {
        None => read_stdin(),
        Some(p) if p.as_os_str() == "-" => read_stdin(),
        Some(p) => std::fs::read_to_string(p).map_err(|e| e.to_string()),
    }
}

fn read_stdin() -> Result<String, String> {
    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .map_err(|e| e.to_string())?;
    Ok(buf)
}

fn print_human(report: &Report, passed: bool) {
    println!("Scrutari audit-export verification (pack format v2)");
    println!("====================================================");
    for f in &report.findings {
        let mark = if f.ok { "PASS" } else { "FAIL" };
        println!("[{mark}] {:<22} {}", f.check, f.detail);
    }
    println!("----------------------------------------------------");
    if passed {
        println!("RESULT: PASS (pack is complete, untampered, and correctly signed)");
    } else {
        println!("RESULT: FAIL (one or more checks failed, see above)");
    }
}
