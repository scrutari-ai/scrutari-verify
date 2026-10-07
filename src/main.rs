//! Thin CLI over the `scrutari_verify` engine.
//!
//! ```text
//! scrutari-verify --pack export.jsonl        # human report, exit 0 = PASS
//! scrutari-verify --pack export.jsonl --json # machine-readable report
//! cat export.jsonl | scrutari-verify         # reads stdin when --pack omitted
//! ```
//!
//! Exit codes: 0 = PASS, 1 = verification FAILED, 2 = could not read / serialize.
//!
//! Human output is colorized only when stdout is an interactive terminal;
//! piped output, `NO_COLOR` set to a non-empty value, or `TERM=dumb` all
//! give plain text, so CI logs and shell pipelines stay stable. `--json`
//! output is never colorized.

use std::io::IsTerminal;
use std::io::Read;
use std::path::Path;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use serde::Serialize;

use scrutari_verify::chain::{is_chain_pack, verify_chain};
use scrutari_verify::verify::{Finding, Report, verify};

#[derive(Parser)]
#[command(
    name = "scrutari-verify",
    about = "Offline verifier for Scrutari audit-export packs (Merkle v2 and chain/v1).",
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

    // No pack argument AND stdin is a terminal: nothing is coming.
    // Without this check the process blocks silently on a TTY read —
    // an operator typing `scrutari-verify` to see what it does gets a
    // hang instead of help. Piped stdin still works exactly as
    // documented.
    if cli.pack.is_none() && std::io::stdin().is_terminal() {
        use clap::CommandFactory;
        let _ = Cli::command().print_help();
        eprintln!();
        eprintln!("scrutari-verify: pass --pack <file>, or pipe a pack on stdin.");
        return ExitCode::from(2);
    }

    let input = match read_input(cli.pack.as_deref()) {
        Ok(text) => text,
        Err(why) => {
            eprintln!("scrutari-verify: cannot read pack: {why}");
            return ExitCode::from(2);
        }
    };

    // chain/v1 packs (hash-chained audit tables with signed chain-head
    // anchors) and Merkle v2 packs share one CLI; the header's `profile`
    // field picks the engine.
    let (report, profile): (Report, &str) = if is_chain_pack(&input) {
        (verify_chain(&input), "chain/v1")
    } else {
        (verify(&input), "merkle/v2")
    };
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
        print_human(&report, passed, profile);
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

// ── Human report rendering ──────────────────────────────────────────
//
// Hand-rolled ANSI on purpose: this binary is the thing auditors are
// asked to trust, so its output path stays dependency-free and short
// enough to read in one sitting. 16-color SGR codes only, nothing a
// terminal from this century cannot render.

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";
/// Bold bright-white on green, for the PASS verdict badge.
const BADGE_PASS: &str = "\x1b[1;97;42m";
/// Bold bright-white on red, for the FAIL verdict badge.
const BADGE_FAIL: &str = "\x1b[1;97;41m";

/// Column width for check names; fits the widest one,
/// `structure.manifest_terminal` (27 chars), across both engines.
const CHECK_COL: usize = 28;

/// Color is opt-out, never forced: an interactive stdout gets it, and
/// `NO_COLOR` (non-empty) or `TERM=dumb` turns it back off. Anything
/// piped or redirected is plain bytes.
fn use_color() -> bool {
    if std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty()) {
        return false;
    }
    if std::env::var_os("TERM").is_some_and(|t| t == "dumb") {
        return false;
    }
    std::io::stdout().is_terminal()
}

fn print_human(report: &Report, passed: bool, profile: &str) {
    let total = report.findings.len();
    let ok = report.findings.iter().filter(|f| f.ok).count();
    if use_color() {
        print_pretty(report, passed, profile, ok, total);
    } else {
        print_plain(report, passed, profile, ok, total);
    }
}

/// Colorized report for interactive terminals.
fn print_pretty(report: &Report, passed: bool, profile: &str, ok: usize, total: usize) {
    println!(
        "{BOLD}scrutari-verify{RESET} {DIM}offline verification of a Scrutari audit pack{RESET}"
    );
    println!("{DIM}pack profile: {profile}{RESET}");
    println!();
    for f in &report.findings {
        if f.ok {
            println!(
                "  {GREEN}\u{2713}{RESET} {:<CHECK_COL$} {DIM}{}{RESET}",
                f.check, f.detail
            );
        } else {
            println!(
                "  {RED}\u{2717} {BOLD}{:<CHECK_COL$}{RESET} {RED}{}{RESET}",
                f.check, f.detail
            );
        }
    }
    println!();
    if passed {
        println!(
            " {BADGE_PASS} PASS {RESET} {GREEN}{ok}/{total} checks passed.{RESET} The pack is complete, untampered, and correctly signed."
        );
    } else if total == 0 {
        println!(
            " {BADGE_FAIL} FAIL {RESET} {RED}{BOLD}No checks ran; the input is not a readable pack.{RESET}"
        );
    } else {
        println!(
            " {BADGE_FAIL} FAIL {RESET} {RED}{BOLD}{failed} of {total} checks failed.{RESET} Do not rely on this pack as evidence; the failed checks above say why.",
            failed = total - ok
        );
    }
}

/// Plain report for pipes, CI, `NO_COLOR`, and dumb terminals. Keeps the
/// original greppable shape: `[PASS]`/`[FAIL]` per check, `RESULT:` verdict.
fn print_plain(report: &Report, passed: bool, profile: &str, ok: usize, total: usize) {
    println!("Scrutari audit-export verification (profile: {profile})");
    println!("====================================================");
    for f in &report.findings {
        let mark = if f.ok { "PASS" } else { "FAIL" };
        println!("[{mark}] {:<CHECK_COL$} {}", f.check, f.detail);
    }
    println!("----------------------------------------------------");
    if passed {
        println!(
            "RESULT: PASS ({ok}/{total} checks passed; pack is complete, untampered, and correctly signed)"
        );
    } else if total == 0 {
        println!("RESULT: FAIL (no checks ran; the input is not a readable pack)");
    } else {
        println!(
            "RESULT: FAIL ({failed} of {total} checks failed, see above)",
            failed = total - ok
        );
    }
}
