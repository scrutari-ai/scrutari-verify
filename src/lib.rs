//! `scrutari-verify` — the offline verification engine for Scrutari
//! audit-export packs (format v2).
//!
//! An auditor takes a tenant's exported `.jsonl` pack to an air-gapped machine
//! and runs the CLI; it proves, with no network and no Scrutari services, that
//! the pack is complete (not truncated), untampered (every row hashes to its
//! recorded hash), included (every row sits under a signed anchor — by full
//! Merkle recompute on the tenant's sovereign chain, or by inclusion proof on
//! the shared fleet chain), correctly signed (each anchor under the declared
//! public key, with explicit `key_origin`), and continuous (per-chain prev-links
//! plus the genesis-handoff seam between the two windows).
//!
//! All cryptography lives in [`crypto`]: Ed25519 and ECDSA P-256 verification,
//! SHA-256, and RFC 6962-style Merkle tree operations, implemented over
//! aws-lc-rs — the same backend and the same math the signing side used.
//! The pack wire format (see [`pack`] and the README) is specified precisely
//! enough that a third party can reimplement this verifier independently; this
//! crate is a reference, not the only possible implementation.

pub mod canonical;
pub mod crypto;
pub mod hexutil;
pub mod pack;
pub mod verify;
