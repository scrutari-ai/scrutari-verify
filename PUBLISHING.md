# Publishing scrutari-verify

How to cut a public release of `scrutari-verify`. There are two
distribution channels, both driven by one git tag:

1. A GitHub Release with signed, multi-platform binaries (keyless cosign
   signature + SLSA provenance).
2. The crates.io listing, so auditors can `cargo install scrutari-verify`.

Unlike a Terraform provider, this needs no GPG keypair and no external
registry connect. Signing is keyless (Sigstore via the workflow's GitHub
OIDC token), so there are no signing secrets to manage. The only secret
involved is the optional crates.io token.

## One-time setup

1. The GitHub repository must be PUBLIC. The SLSA provenance generator and
   the public download/verify story both require it.
   ```
   gh repo view scrutari-ai/scrutari-verify --json visibility
   ```
2. crates.io token (only needed for the crates.io channel). Sign in at
   crates.io with GitHub, create an API token scoped to publish, and add it
   as a repository secret named exactly `CARGO_REGISTRY_TOKEN`:
   ```
   gh secret set CARGO_REGISTRY_TOKEN --repo scrutari-ai/scrutari-verify
   ```
   (Run without `--body` so the value is pasted interactively and stays out
   of shell history.) The crate name `scrutari-verify` must be available or
   already owned by your crates.io account.

   The `cargo publish` step is gated on this token: if it is absent, the
   GitHub release still succeeds and only the crates.io publish is skipped.
   So you can ship the first GitHub release before setting the token, then
   add it and publish to crates.io on a later tag.

## Cutting a release

1. Make sure `main` is green and everything is committed:
   ```
   cargo fmt --all --check && cargo clippy --all-targets -- -D warnings && cargo test --all-targets
   git status   # clean
   ```
2. Confirm the version in `Cargo.toml` is the one you intend to publish (it
   is `1.0.0` today). crates.io versions are immutable and cannot be
   re-published, so a version is spent the moment it lands.
3. Tag and push:
   ```
   git tag v1.0.0
   git push origin v1.0.0
   ```
4. The `release` workflow runs on the `v*` tag and does everything:
   - cross-compiles Linux (x86_64-gnu), macOS (aarch64), and Windows
     (x86_64-msvc) binaries;
   - writes `SHA-256SUMS`, signs it keyless with cosign
     (`SHA-256SUMS.sig` + `SHA-256SUMS.pem`), and attaches all of it to the
     GitHub Release;
   - generates SLSA build provenance (`scrutari-verify-<tag>.intoto.jsonl`);
   - publishes to crates.io if `CARGO_REGISTRY_TOKEN` is set, else skips
     that step cleanly.

## Verifying the release went out correctly

```
gh release view v1.0.0 --repo scrutari-ai/scrutari-verify
```

Confirm the assets include the three platform archives, `SHA-256SUMS`,
`SHA-256SUMS.sig`, `SHA-256SUMS.pem`, and `scrutari-verify-<tag>.intoto.jsonl`.
Then run the auditor-facing checks from README.md "Verifying a release" once
yourself (the `cosign verify-blob`, the `sha256sum -c`, and the
`slsa-verifier verify-artifact`) so you know the published instructions
actually pass against the published artifacts.

If the token was set, confirm the crates.io listing:
```
cargo search scrutari-verify
```
and that `https://crates.io/crates/scrutari-verify` shows the version.

## Subsequent releases

Bump the version in `Cargo.toml`, commit, then tag `vX.Y.Z` and push. The
same workflow re-runs. Because the verifier reads a frozen on-disk pack
format (v2), treat any change that alters what counts as a PASS as a
breaking change and reflect it in the version. The whole point of this tool
is that a PASS means the same thing across releases.
