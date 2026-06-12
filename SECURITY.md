# Security Policy

This repository contains scrutari-verify, the offline verifier for
Scrutari audit-export packs.

scrutari-verify is an offline verification tool. It performs no network
I/O and never handles private key material. Its threat model, including
what a PASS does and does not prove, is documented in the
[README](README.md). Reports about incorrect verification results,
packs that pass when they should fail, or crashes and panics on
malformed input are all in scope and welcome.

## Supported versions

Only the latest release receives security fixes. If you are running an
older version, upgrade before reporting an issue against it.

## Reporting a vulnerability

Email boubacar@scrutari.ai with the subject prefix `[SECURITY]`.
Include what you found, how to reproduce it (a minimal pack that
triggers the issue helps a lot), the affected version or commit, and
your assessment of the impact.

You will receive an acknowledgment within 2 business days.

We prefer coordinated disclosure. The default disclosure window is
90 days from your first report. If a fix needs more time, we will tell
you why and agree on a new date with you. Please do not open public
GitHub issues for security reports.

## Scope

In scope:

* The offline audit-pack verifier (this repository).
* The Scrutari gateway and webhook receiver (scrutari-pq-workspace).
* The Scrutari dashboard (scrutari-point).

Out of scope:

* Content of the marketing site at scrutari.ai.
* Third-party identity providers and other third-party services that
  Scrutari integrates with. Report those to the respective vendor.

## Safe harbor

We will not pursue legal action against researchers who act in good
faith, avoid privacy violations and service disruption, access only the
minimum data needed to demonstrate an issue, and report it privately as
described above.

## PGP

A PGP key for encrypted reports is available on request; ask for it in
your first email.
