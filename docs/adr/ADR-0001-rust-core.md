# ADR-0001: Rust as the sole trusted implementation language

Status: accepted. Date: 2026-10-30.

## Context
The specification mandates Rust and forbids Go or Node.js for enforcement. The trusted controller parses hostile input from the container (IPC, Git objects, HTTP), so memory safety matters.

## Decision
All trusted components (controller, guards, broker, proxy, audit) and the in-container shim are Rust. The only non-Rust executables the controller invokes are `git` (with locked-down configuration), `gitleaks`, `trivy`, and the Docker daemon API. Agent CLIs run only inside the container.

## Consequences
- `#![forbid(unsafe_code)]` by default; unsafe confined to three crates with review.
- Git object inspection uses gix to avoid spawning git for parsing; transport still uses the git CLI.
- Some provider SDKs are unavailable in Rust; the broker uses plain HTTPS APIs.
