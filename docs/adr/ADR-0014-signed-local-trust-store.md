# ADR-0014: Signed, pinned local trust store with Ed25519 and an optional administrator anchor

Status: accepted (Phase 2, 2026-10-31). Implements ADR-0005's "policy file is input; trusted policy is a pinned snapshot" for the hook-driven engine (ADR-0013).

## Context
Phase 2 requires:
- trusted policy that an agent cannot silently weaken;
- detection of modified, missing, replaced and rolled-back state;
- a root of trust;
- authorised updates;
- no daemon, server or Docker;
- established cryptography only, with no private keys shipped.

## Decision
1. **Location.** A private (0700) directory under the user's XDG configuration directory, outside every project, with `keys/`, `trusted/`, `registry/`, `integrity/` and `audit/`. Project directories, including `.agentguard/`, are never read as trust material.
2. **Cryptography.** Ed25519 via `ed25519-dalek` 2.2:
   - strict verification, weak keys rejected;
   - purpose-separated messages;
   - SHA-256 for hashes and IDs;
   - canonical JSON of typed values.

   No algorithm is implemented in AgentGuard itself.
3. **Keys.** A root key signs a key set of policy-signing keys, and policy-signing keys sign manifests, the registry and the integrity state. Only public keys are stored. Private keys are passed in for one operation through a `Signer` trait.
4. **Integrity.** One signed integrity state pins every current object by version and body hash. Objects are immutable, versioned files written before the pointer is atomically replaced. A high-water mark catches replay of older states and key sets.
5. **Optional administrator anchor.** `/etc/agentguard/root.json`, root-owned and not group/world-writable. When present, it pins the root key. This is the only defence against a same-user process re-creating the whole store.
6. **Fail closed.** Any verification failure produces a deny-all lockdown policy and an audit event. State is never regenerated automatically, and recovery is an explicit, human-only quarantine plus re-initialisation.

## Alternatives rejected
- **Unsigned hashes in a manifest.** They detect accidental corruption only; anyone can recompute them.
- **HMAC with a locally stored key.** The key would be readable by a same-user agent, so it adds nothing over a hash.
- **OS keychain as the only store.** It is not available uniformly (headless Linux), and a same-user process can usually query it.
- **minisign/SSH signature formats.** These are established, but would add a parsing surface and a format dependency. Ed25519 over our canonical bytes is the same primitive, used directly. External signing tools can be bridged later through the `Signer` trait.
- **SQLite now.** That is Phase 3. Flat signed files are enough for the trust store and keep the commit protocol simple.

## Consequences
- Every policy change requires the human's signing key, so routine changes are deliberate by design.
- Without an administrator anchor, a same-user process with arbitrary code execution can replace the entire trust store undetected. This is documented in TRUST_MODEL.md §1 and limitation L37.
- The engine's guard must be given the trust root as a protected root (`TrustedRuntime::protected_roots`).
