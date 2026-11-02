# Trust Model: Trusted Policy, Root of Trust and Tamper Protection

Implemented in Phase 2 (`crates/agentguard-trust`). Decision: [ADR-0014](adr/ADR-0014-signed-local-trust-store.md).

## 1. What this protects against, and what it cannot

**Goal:** an AI agent must not be able to silently weaken or disable AI Defender's policy. A modified, corrupted, rolled-back or missing trusted policy must be detected, and must never fall back to permissive behaviour.

**Hard limit.** AI Defender is a local tool that runs as your user. It **cannot** protect itself against:
- a process with unrestricted administrator/root privileges;
- a process running as your user that is free to execute arbitrary code outside AI Defender's hooks.

Such a process can read your files, replace AI Defender's binary, or delete and re-create the whole trust store with its own keys. What AI Defender does provide:

| Property | Holds against |
|---|---|
| Agent actions that change trusted state are denied | everything that goes through a hook (engine guard `guard.trusted-state`, `guard.self-approval`) |
| Any edit, replacement, removal or rollback of an individual trusted file is detected and causes lockdown | anyone without a trusted private key |
| Policy can only change with a valid signature from a key the store already trusts | anyone without that private key |
| The root key cannot be swapped | **only** when an administrator-provisioned system anchor exists (§4.2); otherwise a same-user process that rewrites the *entire* store consistently is not detectable locally |

Keep private keys where same-user processes cannot read them (§4.3); this is the single most important operational rule.

## 2. Trust hierarchy

```
1. Mandatory baseline   built into the binary              cannot be weakened by anything below
2. Global policy        signed; organisation/user          may grant exceptions to defaults; cannot lower 1;
                                                           selects and configures the security profile
3. Project policy       signed after human approval        may only add restrictions
4. Profile rules        built in (balanced)                action defaults beneath the global layer
5. Default behaviour    built in                           for actions nothing matched
6. Runtime request      from the agent                     cannot express rules at all
```

Since Phase 3 the evaluation of these layers (priority, conflicts, floors) is specified in [POLICY_EVALUATION.md](POLICY_EVALUATION.md) §4.

- **Mandatory baseline** (`hierarchy::mandatory_rules`, version `agentguard.mandatory-baseline.v1`). It consists of:
  - the engine's guards: unknown operations, trusted-state writes and self-approval are denied;
  - the critical floor: critical risk is never plain-allowed;
  - REQUIRE_APPROVAL floors on secrets, external transfer, git push and config, GitHub merge/release/workflow/settings, database writes/schema/drop/admin, Terraform apply/destroy/import/state, and filesystem changes outside the project;
  - DENY for GitHub repository deletion.
- **Global policy** is evaluated as a deny-wins rule set over the engine defaults:
  - read-only low risk → ALLOW;
  - critical → DENY;
  - otherwise → REQUIRE_APPROVAL.

  It can ALLOW things the defaults gate (for example writes inside the project).
- **Floors.** Mandatory and project rules are applied *as floors* on top of the global result: a matching floor rule can raise the decision, never lower it. This matters: if they were ordinary rules, a project or mandatory REQUIRE_APPROVAL rule matching a critical action would replace its default DENY.
- **Project policy** may contain only DENY and REQUIRE_APPROVAL rules. ALLOW rules are rejected when the update is proposed.
- **Determinism.** Merging is deterministic. Rules are namespaced (`mandatory:`, `global:`, `project:`), combination ignores rule order, and the effective policy version is the SHA-256 of the canonical, ID-sorted layers.

## 3. Global versus project configuration

| | Global (trusted) | Project (untrusted input) |
|---|---|---|
| Location | `$XDG_CONFIG_HOME/agentguard/` (default `~/.config/agentguard/`), mode 0700, outside every project | `<project root>/.agent-security.yml` |
| Read as trust material | yes, after signature, pin and permission checks | **never**. `.agentguard/` and every other file in a project are ignored for keys, manifests and registry. |
| Takes effect | when signed and committed by an authorised update | only after a human approves it via `update_policy` with scope `Project`, which copies the rules into a signed manifest in the trust store |
| Agent edits | denied by the engine guard; detected by signatures if done out of band | have no effect; a difference from the approved policy is recorded as `ProjectPolicyDrift` and the approved policy stays in force |
| How it is found | fixed path | only at the *registered canonical root*, never by walking up from the working directory (fixes audit finding W4) |

## 4. Root of trust and keys

### 4.1 Keys and what they sign

| Key | Signs | Where its private half lives |
|---|---|---|
| **Root key** (Ed25519) | key sets; during rotation, the re-issued manifests, registry and integrity state | offline: password manager, hardware token, or an offline machine. Used rarely. |
| **Policy-signing key(s)** (Ed25519, listed in the root-signed key set) | policy manifests, the project registry, the integrity state, and (Phase 5) each human approval's one-time authorization grant (purpose `agentguard.approval-grant.v1`; see [APPROVALS.md](APPROVALS.md)) | with the human who approves changes: since Phase 4, passphrase-encrypted in `signing/policy.key` (§4.3.1) or held externally; never in plain form, a project, the npm package or the binary |

AI Defender's trusted objects contain **public keys only**; private keys are stored, if at all, only in the encrypted key files of §4.3.1. Private keys enter the process only for the duration of an authorised operation, through the `Signer` trait. The `Ed25519Signer` implementation zeroises the key on drop and never prints it. The trait exists so a later phase can sign through a hardware token or an agent socket, and then the private key never enters AI Defender at all.

### 4.2 Provisioning

1. **Local-user provisioning (default).** `initialize` creates the store with your root public key and an initial key set holding one policy-signing key. It refuses to run if any trusted state exists. From then on the integrity state pins the root key ID.
2. **Administrator provisioning (recommended for teams).** An administrator places the root anchor at `/etc/agentguard/root.json`, owned by root and not writable by group or others. When present:
   - `initialize` refuses any other root key;
   - every load refuses a store whose root key differs (`KeyChange`);
   - an anchor with the wrong owner or permissions is refused (`Insecure`).

   Because a same-user process cannot modify a root-owned file, this is what makes root-key replacement detectable.

### 4.3 Operational rules for keys

- Never keep a private key unencrypted in a directory the agent can read. Agents run as your user, and the engine's hook guard does not know where you keep keys.
- Use a distinct policy-signing key per person who approves policy. Label keys in the key set.
- Keep the root key offline. You need it only to rotate keys.

### 4.3.1 Encrypted key files (Phase 4)

`ai-defender init` generates the root and policy-signing keys and stores each sealed under your passphrase in `<trust root>/signing/{root,policy}.key` (mode 0600, created exclusively, never overwritten):

- Argon2id (19 MiB, 2 passes, 1 lane by default; weaker parameters than 1 MiB / 1 pass are refused) derives the key-encryption key from a passphrase of at least 12 characters.
- XChaCha20-Poly1305 encrypts the Ed25519 seed; the file header (role, KDF parameters, salt, public key) is authenticated as associated data, so a modified header fails to decrypt.
- Opening checks that the decrypted seed matches the recorded public key and role.

The trust store therefore holds private keys, but only in encrypted form; a same-user process needs the passphrase as well (KNOWN_LIMITATIONS L57). Back up both files. After setup, `root.key` can be moved offline: it is needed only for rotation and recovery.

### 4.4 Rotation

`rotate_keyset(new public keys, human, root signer)`:
1. Writes a new root-signed key set with an incremented version.
2. Re-issues every current object (global manifest, every approved project manifest, the registry, the integrity state) under the root key, in the same commit.

Signatures by a removed key therefore stop being current immediately, and a removed key can no longer sign updates. The high-water mark records the key-set version, so a forged integrity state that points back at an older key set is caught as a rollback.

Root-key rotation is done by recovery (§6) followed by re-initialisation with the new root key (and a new system anchor, if one is used).

## 5. Signing and verification

- **Algorithm.** Ed25519 (RFC 8032) via `ed25519-dalek` 2.2:
  - `verify_strict` rejects malleable signatures and small-order points;
  - weak public keys are refused at parse;
  - the RFC 8032 test vector 1 is part of the test suite.
- **Domain separation.** Every signed message is `agentguard.<purpose>.v1\0 ‖ canonical body`, with purpose one of `keyset`, `policy-manifest`, `registry`, `integrity`. A signature for one purpose cannot verify for another.
- **Canonical form.** The compact `serde_json` serialisation of the typed body. Trusted types hold no maps or floats, so the form is deterministic. Verification re-serialises the parsed body, so reformatting a file is harmless and any semantic edit breaks the signature.
- **Hashes.** SHA-256 throughout, used for policy content (`policy_hash`), manifest bodies (pins), key IDs (domain-separated, first 16 bytes) and project IDs.
- **Chain of pins.** The integrity state pins:
  - the root key ID;
  - the key set (version + body hash);
  - the global manifest;
  - the registry, which in turn pins each project's approved manifest.

  Every manifest and registry also carries the hash of the version it replaced.
- **Verification on every load,** in this order:
  1. directory and file safety: not a symlink (`O_NOFOLLOW`), owned by the user, not group/world-writable, at most 1 MiB;
  2. root anchor, plus system anchor if present;
  3. integrity root key ID;
  4. key set signed by root, and its pin;
  5. integrity signature;
  6. high-water mark;
  7. global manifest;
  8. registry;
  9. project manifests.

  Any failure fails the whole load. There is no partial trust.
- **Anti-rollback.** An object that is older than its pin is reported as `Rollback`; newer is `UnexpectedVersion`; same version with different content is `Replaced`. Replaying an older (validly signed) integrity state or key set is caught by the high-water mark.

## 6. Tamper detection, lockdown and recovery

`load_runtime` never errors. On any failure it returns `LockdownPolicy`, which denies **every** action with rule `trust.lockdown` and a reason naming the failure, and it records an audit event:

| Failure | Audit event |
|---|---|
| missing or unreadable state | `TrustedStateUnavailable` |
| invalid or untrusted signature | `SignatureVerificationFailed` |
| root or key-set substitution | `KeyChangeRejected` |
| older version | `RollbackDetected` |
| modified, replaced, inconsistent or insecure files; unexpected version | `PolicyIntegrityFailed` |
| registered project root replaced or symlinked | `ProjectIdentityMismatch` (that project is treated as unregistered) |

AI Defender never regenerates trusted state by itself, and updates against a tampered store are refused.

**Recovery path for an authorised human:**
1. Inspect the trust audit log (`audit/trust.jsonl`) and the store to understand what changed.
2. If the store can be restored from your own backup, restore it. Verification then succeeds again.
3. Otherwise call `quarantine(human)`. It moves the whole store aside to `<root>.quarantine-<timestamp>`, never deleting it, so it stays available for investigation. Every protected operation remains denied.
4. Re-run `initialize` with your root key. With a system anchor this must be the provisioned key.
5. Re-register projects and re-approve policies with your policy-signing key.

These operations are library functions in this phase. Their CLI commands arrive with the npm CLI phase, and the engine guard already denies agents running `ai-defender init|keys|rotate|recover|quarantine|register|revoke|policy|trust`.

## 7. Project registration

A registration records:
- the project ID (derived from the canonical root);
- the canonical root;
- trust status (`trusted` / `revoked`);
- the approved policy pin;
- the repository, optionally;
- the root directory's device and inode;
- the registration time.

Registration:
- canonicalises the path (symlinks and `..` resolved);
- rejects `/`, non-directories, and any path that contains or lies inside the trust store;
- requires a human requester and a policy-signing key.

At decision time a project matches only if its root is still the same directory: not a symlink, still canonical, same device and inode. The deepest registration wins, and a revoked or mismatched project is **not** replaced by an enclosing one, so trust is never inherited from a parent directory. A project ID supplied in a request is only a claim and must equal the registry's.

## 8. Policy updates

`update_policy(PolicyUpdateRequest { scope, policy, requested_by, reason }, signer)`:
1. Records `PolicyUpdateRequested`. If that cannot be recorded, the update is refused.
2. Requires a human requester (an agent gets `SelfApproval`).
3. Loads and fully verifies the current store.
4. Requires the signer to be a policy-signing key in the key set (otherwise `UnauthorizedSigner`).
5. Validates the layer: a project may not ALLOW, and every rule must be valid.
6. Checks baseline compatibility by building the merged effective policy.
7. Writes a new manifest, version + 1, chained to the old hash, then the new registry (for project scope), then the new integrity state, which is replaced atomically.
8. Records `PolicyUpdateAuthorized` with the old and new versions, or `PolicyUpdateRejected` with the reason.

There is no unsigned or development shortcut.
