# Security Invariants

Each invariant names where it is enforced and which tests prove it. Tests live in `tests/integration/tests/invariants.rs` unless another path is given. All of them run end to end: raw request bytes go into `Authorizer::authorize_bytes` against a real temporary project and the filesystem resolver.

A mutation check was run on 2026-10-30: each enforcement point below was disabled in turn. In every case the listed test failed (10 of 10 mutants caught). Repeat this check whenever an enforcement point moves.

| # | Invariant | Enforced in | Tests |
|---|---|---|---|
| 1 | Missing identity never produces an unauthorized allow | `agent` and `project` are required by the wire schema (`proto/request.rs`). Agent kind is verified against `TrustedInvocation` (`engine/identity.rs`). | `invariant_01_control_valid_identity_allows_read`, `invariant_01_missing_or_wrong_identity_denies`; proto `missing_identity_is_rejected` |
| 2 | Invalid requests never produce an allow | `parse_request`: size limit, `deny_unknown_fields`, duplicate keys, protocol version, per-field validation. `Authorizer::reject` always returns DENY. | `invariant_02_invalid_requests_deny`, `invariant_02_property_corruption_never_allows_invalid_input` (1,500 random corruptions); proto `property_parser_total_and_strict` (2,000 random byte strings, 2,000 field corruptions) |
| 3 | Unknown sensitive actions are denied | Unknown operations parse as `Unknown(name)`. `guard.unknown-operation` runs before policy. The baseline never allows terminal commands, custom tools or anything that is not read-only and low risk. | `invariant_03_unknown_operations_denied_even_if_policy_allows_category`, `invariant_03_unmodelled_actions_are_never_allowed_by_default`; engine `properties.rs` (unknown ⇒ DENY under random policies) |
| 4 | Agents cannot modify trusted authorization state | `TrustedStateGuard` denies non-read filesystem actions on the policy file, `.agentguard/`, hook settings files and AI Defender's state/config roots, including rename destinations and symlinked paths (resolved first). Terminal commands naming those paths are denied (best effort, see L27). | `invariant_04_trusted_state_writes_denied_despite_allow_rule`, `invariant_04_symlink_into_trusted_state_is_resolved_and_denied`, `invariant_04_rename_onto_policy_and_terminal_edits_denied` |
| 5 | Agents cannot approve their own privileged operations | The request schema has no approval field. `ApprovalGrant::new` refuses `Approver::Agent`. `guard.self-approval` denies `ai-defender approve/policy/grant/…` in commands. | `invariant_05_requests_cannot_carry_approvals`, `invariant_05_agent_principals_cannot_grant`, `invariant_05_agent_cannot_run_approval_commands` |
| 6 | Approval is bound to a specific operation | `OperationFingerprint` over action + agent + project + session + working directory + policy version. `consume` is single-use. Approvals apply only to `REQUIRE_APPROVAL`. | `invariant_06_approval_applies_once_to_exactly_its_operation`, `invariant_06_approval_cannot_override_a_denial`; engine `approval::tests::single_use_bound_and_expiring` |
| 7 | Changed authorization context requires re-evaluation | Any context change alters the fingerprint. `policy.version-mismatch` rejects stale requests. Grants expire within 300 s. | `invariant_07_session_or_directory_change_invalidates_approval`, `invariant_07_expired_approval_requires_new_approval`, `invariant_07_policy_change_invalidates_requests_and_approvals` |
| 8 | Security errors never silently permit execution | The authorizer has no error return. Policy, fingerprint and store failures become `engine.error`. Audit failure becomes `audit.unavailable`. `AuthorizationResponse::new` turns `REQUIRE_APPROVAL` without a fingerprint into DENY, and `check`/`permits_execution` reject inconsistent responses. | `invariant_08_policy_store_and_audit_failures_deny`; proto `response_keeps_approval_consistent` |
| 9 | Project identity is verified independently | The project is resolved from the symlink-resolved working directory through the trusted `ProjectRegistry`. The claimed root and ID must match. | `invariant_09_project_claims_must_match_registry`, `invariant_09_working_directory_symlink_cannot_fake_membership` |
| 10 | Security decisions are auditable | Every request records `AuthorizationRequested` before evaluation and a decision event after. Each carries request ID, decision, rule, risk, policy version, project and agent. Events are redacted and hash-chained. A decision that cannot be recorded is DENY. | `invariant_10_every_decision_is_recorded_correlated_and_chained`; audit `security::tests`, `jsonl_open_refuses_tampered_chain` |

Supporting properties:

| Property | Tests |
|---|---|
| Risk is separate from authorization (low-risk denied, high-risk approval, critical floor) | `risk_and_authorization_are_independent` |
| Policy evaluation is deterministic and independent of rule order | engine `property_rule_order_never_changes_verdict_or_version` |
| Final decision is never weaker than the policy verdict | engine `property_final_decision_never_weaker_than_policy_and_deterministic` |
| A policy cannot contain an unbounded ALLOW | `unbounded_allow_rules_are_refused` |
| Credentials never survive redaction | core `property_embedded_secrets_never_survive` (3,000 cases), `redact_text_assignments_headers_and_flags` |

## Phase 2: trusted policy, root of trust and tamper protection

Tests live in `crates/agentguard-trust/tests/invariants.rs`. They run against real trust stores on disk; decision-level tests drive the engine's `Authorizer` built from `load_runtime`. A mutation check was run on 2026-10-31: 13 enforcement points were each disabled in turn, and every one was caught by a named test (13 of 13).

| # | Invariant | Enforced in | Tests |
|---|---|---|---|
| 1 | Project policy cannot weaken the mandatory baseline | `hierarchy::validate_document` rejects project ALLOW rules. Mandatory and project rules are floors (`EffectivePolicy::evaluate`), so they can only raise a decision. | `inv01_project_allow_rules_are_rejected`, `inv01_restrictive_project_rule_cannot_lower_a_default`, `inv01_global_allow_cannot_lower_mandatory_floor`, `inv01_property_project_layer_is_monotonic` (300 random policies) |
| 2 | Invalid signatures are rejected | `Signed::verify` (Ed25519 `verify_strict`, purpose-separated, signer must be trusted) | `inv02_corrupted_signature_rejected`, `inv02_manifest_signed_by_untrusted_key_rejected`; unit `crypto::tests::*` incl. RFC 8032 vector |
| 3 | Modified trusted policies are detected | Canonical re-serialisation plus signature. File type, owner and permission checks with `O_NOFOLLOW`. | `inv03_policy_edit_detected_but_reformatting_is_not_an_edit`, `inv03_trusted_file_permission_and_symlink_tampering_detected` |
| 4 | Missing trusted state does not cause permissive fallback | `load_runtime` returns `LockdownPolicy` (deny all) on any load error | `inv04_uninitialised_store_locks_down`, `inv04_each_missing_trusted_file_locks_down` |
| 5 | Older policy versions cannot silently replace newer ones | `VersionRef::check` (`Rollback` / `UnexpectedVersion` / `Replaced`). `HighWaterMark` covers integrity and key-set versions. | `inv05_older_manifest_in_place_of_current_is_rollback`, `inv05_replaying_an_older_integrity_state_is_rollback`, `inv05_project_manifest_rollback_detected` |
| 6 | An AI agent cannot authorise its own policy changes | Every update requires `Approver::Human` and a key-set signer. The engine guard denies trust-store writes and AI Defender admin commands. | `inv06_agent_requester_rejected`, `inv06_unauthorised_key_cannot_sign_an_update`, `inv06_engine_denies_agent_writes_to_trust_store_and_policy_commands` |
| 7 | An unregistered project cannot claim trusted identity | `VerifiedRegistry` comes from the signed registry only. Revoked projects are not resolved. | `inv07_unregistered_and_revoked_projects_denied`, `inv07_injected_registry_entry_detected` |
| 8 | Project path manipulation cannot impersonate a registered project | Canonical registration. Directory identity (device + inode, not a symlink, canonical) is checked at decision time. No fallback to an enclosing project. | `inv08_recreated_directory_at_same_path_is_not_the_project`, `inv08_root_swapped_for_symlink_is_not_the_project`, `inv08_prefix_sibling_and_bad_registrations_rejected` |
| 9 | Policy merge results are deterministic | Namespaced rules, order-independent combination, version over canonical sorted layers | `inv09_property_merge_is_order_independent_and_repeatable` (100 shuffles) |
| 10 | Integrity failures prevent protected operations | Lockdown denies every action, including reads. Updates against a tampered store are refused. | `inv10_any_integrity_failure_denies_everything` |
| 11 | Trusted public keys cannot be replaced by untrusted configuration | Keys are read only from the trust store. The key set must be root-signed. The integrity state pins the root key ID. The optional system anchor pins the root key. Rotation requires the root key. | `inv11_keys_and_manifests_in_the_project_are_ignored`, `inv11_replacing_root_or_keyset_in_the_store_is_a_key_change`, `inv11_rotation_requires_the_root_key`, `inv11_system_anchor_pins_the_root_key` |
| 12 | A valid project policy can add restrictions without weakening global rules | Project floors on top of the global result. Repository edits are drift, not policy. | `inv12_project_restrictions_apply_on_top_of_global`, `inv12_policy_file_changes_are_drift_not_policy` |

Also covered: `rotation_retires_old_key_and_keeps_policy`, `recovery_is_explicit_and_never_regenerates_in_place`, `trust_events_never_contain_key_material`.

## Phase 3: policy and permission evaluation engine

Tests live in `tests/integration/tests/evaluation.rs` (end to end through the `Authorizer` and the `evaluate` API, against a real project, a fake home directory with an SSH key, and the filesystem resolver), plus unit tests in `normalize`, `resource`, `classify`, `rules`, `pattern` and `profile`. A mutation check was run on 2026-10-31: 16 enforcement points were each disabled in turn, and every one was caught by a named test (16 of 16). Four of them are additionally backed by a second layer (unit test plus integration test, or two independent rules).

| # | Invariant | Enforced in | Tests |
|---|---|---|---|
| 1 | Mandatory deny rules always win | Mandatory rules are floors (`LayeredPolicy`); a DENY outranks any priority (`rules::evaluate_layer`) | `inv01_mandatory_deny_beats_high_priority_global_allow` |
| 2 | Project allow rules cannot override global restrictions | `LayeredPolicy::new` and trust `validate_document` reject project ALLOW | `inv02_project_allow_rules_are_rejected`; trust `inv01_project_allow_rules_are_rejected` |
| 3 | User-level restrictions cannot be weakened by project configuration | Project rules are floors applied after the global verdict | `inv03_project_rules_never_weaken_global_restrictions`, `project_floor_raises_but_never_lowers` |
| 4 | Invalid identities never receive ALLOW | `EvaluationContext::establish` (trusted invocation, registry) | `inv04_invalid_identity_never_allowed` |
| 5 | Invalid policy integrity never receives ALLOW | `evaluate` refuses a policy whose `integrity()` is `Failed` | `inv05_failed_policy_integrity_never_allowed`; trust `inv10_*` |
| 6 | Missing required context fails closed | Wire schema requires every field; `evaluate` checks request ⇄ context consistency | `inv06_missing_or_mismatched_context_fails_closed` |
| 7 | Same request and policy → same decision | Pure evaluation, order-independent layers, versioned canonical policy | `inv07_property_same_request_same_decision_regardless_of_rule_order` (20 shuffles × 14 actions); engine `properties.rs` |
| 8 | Conflicts resolve to the most restrictive decision | `evaluate_layer` (DENY first, then restrictive within top priority), floors | `inv08_conflicts_resolve_to_most_restrictive_and_are_reported` |
| 9 | Unknown sensitive operations are not automatically allowed | Guard denies unknown operations; uncertainty → `profile.uncertain` (never ALLOW) | `inv09_unknown_operations_are_not_automatically_allowed` |
| 10 | Harmless development operations remain usable | Balanced profile ALLOW rules (ordinary resource, confidence ≥ medium) | `inv10_harmless_development_operations_are_allowed` (25 actions), `balanced_profile_*` |
| 11 | Path traversal cannot bypass resource restrictions | Resolved paths only; case-insensitive sensitive-name classification | `inv11_path_traversal_cannot_bypass_resource_restrictions`, `inv11_property_random_traversals_to_the_key_never_allow` (200 cases) |
| 12 | Symlink escapes are handled or rejected | `FsPathResolver` for typed paths *and* terminal path arguments; dangling links rejected | `inv12_symlink_escapes_are_resolved_or_rejected` |
| 13 | Risk classification cannot override mandatory policy | Floors and the critical floor apply after any risk-bounded rule | `inv13_risk_bounds_on_rules_cannot_slip_under_mandatory_floors` |
| 14 | Invalid action metadata cannot produce ALLOW | Protocol validation of every new category and field | `inv14_invalid_action_metadata_never_allowed` |
| 15 | Audit records never contain raw secrets | Terminal summaries keep only safe argument shapes; redaction on write | `inv15_audit_never_contains_raw_secrets`; `normalize::tests::summary_masks_values_and_secrets` |
| 16 | The engine never executes the requested operation | No process spawning (`clippy.toml` disallows `Command::new`); evaluation is read-only | `inv16_evaluation_never_executes_the_requested_operation` |

Also covered: `adversarial_property_safe_prefix_never_launders_a_dangerous_suffix` (5 safe × 9 dangerous × 8 compositions), `configurable_profile_settings_change_defaults_but_not_floors`, `rule_resource_patterns_and_executables`.

## Phase 4: CLI, installation and project initialisation

Tests live in `crates/agentguard-engine-cli/tests/engine.rs` (the engine binary's protocol, against isolated trust stores), `cli/test/*.test.ts` (the TypeScript CLI against fake engines, against the real engine in temporary XDG homes, and static checks of its own source), and unit tests in `agentguard-trust` (`keyfile`, `project_file`) and `agentguard-engine` (`guard`).

| # | Requirement | Enforced in | Tests |
|---|---|---|---|
| 1 | CLI cannot directly overwrite trusted policy state | The CLI has no file-writing code; every change is an engine command that needs the signing key | static `the CLI never writes files`; engine `wrong_passphrase_registers_nothing_and_writes_no_config`, `tampered_trust_is_reported_and_blocks_changes` |
| 2 | Project configuration cannot override mandatory baseline rules | `parse_project_config` rejects ALLOW; approved rules are floors | engine `project_config_cannot_weaken_the_baseline`; CLI `policy show … project config cannot weaken it`; trust `rejects_allow_rules_unknown_fields_and_versions` |
| 3 | Invalid Rust binary signatures are rejected | `verifyEnginePackage` (Ed25519 manifest, key ID, platform, protocol, sha256) | `tampered binaries, manifests and signatures are rejected`; `release scripts produce a package the CLI verifies, and an unsigned package fails` |
| 4 | Missing Rust binaries never result in permissive behaviour | `resolveEngine` has no fallback; `callEngine` spawn failure is exit 3 | `a missing engine binary is unavailable, never a success`; `engine resolution: unsupported platforms, missing packages and the development override` |
| 5 | Unsupported protocol versions fail safely | Engine rejects `protocol_version ≠ 1`; CLI rejects responses with another version; manifests must declare protocol 1 | engine `protocol_rejects_malformed_oversized_and_incompatible_requests`; `engine response validation accepts only well-formed, matching responses` |
| 6 | Malformed engine responses are rejected | `validateResponse` (exact keys, request ID, success/data/error and exit status agree, bounded size, timeout) | `malformed, mismatched or oversized engine output is rejected`; `a hung engine is killed after the timeout` |
| 7 | CLI cannot manufacture an ALLOW decision | No engine command returns a decision; the CLI's source cannot construct one | static `the CLI has no way to produce an authorization decision` |
| 8 | Project initialisation cannot bypass trust registration | `project.init` always registers through the signed registry (confirmation + passphrase); the guard denies agents `ai-defender init/project/trust/register` | engine `init_requires_confirmation_and_passphrase_before_writing_anything`, `init_sets_up_trust_registers_and_is_idempotent`; guard `terminal_best_effort` |
| 9 | Existing project configuration is never silently overwritten | `write_initial_config` refuses if any configuration exists (`create_new`) | trust `writes_valid_config_once`; engine `init_sets_up_trust_registers_and_is_idempotent`; CLI `init is idempotent and never overwrites existing configuration` |
| 10 | Path traversal cannot escape intended configuration directories | Absolute, normalised working directories only; symlinked `.agentguard` refused; `O_NOFOLLOW`; roots containing the trust store refused; engine binary must resolve inside its package | engine `symlinked_config_directory_and_unsafe_roots_are_refused`; trust `symlinks_and_ambiguity_are_refused`; `binary paths cannot escape the package, directly or through symlinks` |
| 11 | Shell injection is prevented | `spawn(path, [], {shell: false})`; arguments travel as JSON on stdin | `paths with spaces and shell metacharacters are passed as data, never interpreted`; static `the CLI never invokes a shell` |
| 12 | Sensitive information is not printed in terminal output | Passphrases never echoed or returned; engine text sanitised | CLI `unregistered directories are reported, and outputs never contain the passphrase`; `terminal output is sanitized and colour is opt-out` |
| 13 | JSON output does not expose private keys or raw secrets | Responses carry key IDs only; key files are never serialised | same test (asserts no passphrase, `ciphertext`, `seed` or `PRIVATE KEY` in any `--json` output); keyfile `passphrase_rules_and_debug` |
| 14 | Project revocation cannot be silently skipped | `project.revoke` needs confirmation and the passphrase, and reports failure otherwise | engine `revoke_requires_confirmation_and_authorization_and_is_not_skipped`; CLI `project list, inspect and revocation with explicit confirmation` |
| 15 | Non-interactive mode does not bypass required authorisation | Without `--yes` → exit 6; without `--passphrase-file` → exit 6; the passphrase is never read from env or argv | CLI `non-interactive init cannot bypass confirmation or authorization`; static `secrets are never read from the environment or the command line`; engine `passphrase_file_must_be_private` |

## Phase 5: human approval and authorization grants

Design: [APPROVALS.md](APPROVALS.md). Test files: `crates/agentguard-trust/tests/approvals.rs`
(trust), `crates/agentguard-engine-cli/tests/approvals.rs` (engine), `cli/test/approvals.test.ts`
(CLI), plus unit tests in `binding.rs`, `token.rs`, `guard.rs`, `hierarchy.rs` and the audit
crate.

| # | Invariant | Enforcement point | Tests |
|---|---|---|---|
| 1 | An AI agent cannot approve its own request | engine refuses `approval.approve` under `--agent`; approval needs the passphrase and a trusted signer; guard denies agent commands running `approve`/`reject`/`approvals`/the engine binary | engine `an_agent_cannot_approve_even_with_the_passphrase`; guard `terminal_best_effort`; CLI `approve refuses every non-human route…` |
| 2 | An AI agent cannot manufacture a grant | grants are Ed25519-signed by a trusted policy key (purpose `approval-grant`) and verified at every redemption | trust `a_manufactured_or_edited_grant_is_rejected`, `only_a_trusted_policy_key_can_approve` |
| 3 | An approval authorizes one exact operation | digest over the canonical operation; compared at redemption | binding `every_bound_field_changes_the_digest`; trust `a_grant_authorizes_only_its_exact_operation_project_and_agent`; engine `an_approval_binds_the_exact_operation_and_agent` |
| 4 | Changing one protected argument invalidates approval | same | binding `every_bound_field_changes_the_digest`, `file_and_database_targets_are_bound`; engine (`feature-a` vs `main`); CLI interactive approval test |
| 5 | Changing project identity invalidates approval | project id and root in the digest; project compared at redemption | binding (project); trust (`ProjectMismatch`) |
| 6 | Changing agent identity invalidates approval | agent in the digest; trusted invocation; agent compared at redemption | engine `an_approval_binds_the_exact_operation_and_agent` (Codex, claimed agent); trust (`AgentMismatch`) |
| 7 | Expired approvals cannot issue grants | expiry checked inside the approve transaction | trust `expired_requests_cannot_be_approved…`; engine `expiry_reject_cancel_and_revoke` |
| 8 | Expired grants cannot be consumed | expiry checked inside the redeem transaction; permanent once observed | same tests |
| 9 | Consumed grants cannot be reused | `active → consumed` inside one locked transaction | trust `full_lifecycle…`, `state_survives_restart_and_replay_is_still_refused`; engine `end_to_end…`; CLI interactive test |
| 10 | Two concurrent consumptions cannot both succeed | exclusive `flock` per transaction | trust `concurrent_consumers_cannot_both_succeed` (16 threads × 5 rounds; fails with a shared lock); engine `concurrent_engine_processes_consume_a_grant_at_most_once` (8 processes) |
| 11 | Rejected requests cannot issue grants | approve requires `pending` | trust `pending_rejected_and_cancelled_requests_authorize_nothing`; engine `expiry_reject_cancel_and_revoke` |
| 12 | Cancelled requests cannot issue grants | same | same |
| 13 | Revoked grants cannot be consumed | redeem requires grant state `active` | trust `revoked_grants_cannot_be_consumed`; engine `expiry_reject_cancel_and_revoke`; CLI revoke test |
| 14 | Policy changes invalidate incompatible grants | policy version compared at approve and redeem (strict equality); grant voided | trust `policy_changes_invalidate_pending_requests_and_grants`; engine `a_policy_change_between_approval_and_use_voids_the_grant` |
| 15 | Mandatory (and any) deny rules override prior approvals | redemption evaluates policy before consulting the store; `DENY` voids the approval | engine `deny_after_approval_wins_and_policy_changes_void_grants`; mandatory-denied operations never get a request: `denied_and_unbindable_operations_never_create_approvals` |
| 16 | A project policy cannot authorize its own security-policy modification | guard denies writes to `.agentguard`/policy files before policy; project policy cannot contain ALLOW rules or approval timing | engine `denied_and_unbindable_operations_never_create_approvals`; hierarchy `approval_timing_is_global_only_and_bounded` |
| 17 | Non-interactive mode cannot silently approve | CLI requires a TTY and refuses `--non-interactive`; engine accepts no passphrase file for approval | CLI `approve refuses every non-human route…`; engine `approval_needs_confirmation_and_the_passphrase_never_a_flag_or_file` |
| 18 | `--yes` cannot bypass human authorization | CLI refuses `--yes` for approve before asking anything; only the typed word `approve` proceeds | CLI `approve refuses…`, `only the typed word approve approves…`; static `approval cannot be automated…` |
| 19 | A forged approval ID cannot authorize an operation | IDs are references; redemption needs the claim token and a signed grant | trust `a_forged_approval_id_or_token_authorizes_nothing`; engine (`approval-not-found`, guessed token) |
| 20 | Raw authorization secrets never appear in audit logs | only verifiers are stored; events carry IDs and digests | trust `no_token_or_verifier_reaches_audit_records_or_views`; engine `end_to_end…` (audit file); CLI `listings and JSON output never expose…`; audit `approval_records_correlate_without_arguments` |
| 21 | Database failures cannot produce false successful authorization | required audit events; store errors fail closed; consumed grants never restored | trust `audit_failure_never_yields_a_usable_grant_or_a_reported_success`, `storage_failures_fail_closed` |
| 22 | Invalid identity or policy integrity cannot produce a valid grant | redemption and approval load the verified runtime; lockdown is an error; identity verified first | engine `tampered_trusted_state_never_produces_or_honours_a_grant`, `agent_commands_need_an_integration_launch`, `an_approval_binds_the_exact_operation_and_agent` (claimed agent) |

## Phase 6: sensitive files, secret detection and disclosure

Design: [SECRETS.md](SECRETS.md). Test files: `tests/integration/tests/secrets.rs` (policy, end to
end through the `Authorizer`), `crates/agentguard-secrets/tests/scanner.rs` (scanner, redaction,
Git index, properties, performance), `crates/agentguard-engine-cli/tests/secrets.rs` (engine
commands), `cli/test/secrets.test.ts` and `cli/test/static.test.ts` (CLI). Enforcement points were
mutation-checked: disabling any of the three mandatory secret rules, the `.env` floor, configured
patterns, bare-argument resolution, written-content inspection, file-content inspection,
staged-change inspection or the sensitivity audit steps fails at least one test (10 of 10).

| # | Invariant | Enforcement point | Tests |
|---|---|---|---|
| 1 | `.env` content is never exposed to an unauthorized agent request | `profile:sensitive-read` (DENY), `mandatory:environment-file` (approval floor), `mandatory:secret-disclosure`, `mandatory:secret-into-ordinary-file`; `sensitive_read: ALLOW` rejected | `inv01_env_content_is_never_exposed_without_authorization` |
| 2 | Private key contents never appear in ordinary audit logs | private-key blocks replaced whole by redaction; key files are not content-inspected | `inv02_inv13_secrets_are_redacted_from_audit_records`; secrets `redacts_lines_and_key_blocks` |
| 3 | Secret values are never printed in CLI diagnostic output | engine returns redacted previews only; CLI output redaction | CLI `scan finds secrets, prints only redacted previews…`, `explain reviews a finding…`, `preview lists…` |
| 4 | Detected credentials cannot be committed under the mandatory baseline | `mandatory:secret-commit` over staged inspection (`.git/index`) | `inv04_staged_credentials_cannot_be_committed` (real Git, global ALLOW present) |
| 5 | Project configuration cannot weaken mandatory secret protections | project rules cannot ALLOW; sensitive decisions only in the global profile, never ALLOW; project `sensitive` only adds | `inv05_project_configuration_only_adds_protection`; hierarchy tests |
| 6 | Path traversal cannot reach protected files outside the boundary | resolved paths classified; scan paths confined (`resolve_within`) | `inv06_inv07_traversal_and_symlinks_reach_the_real_target`; scanner `symlinks_are_never_followed_and_paths_cannot_escape`; engine `paths_are_confined…` |
| 7 | Symlink escapes are handled safely | resolver follows links to the real target; existing bare terminal arguments resolved; scanner never follows links, `O_NOFOLLOW` | same tests |
| 8 | False positives can be reviewed without exposing the value | `secrets explain` from stored findings without values | engine `explain_describes_a_finding_without_its_value`; CLI explain test |
| 9 | Binary files are handled safely | NUL detection, skipped and listed | scanner `binary_large_and_special_files_are_skipped_and_reported`, `random_bytes_never_panic` |
| 10 | Large files do not cause unbounded memory use | size limits, streaming, 64 KiB line segments | scanner `long_lines_are_scanned_in_bounded_segments`, `binary_large…`, `limits_mark_the_scan_incomplete` |
| 11 | Excluded files are reported as excluded, not clean | exclusions listed with their rule; incomplete scans flagged | scanner `excluded_files_are_reported_as_excluded_never_clean`; engine and CLI exclusion tests |
| 12 | External disclosure of detected secrets is denied | `mandatory:secret-disclosure` | `inv12_inv17_secret_disclosure_is_denied_wherever_it_would_go` |
| 13 | Secret-bearing command arguments are redacted where supported | `redact_text` + detector spans; `SecretRedacted` step | `inv02_inv13_…`; secrets `redaction_property_fake_tokens_never_survive` |
| 14 | Audit failure cannot result in false successful authorization | sensitivity steps are part of the decision; a failed write is `audit.unavailable` DENY | `inv14_audit_failure_never_authorizes` |
| 15 | The scanner never uploads source code or secrets | no network code in the secrets crate or the CLI | secrets `the_crate_has_no_network_or_process_code`; CLI static `the CLI has no network access…` |
| 16 | Ordinary source files remain usable under the balanced profile | profile ALLOW rules for ordinary files; only `high`+ detections drive policy | `inv16_ordinary_source_files_remain_usable` |
| 17 | Unknown destinations get no implicit secret-disclosure permission | `unknown` counts as external | `inv12_inv17_…` (interpreter, upload without a host) |
| 18 | A detected secret cannot be retrieved from finding metadata | IDs from location and detector; previews keep only public prefixes; no hashes | secrets `finding_metadata_cannot_recover_the_secret`; engine record test |

## Phase 7: Git security, terminal command governance and controlled execution

Design: [EXECUTION.md](EXECUTION.md). Test files: `crates/agentguard-engine-cli/tests/execution.rs`
(end to end through `execution.run` against temporary repositories and a local bare remote),
unit tests in `crates/agentguard-exec` (shell subset, Git parsing, environment, executable
resolution, process runner, redaction), `crates/agentguard-engine` (force detection, quoting
round trip, binding), `cli/test/execution.test.ts` (CLI, including the live approval wait).

Enforcement points were mutation-checked: 13 distinct mutants, 11 caught. The caught ones
disabled:
- the idempotency reservation;
- staged-tree binding;
- environment filtering;
- the trusted search path;
- shell expansion refusal;
- the force-push rule;
- host scan evidence;
- output redaction;
- the time limit;
- the protected-destruction rule;
- the repository-inside-project check.

The trusted-search-path and repository-inside-project mutants first survived. Both exposed
test gaps (a group-writable test directory; no monorepo case), and both are caught after
tightening the tests.

The two survivors are redundant layers:
- the requested-name check for refused programs. The resolved-name check refuses too, and the
  set-ID check stops `sudo`.
- push-source binding. The named ref is also bound; a double mutant removing both is caught.

Revalidation between grant consumption and spawn is not mutation-tested: no test can change the
repository inside that window.

| # | Invariant | Enforcement point | Tests |
|---|---|---|---|
| 1 | Git push requires approval by default | `mandatory:git-push`, `mandatory:terminal-vcs-remote` | `push_requires_approval_bound_to_remote_and_branch_once`; CLI push test |
| 2 | Force push is denied unless a stronger trusted policy allows approval | `profile:git-force-push` (`git_force_push`, default DENY, ALLOW rejected) over the `Force` condition (typed and terminal); `mandatory:git-force-push` approval floor | `force_push_is_denied_unless_trusted_policy_permits_approval`; engine `git_force_is_structured`; profile settings test |
| 3 | A Git approval cannot authorize a different remote or branch | argv digest plus `git.push.*` and `git.ref.*` binding | `push_requires_approval_bound_to_remote_and_branch_once`; CLI `HEAD:other` case |
| 4 | A commit approval cannot include changed staged content | `git.staged-tree` binding (`git write-tree`); commit verification of the recorded tree | `a_commit_approval_cannot_include_changed_staged_content` |
| 5 | Detected secrets prevent prohibited commits (and pushes) | staged and push-range scans passed as `HostInspection` evidence; `mandatory:secret-commit`, `mandatory:secret-disclosure` | `detected_secrets_prevent_commits_and_pushes` |
| 6 | Destructive shell operations are denied according to policy | `profile:destructive-protected`, `profile:permission-protected` (`protected_destruction`), `mandatory:terminal-destructive-critical` | `destructive_commands_against_protected_locations_are_denied` |
| 7 | Injection cannot escape the managed argument structure | argv executed without a shell; `quote_argv` round trip for policy | `arguments_cannot_escape_their_structure`; `quoted_argv_round_trips_through_the_lexer` |
| 8 | Unsupported shell syntax never executes in protected mode | strict parser; canonical rendering executed | `unsupported_shell_syntax_never_executes`; shell unit tests and fuzz property |
| 9 | Agent identity cannot be forged | identity from the launch (`--agent`) or generic; request fields rejected; grants bound to agent | `agent_identity_cannot_be_forged` |
| 10 | Project identity cannot be forged | registry lookup of the resolved working directory; request fields rejected | `project_identity_cannot_be_forged` |
| 11 | Approval grants cannot be reused | Phase 5 atomic consume; replay detected | `push_requires_approval_bound_to_remote_and_branch_once`; CLI replay case |
| 12 | Changed operation context invalidates approval | digest recomputed from fresh inspection at redemption; revalidation before spawn | `a_moved_branch_invalidates_a_push_approval`, `a_repointed_source_branch_invalidates_a_push_approval`, commit test |
| 13 | Environment secrets are not exposed in logs | `env_clear` + profiles; credential and injection names never passed; withheld values masked in output; records list names only | `environment_secrets_are_not_exposed`; environment unit tests; `output_redaction` |
| 14 | Child-process output is bounded | `poll` reader keeps 128 KiB per stream, counts the rest | `child_output_is_bounded`; `output_is_bounded` |
| 15 | Execution timeouts are handled safely | group `SIGTERM` then `SIGKILL`; leftovers killed; `timed-out` recorded | `timeouts_are_handled_safely`; `timeouts_terminate_the_whole_group`, `leftover_background_processes…` |
| 16 | A failed audit write cannot produce a false success | audit before start (fail closed); `outcome-unrecorded` after | `a_failed_audit_write_never_produces_a_run`; CLI exit-code mapping |
| 17 | Unrestricted direct execution is not reported as protected | `enforcement` block on every outcome, history and `status` | `direct_execution_is_never_reported_as_protected`; CLI help and JSON tests |
| 18 | Arbitrary commands cannot invoke internal executors without authorization | private process module behind a sealed `Permit`; no protocol command bypasses `execute` | `internal_executors_cannot_be_invoked_directly`; `compile_fail` doctest |
| 19 | Executable path manipulation is handled safely | trusted search path (no project, relative, or group/other-writable directories); identity bound and rechecked; wrappers, set-ID and AI Defender refused | `executable_path_manipulation_is_handled`; validation unit tests |
| 20 | No automatic retry of uncertain external side effects | idempotency key reserved with `O_EXCL`; nothing retried; stale `started` shown as indeterminate | `requests_are_never_run_twice` |

## Phase 8: Claude Code and Codex hook integrations

Design: [HOOKS.md](HOOKS.md). Tests:
- `crates/agentguard-engine-cli/tests/hooks.rs`: 13 tests through `run_hook` and
  `integrations.*`, with isolated HOME, trust store and repository.
- Unit tests in `crates/agentguard-hooks`: payloads, patches, installer, response shapes.
- `crates/agentguard-engine` guard tests: `~/` and `$HOME/` spellings.
- `cli/test/integrations.test.ts`: CLI, plus the real `hook` process end to end.

Mutation checks: 7 of 7 hook enforcement-point mutants are caught. They disable, in turn:
- fail-closed invalid payloads;
- the agent-configuration guard;
- tool-input binding;
- Git-fact binding;
- written-content inspection;
- the agent identity taken from the command line;
- pending-request reuse.

The identity mutant first survived, because `hook.provider` binding already prevented
cross-provider redemption. It is caught after the test also checked the recorded agent.

| # | Invariant | Enforcement point | Tests |
|---|---|---|---|
| 1 | Claude Code payloads cannot manufacture ALLOW | payload decision fields never read; AI Defender never answers `allow` | `payloads_cannot_manufacture_allow` |
| 2 | Codex payloads cannot manufacture ALLOW | same, separate parser | `payloads_cannot_manufacture_allow` |
| 3 | Project identity is independently validated | registry lookup of the resolved cwd or target path; payload `project` ignored | `identities_are_independently_established` |
| 4 | Agent identity cannot be forged through payload fields | agent from `hook <provider>`; `hook.provider` bound into the digest | `identities_are_independently_established` |
| 5 | Invalid payloads never produce ALLOW | validation failures, oversize, schema changes and unreadable patches are denied | `invalid_payloads_never_allow`; input and patch unit tests |
| 6 | Invalid policy integrity blocks protected operations | lockdown → deny `policy.integrity` | `integrity_failure_blocks` |
| 7 | Sensitive file reads follow Phase 6 policy | same evaluator (`profile:sensitive-read`) | `sensitive_files_and_secret_disclosure_follow_phase_6` |
| 8 | Detected secret disclosure follows Phase 6 policy | written text and push range scanned as host evidence; mandatory secret rules | same test |
| 9 | Git push requires approval by default | Phase 7 policy via the hook | `push_approval_is_exact_and_single_use`; CLI end to end |
| 10 | Changing the approved operation invalidates authorization | digest over tool input, content and Git facts | `push_approval_is_exact_and_single_use`, `write_approvals_are_bound_to_content` |
| 11 | Consumed grants cannot be reused | Phase 5 atomic consume | `push_approval_is_exact_and_single_use` |
| 12 | A hook cannot approve its own request | guard denies agent `ai-defender approve` and the engine binary; agent-launched engine refuses approval | `hooks_cannot_approve_or_weaken_anything` |
| 13 | A hook cannot modify the mandatory baseline | guard covers trust store, project policy, agent hook settings, engine binary (incl. `~/` spellings); install and uninstall refused under `--agent` | same test; guard unit test |
| 14 | Hook timeouts do not silently permit protected operations | Claude Code `onFailure: "block"`; Codex `\|\| exit 2`; internal failures deny | `install_verify_and_uninstall` (config shape); `the_hook_process_fails_closed`; limitations L98, L99 |
| 15 | Missing engine behaviour is accurately reported | status checks every configured handler's engine; Codex command exits 2 without it | `install_verify_and_uninstall` |
| 16 | Unrelated user hook configuration remains intact after installation | installer edits only marked handlers; backup first | `install_verify_and_uninstall`; installer unit tests; CLI install test |
| 17 | Uninstall removes only AI Defender-managed configuration | same; exact restoration asserted | same tests |
| 18 | Informational events are not reported as blocking enforcement | capabilities per event; post-tool and session hooks never block | `informational_events_never_block` |
| 19 | Unsupported tools are not reported as protected | coverage table; anchored matcher | `coverage_is_honest_and_unknowns_are_blocked` |
| 20 | Direct-execution bypass paths are documented and tested | coverage rows (direct commands, `write_stdin`, hosted tools, opt-out paths); `global_enforcement: false` | same test; HOOKS.md §9 |
| 21 | Hook output matches the official provider schema | exact key-set assertions on the deny shape; SessionStart shape | `assert_schema` in several tests; verify's synthetic checks |
| 22 | Provider-specific error responses are handled safely | unknown provider or event exits 2; Codex-unsupported fields (`ask`, `continue`) never emitted | `coverage_is_honest_and_unknowns_are_blocked` |
