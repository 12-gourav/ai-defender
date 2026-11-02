//! Commands that change trusted state or project files: project.init, project.trust,
//! project.revoke.
//!
//! Each requires `confirm: true` and, for any change to trusted state, the policy-signing key
//! passphrase. Checks run before anything is written, so a refused request leaves no partial
//! configuration behind. Every change goes through the trust layer's authorised workflows
//! (human requester, signing key, validation, audit).

use agentguard_core::Name;
use agentguard_core::{BoundedText, NormalizedPath};
use agentguard_engine::ProfileName;
use agentguard_trust::canonical::ContentHash;
use agentguard_trust::keyfile::{generate_sealed_with, write_key_file, Passphrase, SigningRole};
use agentguard_trust::project_file::{
    load_project_config, write_initial_config, ConfigSource, LoadedConfig, ProjectConfigError,
    ProjectMetadata,
};
use agentguard_trust::registry::canonical_project_root;
use agentguard_trust::{
    initialize, register_project, revoke_project, update_policy, Ed25519Signer, PolicyDocument,
    PolicyScope, PolicyUpdateRequest, ProjectRegistration, TrustStatus,
};
use serde::Deserialize;
use serde_json::{json, Value};
use time::OffsetDateTime;

use crate::protocol::{EngineError, ErrorCode};
use crate::support::{
    args, detect_kind, detect_root, directory_matches, load_trust, passphrase, registered_for,
    requester, require_confirmation, trust_error, unlock, verified, working_directory, TrustView,
};
use crate::Environment;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InitArgs {
    working_directory: String,
    #[serde(default)]
    profile: Option<String>,
    #[serde(default)]
    name: Option<String>,
    confirm: bool,
    #[serde(default)]
    setup_trust: bool,
    requested_by: String,
    #[serde(default)]
    passphrase: Option<String>,
    #[serde(default)]
    passphrase_file: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChangeArgs {
    working_directory: String,
    confirm: bool,
    requested_by: String,
    #[serde(default)]
    passphrase: Option<String>,
    #[serde(default)]
    passphrase_file: Option<String>,
}

fn config_error(e: &ProjectConfigError) -> EngineError {
    let code = match e {
        ProjectConfigError::Io { .. } => ErrorCode::IoError,
        _ => ErrorCode::InvalidConfiguration,
    };
    EngineError::new(code, e.to_string())
}

fn profile_name(raw: Option<&str>) -> Result<ProfileName, EngineError> {
    match raw {
        None | Some("balanced") => Ok(ProfileName::Balanced),
        Some(_) => Err(EngineError::new(
            ErrorCode::InvalidRequest,
            "unknown profile; available profiles: balanced",
        )),
    }
}

/// Lazily unlocked policy signer: the passphrase is asked for only when a change needs it.
struct Authority<'a> {
    env: &'a Environment,
    inline: Option<String>,
    file: Option<String>,
    unlocked: Option<Ed25519Signer>,
}

impl Authority<'_> {
    fn passphrase(&mut self) -> Result<Passphrase, EngineError> {
        passphrase(self.inline.take(), self.file.take())
    }

    fn signer(&mut self) -> Result<&Ed25519Signer, EngineError> {
        if self.unlocked.is_none() {
            let phrase = self.passphrase()?;
            self.unlocked = Some(unlock(
                &self.env.store,
                SigningRole::Policy,
                &phrase,
                self.env.clock.now(),
            )?);
        }
        self.unlocked
            .as_ref()
            .ok_or_else(|| EngineError::new(ErrorCode::InternalError, "signer unavailable"))
    }
}

/// Create the trust store: root and policy keys sealed with `phrase`, then `initialize`.
fn setup_trust(
    env: &Environment,
    phrase: &Passphrase,
    requested_by: &agentguard_engine::approval::Approver,
    label: Name,
    now: OffsetDateTime,
) -> Result<Ed25519Signer, EngineError> {
    let key_error = |e: agentguard_trust::keyfile::KeyFileError| {
        EngineError::new(ErrorCode::IoError, e.to_string())
    };
    let (root_sealed, root) =
        generate_sealed_with(SigningRole::Root, phrase, env.kdf, now).map_err(key_error)?;
    let (policy_sealed, policy) =
        generate_sealed_with(SigningRole::Policy, phrase, env.kdf, now).map_err(key_error)?;
    // Keys first: a failure afterwards leaves keys without a store (recoverable), never a store
    // nobody can sign for.
    write_key_file(&env.store.signing_key_path(SigningRole::Root), &root_sealed)
        .map_err(key_error)?;
    write_key_file(
        &env.store.signing_key_path(SigningRole::Policy),
        &policy_sealed,
    )
    .map_err(key_error)?;
    initialize(&env.store, &root, &policy, label, requested_by, now)
        .map_err(|e| trust_error(&e))?;
    Ok(policy)
}

/// Approve the configuration's restrictions if they differ from the approved ones.
fn approve_restrictions(
    env: &Environment,
    authority: &mut Authority<'_>,
    registration: &ProjectRegistration,
    config: Option<&LoadedConfig>,
    requested_by: &agentguard_engine::approval::Approver,
) -> Result<Option<String>, EngineError> {
    let proposed = config.map(LoadedConfig::policy).unwrap_or_default();
    let trust = verified(&env.store)?;
    let approved = trust
        .project_policies
        .get(&registration.id)
        .map(|m| m.policy_hash);
    let proposed_hash = ContentHash::of(&proposed).map_err(|e| trust_error(&e))?;
    let unchanged = approved == Some(proposed_hash)
        || (approved.is_none() && proposed == PolicyDocument::default());
    if unchanged {
        return Ok(registration.approved_policy.map(|v| v.to_string()));
    }
    let receipt = update_policy(
        &env.store,
        PolicyUpdateRequest {
            scope: PolicyScope::Project(registration.id),
            policy: proposed,
            requested_by: requested_by.clone(),
            reason: BoundedText::lossy(
                "project restrictions approved from the project configuration",
            ),
        },
        authority.signer()?,
        OffsetDateTime::now_utc(),
        &env.store.open_audit_log().map_err(|e| trust_error(&e))?,
    )
    .map_err(|e| trust_error(&e))?;
    Ok(Some(receipt.current.to_string()))
}

fn project_summary(
    env: &Environment,
    root: &NormalizedPath,
) -> Result<(ProjectRegistration, Value), EngineError> {
    let trust = verified(&env.store)?;
    let registration = registered_for(root, &trust.registry)
        .filter(|r| &r.root == root && r.status == TrustStatus::Trusted && directory_matches(r))
        .cloned()
        .ok_or_else(|| {
            EngineError::new(
                ErrorCode::IntegrityFailure,
                "registration did not validate after it was written",
            )
        })?;
    let profile = trust.global.policy.profile.clone().unwrap_or_default().name;
    Ok((registration, json!({ "effective_profile": profile })))
}

/// `project.init`.
pub fn init(env: &Environment, arguments: Value) -> Result<Value, EngineError> {
    let a: InitArgs = args(arguments)?;
    let cwd = working_directory(&a.working_directory)?;
    let profile = profile_name(a.profile.as_deref())?;
    let who = requester(&a.requested_by)?;
    let label = Name::new(a.requested_by.clone())
        .map_err(|_| EngineError::new(ErrorCode::InvalidRequest, "invalid requested_by"))?;
    let name = a
        .name
        .as_deref()
        .map(BoundedText::<100>::new)
        .transpose()
        .map_err(|_| {
            EngineError::new(
                ErrorCode::InvalidRequest,
                "name must be at most 100 printable characters",
            )
        })?;
    require_confirmation(a.confirm, "initialising AI Defender in a project")?;

    let trust_state = load_trust(&env.store);
    let registered = match &trust_state {
        TrustView::Verified(t) => registered_for(&cwd, &t.registry).cloned(),
        TrustView::Failed(e) => return Err(trust_error(e)),
        TrustView::Uninitialized => None,
    };
    if let Some(r) = &registered {
        if r.status == TrustStatus::Revoked {
            return Err(EngineError::new(
                ErrorCode::ProjectRevoked,
                "this project's trust was revoked",
            )
            .recovery("re-trust it deliberately with `ai-defender project trust`"));
        }
        if !directory_matches(r) {
            return Err(EngineError::new(
                ErrorCode::IntegrityFailure,
                "the registered project directory was replaced since registration",
            )
            .recovery("revoke the registration and register the project again"));
        }
    }
    let root = registered
        .as_ref()
        .map_or_else(|| detect_root(&cwd), |r| r.root.clone());
    if registered.is_none() {
        // The same validation registration applies, before anything is written.
        canonical_project_root(root.as_path(), env.store.root()).map_err(|e| trust_error(&e))?;
    }
    let kind = detect_kind(&root);
    let existing = load_project_config(&root).map_err(|e| config_error(&e))?;

    let mut authority = Authority {
        env,
        inline: a.passphrase,
        file: a.passphrase_file,
        unlocked: None,
    };
    let now = OffsetDateTime::now_utc();
    let created_trust = matches!(trust_state, TrustView::Uninitialized);
    if created_trust {
        if !a.setup_trust {
            return Err(EngineError::new(
                ErrorCode::TrustNotInitialized,
                "no AI Defender trust store exists on this machine",
            )
            .recovery("run `ai-defender init` interactively to create it"));
        }
        let phrase = authority.passphrase()?;
        authority.unlocked = Some(setup_trust(env, &phrase, &who, label, now)?);
    }
    let created_registration = registered.is_none();
    if created_registration {
        // Unlock before writing anything to the project, so a wrong passphrase leaves no trace.
        authority.signer()?;
    }
    let (config_path, created_config) = if let Some(loaded) = &existing {
        (source_path(&loaded.source), false)
    } else {
        let metadata = ProjectMetadata {
            name,
            kind: kind.and_then(|k| BoundedText::new(k).ok()),
        };
        let path = write_initial_config(&root, metadata, profile).map_err(|e| config_error(&e))?;
        (path.to_string_lossy().into_owned(), true)
    };
    let registration = if created_registration {
        register_project(
            &env.store,
            root.as_path(),
            None,
            &who,
            authority.signer()?,
            now,
            &env.store.open_audit_log().map_err(|e| trust_error(&e))?,
        )
        .map_err(|e| trust_error(&e))?
    } else {
        registered
            .clone()
            .ok_or_else(|| EngineError::new(ErrorCode::InternalError, "registration missing"))?
    };
    let config = load_project_config(&registration.root).map_err(|e| config_error(&e))?;
    let approved = approve_restrictions(env, &mut authority, &registration, config.as_ref(), &who)?;
    let (registration, profile_info) = project_summary(env, &registration.root)?;
    let effective = profile_info
        .get("effective_profile")
        .cloned()
        .unwrap_or(Value::Null);
    Ok(json!({
        "root": registration.root,
        "project_id": registration.id,
        "kind": kind,
        "config": { "path": config_path, "created": created_config },
        "trust_store": { "path": env.store.root(), "created": created_trust },
        "registration": { "created": created_registration, "status": registration.status },
        "project_policy": { "approved": approved },
        "profile": { "requested": profile, "effective": effective, "matches": effective == json!(profile) },
        "next_steps": [
            "review the project configuration and add restrictions if needed",
            "run `ai-defender check` to verify the installation",
            "AI Defender enforces nothing for an agent until its hooks are installed: run `ai-defender integrations install claude|codex`",
        ],
    }))
}

fn source_path(source: &ConfigSource) -> String {
    match source {
        ConfigSource::ConfigYaml(p) | ConfigSource::Legacy(p) => p.to_string_lossy().into_owned(),
    }
}

/// `project.trust`: re-trust a revoked project (or register one with existing configuration)
/// and approve its restrictions.
pub fn trust(env: &Environment, arguments: Value) -> Result<Value, EngineError> {
    let a: ChangeArgs = args(arguments)?;
    let cwd = working_directory(&a.working_directory)?;
    let who = requester(&a.requested_by)?;
    require_confirmation(a.confirm, "trusting a project")?;
    let trust = verified(&env.store)?;
    let existing = registered_for(&cwd, &trust.registry).cloned();
    let root = existing
        .as_ref()
        .map_or_else(|| detect_root(&cwd), |r| r.root.clone());
    let config = load_project_config(&root).map_err(|e| config_error(&e))?;
    let mut authority = Authority {
        env,
        inline: a.passphrase,
        file: a.passphrase_file,
        unlocked: None,
    };
    let needs_registration = existing
        .as_ref()
        .is_none_or(|r| r.status == TrustStatus::Revoked || !directory_matches(r));
    let registration = if needs_registration {
        if existing
            .as_ref()
            .is_some_and(|r| r.status == TrustStatus::Trusted)
        {
            return Err(EngineError::new(
                ErrorCode::IntegrityFailure,
                "the registered project directory was replaced since registration",
            )
            .recovery("revoke the registration first with `ai-defender project revoke`"));
        }
        register_project(
            &env.store,
            root.as_path(),
            None,
            &who,
            authority.signer()?,
            OffsetDateTime::now_utc(),
            &env.store.open_audit_log().map_err(|e| trust_error(&e))?,
        )
        .map_err(|e| trust_error(&e))?
    } else {
        existing
            .clone()
            .ok_or_else(|| EngineError::new(ErrorCode::InternalError, "registration missing"))?
    };
    let approved = approve_restrictions(env, &mut authority, &registration, config.as_ref(), &who)?;
    let (registration, _) = project_summary(env, &registration.root)?;
    Ok(json!({
        "root": registration.root,
        "project_id": registration.id,
        "registration": { "changed": needs_registration, "status": registration.status },
        "project_policy": { "approved": approved },
    }))
}

/// `project.revoke`.
pub fn revoke(env: &Environment, arguments: Value) -> Result<Value, EngineError> {
    let a: ChangeArgs = args(arguments)?;
    let cwd = working_directory(&a.working_directory)?;
    let who = requester(&a.requested_by)?;
    require_confirmation(a.confirm, "revoking a project's trust")?;
    let trust = verified(&env.store)?;
    let Some(registration) = registered_for(&cwd, &trust.registry).cloned() else {
        return Err(EngineError::new(
            ErrorCode::NotRegistered,
            "this directory is not inside a registered project",
        ));
    };
    if registration.status == TrustStatus::Revoked {
        return Err(EngineError::new(
            ErrorCode::ProjectRevoked,
            "this project's trust is already revoked",
        ));
    }
    let mut authority = Authority {
        env,
        inline: a.passphrase,
        file: a.passphrase_file,
        unlocked: None,
    };
    revoke_project(
        &env.store,
        &registration.id,
        &who,
        authority.signer()?,
        OffsetDateTime::now_utc(),
        &env.store.open_audit_log().map_err(|e| trust_error(&e))?,
    )
    .map_err(|e| trust_error(&e))?;
    let after = verified(&env.store)?;
    let status = after.registry.get(&registration.id).map(|r| r.status);
    if status != Some(TrustStatus::Revoked) {
        return Err(EngineError::new(
            ErrorCode::IntegrityFailure,
            "revocation did not validate after it was written",
        ));
    }
    Ok(json!({ "root": registration.root, "project_id": registration.id, "status": status }))
}
