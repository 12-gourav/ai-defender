//! Agent hook integrations: the hook entry point and the `integrations.*` commands.
//!
//! | command | effect | authority |
//! |---|---|---|
//! | `integrations.list` | providers, events, documentation sources | none |
//! | `integrations.status` | installed entries, engine checks, provider version, last health check, coverage | none |
//! | `integrations.coverage` | protected, observed, unsupported and bypassable paths | none |
//! | `integrations.verify` | configuration, permissions, engine identity, trusted state, synthetic hook checks; records the result | none |
//! | `integrations.install` | add AgentGuard's hook entries (backup first, idempotent) | confirmation; refused under `--agent` |
//! | `integrations.uninstall` | remove only AgentGuard's entries | confirmation and the policy-key passphrase; refused under `--agent` |
//!
//! The hook entry point (`agentguard-engine hook <provider> <event>`) is [`run_hook`].

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use agentguard_audit::{AuditSink, MemorySink};
use agentguard_hooks::coverage::{rows, NOT_COMPLETE};
use agentguard_hooks::install::{self, config_path, file_sha256, inspect};
use agentguard_hooks::provider::{ADAPTER_VERSION, DOCS_VERIFIED};
use agentguard_hooks::{HookEnv, HookResponse, Provider};
use agentguard_trust::keyfile::SigningRole;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::protocol::{EngineError, ErrorCode};
use crate::support::{args, passphrase, require_confirmation, unlock, verified};
use crate::Environment;

/// Claude Code release that honours `onFailure: "block"`.
pub const CLAUDE_ON_FAILURE: (u64, u64, u64) = (2, 1, 295);

/// Run one hook invocation.
#[must_use]
pub fn run_hook(env: &Environment, provider: &str, event: &str, payload: &[u8]) -> HookResponse {
    let audit = env
        .store
        .open_audit_log()
        .ok()
        .map(|s| Arc::new(s) as Arc<dyn AuditSink>);
    let hook_env = HookEnv {
        store: &env.store,
        clock: &*env.clock,
        caller_env: &env.process_env,
        engine_path: env.engine_path.as_deref(),
    };
    agentguard_hooks::run(&hook_env, provider, event, payload, audit)
}

/// The value at a JSON pointer, or null.
fn at<'a>(v: &'a Value, pointer: &str) -> &'a Value {
    static NULL: Value = Value::Null;
    v.pointer(pointer).unwrap_or(&NULL)
}

fn provider_arg(raw: &str) -> Result<Provider, EngineError> {
    Provider::parse(raw).ok_or_else(|| {
        EngineError::new(
            ErrorCode::InvalidRequest,
            "provider must be claude or codex",
        )
    })
}

fn not_for_agents(env: &Environment, what: &str) -> Result<(), EngineError> {
    if env.invocation.is_some() {
        return Err(EngineError::new(
            ErrorCode::AuthorizationFailed,
            format!("{what} is refused when the engine is launched for an agent"),
        ));
    }
    Ok(())
}

fn records_dir(env: &Environment) -> PathBuf {
    env.store.root().join("integrations")
}

fn record_path(env: &Environment, p: Provider) -> PathBuf {
    records_dir(env).join(format!("{}.json", p.as_str()))
}

fn load_record(env: &Environment, p: Provider) -> Option<Value> {
    let bytes = fs::read(record_path(env, p)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn save_record(env: &Environment, p: Provider, v: &Value) -> Result<(), EngineError> {
    let io = || {
        EngineError::new(
            ErrorCode::IoError,
            "the integration record could not be written",
        )
    };
    let dir = records_dir(env);
    match DirBuilder::new().mode(0o700).create(&dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(io()),
    }
    if !fs::symlink_metadata(&dir).is_ok_and(|m| m.is_dir()) {
        return Err(io());
    }
    let path = record_path(env, p);
    let tmp = dir.join(format!(".{}.{}", p.as_str(), std::process::id()));
    let _ = fs::remove_file(&tmp);
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
        .open(&tmp)
        .map_err(|_| io())?;
    let bytes = serde_json::to_vec_pretty(v).map_err(|_| io())?;
    f.write_all(&bytes)
        .and_then(|()| f.sync_all())
        .map_err(|_| io())?;
    fs::rename(&tmp, &path).map_err(|_| io())
}

fn now(env: &Environment) -> Value {
    env.clock
        .now()
        .format(&time::format_description::well_known::Rfc3339)
        .map_or(Value::Null, Value::String)
}

/// Problems with the engine binary as a hook executable.
fn engine_problems(path: &Path) -> Vec<&'static str> {
    let mut problems = Vec::new();
    if !path.is_absolute() {
        problems.push("the engine path is not absolute");
    }
    match fs::metadata(path) {
        Ok(m) => {
            if !m.is_file() || m.mode() & 0o111 == 0 {
                problems.push("the engine is not an executable file");
            }
            if m.mode() & 0o022 != 0 {
                problems.push("the engine is writable by group or others");
            }
            let me = nix::unistd::getuid().as_raw();
            if m.uid() != me && m.uid() != 0 {
                problems.push("the engine is owned by another user");
            }
        }
        Err(_) => problems.push("the engine binary does not exist"),
    }
    if path
        .parent()
        .and_then(|d| fs::metadata(d).ok())
        .is_some_and(|m| m.mode() & 0o022 != 0)
    {
        problems.push("the engine's directory is writable by group or others");
    }
    problems
}

/// A verified copy of the running engine inside the trust store
/// (`engine/<version>-<sha256 prefix>/agentguard-engine`), which hooks run. The npm package's
/// location changes with Node versions, npm prefixes and upgrades; this copy does not, and the
/// trusted-state guard keeps agents from changing it. An existing copy with the right hash is
/// reused; a new one is written beside it, re-hashed, and renamed into place.
///
/// `expected` is the SHA-256 the CLI verified against the signed release manifest. When it is
/// given, the bytes copied must have exactly that hash, so the copy is the signed release even
/// if the npm-installed file is writable by others.
pub fn stable_engine(env: &Environment, expected: Option<&str>) -> Result<PathBuf, EngineError> {
    let io = |what: &str| {
        EngineError::new(
            ErrorCode::IoError,
            format!("the engine copy could not be {what}"),
        )
    };
    let source = engine_path(env)?;
    let sha = file_sha256(&source).ok_or_else(|| io("read"))?;
    if expected.is_some_and(|e| !e.eq_ignore_ascii_case(&sha)) {
        return Err(EngineError::new(
            ErrorCode::IntegrityFailure,
            "the engine binary changed after the CLI verified it against the signed release manifest; nothing was installed",
        ));
    }
    let base = env.store.root().join("engine");
    let dir = base.join(format!(
        "{}-{}",
        env!("CARGO_PKG_VERSION"),
        sha.get(..12).unwrap_or(&sha)
    ));
    let dest = dir.join("agentguard-engine");
    if file_sha256(&dest).as_deref() == Some(sha.as_str()) && engine_problems(&dest).is_empty() {
        return Ok(dest);
    }
    for d in [&base, &dir] {
        match DirBuilder::new().mode(0o700).create(d) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(io("created")),
        }
        if !fs::symlink_metadata(d).is_ok_and(|m| m.is_dir()) {
            return Err(io("created"));
        }
    }
    let tmp = dir.join(format!(".agentguard-engine.{}.tmp", std::process::id()));
    // The written copy is re-hashed below; a source that changes mid-copy is rejected there.
    let bytes = fs::read(&source).map_err(|_| io("read"))?;
    let _ = fs::remove_file(&tmp);
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o755)
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
        .open(&tmp)
        .map_err(|_| io("written"))?;
    f.write_all(&bytes)
        .and_then(|()| f.sync_all())
        .map_err(|_| io("written"))?;
    drop(f);
    if file_sha256(&tmp).as_deref() != Some(sha.as_str()) {
        let _ = fs::remove_file(&tmp);
        return Err(io("verified"));
    }
    fs::rename(&tmp, &dest).map_err(|_| io("installed"))?;
    Ok(dest)
}

fn engine_path(env: &Environment) -> Result<PathBuf, EngineError> {
    env.engine_path.clone().ok_or_else(|| {
        EngineError::new(
            ErrorCode::InternalError,
            "the engine cannot determine its own path",
        )
    })
}

fn compatibility(p: Provider, version: Option<&str>) -> Value {
    let parsed = version.and_then(agentguard_exec::probe::semver);
    match p {
        Provider::Claude => match parsed {
            Some(v) if v >= CLAUDE_ON_FAILURE => {
                json!({"state": "compatible", "fails_closed_on_hook_failure": true})
            }
            Some(_) => json!({"state": "degraded", "fails_closed_on_hook_failure": false,
                "detail": "Claude Code before 2.1.295 ignores onFailure: a crashed or timed-out AI Defender hook lets the tool call continue"}),
            None => json!({"state": "unknown", "fails_closed_on_hook_failure": null,
                "detail": "the Claude Code version could not be determined; behaviour on hook failure is unverified"}),
        },
        Provider::Codex => json!({
            "state": if parsed.is_some() { "unverified" } else { "unknown" },
            "fails_closed_on_hook_failure": null,
            "detail": "Codex documents no version-specific hook changes; the hook command exits 2 when the engine cannot start, and Codex does not document timeout behaviour",
        }),
    }
}

fn provider_status(env: &Environment, p: Provider, probe: bool) -> Value {
    let config = config_path(p, &env.process_env);
    let installed = config.as_ref().ok().map(|c| inspect(p, c));
    let record = load_record(env, p);
    let current = env.engine_path.clone();
    let engines = installed
        .as_ref()
        .map(|i| i.engines.clone())
        .unwrap_or_default();
    let engine_in_config = engines.first().cloned();
    // Every configured handler must run the same, intact engine.
    let engine_problems = (!engines.is_empty()).then(|| {
        let mut problems: Vec<&'static str> = engines
            .iter()
            .flat_map(|e| engine_problems(Path::new(e)))
            .collect();
        if engines.len() > 1 {
            problems.push("the handlers run different engine binaries");
        }
        problems.dedup();
        problems
    });
    let recorded_sha = record
        .as_ref()
        .and_then(|r| at(r, "/engine_sha256").as_str().map(str::to_owned));
    let shas: Vec<Option<String>> = engines.iter().map(|e| file_sha256(Path::new(e))).collect();
    let first_sha = shas.first().cloned().flatten();
    let engine_sha = if shas.iter().all(|s| s.is_some() && *s == first_sha) {
        first_sha
    } else {
        None
    };
    let version = if probe {
        agentguard_exec::probe::version(p.as_str(), &env.process_env)
    } else {
        None
    };
    let all_events = installed.as_ref().is_some_and(|i| {
        p.events()
            .iter()
            .all(|e| i.events.iter().any(|x| x == e.name))
    });
    let healthy = record
        .as_ref()
        .and_then(|r| {
            r.pointer("/last_health_check/passed")
                .and_then(Value::as_bool)
        })
        .unwrap_or(false);
    let fails_closed = installed.as_ref().is_some_and(|i| i.fails_closed);
    let engine_ok = engine_problems.as_ref().is_some_and(Vec::is_empty)
        && recorded_sha.is_some()
        && recorded_sha == engine_sha;
    let running_sha = if engines.is_empty() {
        None
    } else {
        current.as_deref().and_then(file_sha256)
    };
    let up_to_date = running_sha.is_some() && running_sha == engine_sha;
    let state = match (&installed, all_events) {
        (Some(i), _) if i.events.is_empty() => "not-installed",
        (Some(_), true) if engine_ok && fails_closed && up_to_date => "installed",
        (Some(_), true) if engine_ok && fails_closed => "outdated",
        (Some(_), _) => "degraded",
        (None, _) => "unavailable",
    };
    json!({
        "provider": p,
        "name": p.display(),
        "state": state,
        "config_path": config.as_ref().ok(),
        "config_error": config.as_ref().err().map(ToString::to_string),
        "installed": installed,
        "engine": {
            "configured": engine_in_config,
            "current": current,
            "same_build_as_running_engine": up_to_date,
            "sha256_matches_install": recorded_sha.is_some() && recorded_sha == engine_sha,
            "problems": engine_problems,
        },
        "provider_version": version,
        "compatibility": compatibility(p, version.as_deref()),
        "adapter_version": ADAPTER_VERSION,
        "documentation_verified": DOCS_VERIFIED,
        "documentation": p.documentation(),
        "events": p.events(),
        "last_health_check": record.as_ref().and_then(|r| r.get("last_health_check").cloned()),
        "health_ok": healthy,
        "enforcement": if state == "installed" {
            "pre-execution hooks installed: the protected tools listed by `ai-defender integrations coverage` are evaluated before they run in registered projects; this is not complete protection"
        } else {
            "not enforcing: AI Defender does not see this provider's tool calls"
        },
        "notes": match p {
            Provider::Claude => "Claude Code holds back settings-file hooks in an interactive session until the folder's workspace trust dialog is accepted.",
            Provider::Codex => "Codex skips new or changed hooks until you review and trust them with /hooks in Codex.",
        },
    })
}

/// One-line integration state for `status`.
#[must_use]
pub fn summary(env: &Environment) -> Value {
    let providers: Vec<Value> = Provider::ALL
        .iter()
        .map(|p| {
            let s = provider_status(env, *p, false);
            json!({"provider": p, "state": at(&s, "/state")})
        })
        .collect();
    let any = providers.iter().any(|p| at(p, "/state") == "installed");
    json!({
        "state": if any { "configured" } else { "not-configured" },
        "providers": providers,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderArgs {
    #[serde(default)]
    provider: Option<String>,
}

fn selected(a: &ProviderArgs) -> Result<Vec<Provider>, EngineError> {
    match &a.provider {
        Some(p) => Ok(vec![provider_arg(p)?]),
        None => Ok(Provider::ALL.to_vec()),
    }
}

/// `integrations.list`.
pub fn list(_env: &Environment, arguments: Value) -> Result<Value, EngineError> {
    let _: ProviderArgs = args(arguments)?;
    Ok(json!({
        "integrations": Provider::ALL.iter().map(|p| json!({
            "provider": p,
            "name": p.display(),
            "events": p.events(),
            "documentation": p.documentation(),
            "documentation_verified": DOCS_VERIFIED,
        })).collect::<Vec<_>>(),
        "adapter_version": ADAPTER_VERSION,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusArgs {
    #[serde(default)]
    provider: Option<String>,
    /// Run `<provider> --version` (default true; summaries pass false to stay fast).
    #[serde(default)]
    probe: Option<bool>,
}

/// `integrations.status`.
pub fn status(env: &Environment, arguments: Value) -> Result<Value, EngineError> {
    let a: StatusArgs = args(arguments)?;
    let probe = a.probe.unwrap_or(true);
    let providers = selected(&ProviderArgs {
        provider: a.provider,
    })?;
    Ok(json!({
        "integrations": providers.iter().map(|p| provider_status(env, *p, probe)).collect::<Vec<_>>(),
        "global_enforcement": false,
        "statement": NOT_COMPLETE,
    }))
}

/// `integrations.coverage`.
pub fn coverage(_env: &Environment, arguments: Value) -> Result<Value, EngineError> {
    let a: ProviderArgs = args(arguments)?;
    Ok(json!({
        "coverage": selected(&a)?.iter().map(|p| json!({"provider": p, "name": p.display(), "rows": rows(*p)})).collect::<Vec<_>>(),
        "statement": NOT_COMPLETE,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallArgs {
    provider: String,
    confirm: bool,
    /// SHA-256 the CLI verified against the signed release manifest (release engines).
    #[serde(default)]
    engine_sha256: Option<String>,
}

/// Problems that make an engine unusable even as the source of the protected copy.
fn fatal_engine_problem(problem: &str) -> bool {
    !problem.contains("writable by group or others")
}

/// `integrations.install`.
pub fn install_command(env: &Environment, arguments: Value) -> Result<Value, EngineError> {
    not_for_agents(env, "installing an integration")?;
    let a: InstallArgs = args(arguments)?;
    let p = provider_arg(&a.provider)?;
    require_confirmation(a.confirm, "installing agent hooks")?;
    verified(&env.store)?;
    let running = engine_path(env)?;
    let (fatal, warnings): (Vec<&str>, Vec<&str>) = engine_problems(&running)
        .into_iter()
        .partition(|p| fatal_engine_problem(p));
    if !fatal.is_empty() {
        return Err(EngineError::new(
            ErrorCode::InvalidConfiguration,
            format!("the engine cannot be used: {}", fatal.join("; ")),
        ));
    }
    let engine = stable_engine(env, a.engine_sha256.as_deref())?;
    let copy_problems = engine_problems(&engine);
    if !copy_problems.is_empty() {
        return Err(EngineError::new(
            ErrorCode::InvalidConfiguration,
            format!(
                "the protected engine copy cannot be used as a hook executable: {}",
                copy_problems.join("; ")
            ),
        ));
    }
    let path = config_path(p, &env.process_env)
        .map_err(|e| EngineError::new(ErrorCode::InvalidConfiguration, e.0))?;
    let change = install::install(p, &path, &engine, &records_dir(env).join("backups"))
        .map_err(|e| EngineError::new(ErrorCode::InvalidConfiguration, e.0))?;
    let version = agentguard_exec::probe::version(p.as_str(), &env.process_env);
    save_record(
        env,
        p,
        &json!({
            "provider": p,
            "installed_at": now(env),
            "config_path": path,
            "engine_path": engine,
            "engine_sha256": file_sha256(&engine),
            "events": p.events().iter().map(|e| e.name).collect::<Vec<_>>(),
            "backup": change.backup,
            "adapter_version": ADAPTER_VERSION,
            "documentation_verified": DOCS_VERIFIED,
            "provider_version": version,
        }),
    )?;
    Ok(json!({
        "provider": p,
        "config_path": path,
        "changed": change.changed,
        "backup": change.backup,
        "handlers_added": change.added,
        "handlers_replaced": change.removed,
        "warnings": warnings.iter().map(|w| format!("the npm-installed engine: {w}; hooks run the protected copy instead")).collect::<Vec<_>>(),
        "compatibility": compatibility(p, version.as_deref()),
        "next": match p {
            Provider::Claude => "Restart Claude Code sessions; in an interactive session accept the workspace trust dialog. Then run `ai-defender integrations verify`.",
            Provider::Codex => "Open Codex and review and trust the new hooks with /hooks (Codex skips untrusted hooks). Then run `ai-defender integrations verify`.",
        },
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RepairArgs {
    confirm: bool,
    #[serde(default)]
    engine_sha256: Option<String>,
}

fn install_args(p: Provider, sha: Option<&str>) -> Value {
    let mut v = json!({"provider": p.as_str(), "confirm": true});
    if let (Some(sha), Some(map)) = (sha, v.as_object_mut()) {
        map.insert("engine_sha256".into(), json!(sha));
    }
    v
}

/// `integrations.repair`: re-point every installed integration whose hooks are degraded or
/// outdated at a fresh verified copy of the running engine, and reinstall missing entries.
/// Never touches trusted state: if it does not verify, nothing is repaired.
pub fn repair_command(env: &Environment, arguments: Value) -> Result<Value, EngineError> {
    not_for_agents(env, "repairing integrations")?;
    let a: RepairArgs = args(arguments)?;
    require_confirmation(a.confirm, "repairing agent hooks")?;
    verified(&env.store)?;
    let mut actions = Vec::new();
    for p in Provider::ALL {
        let status = provider_status(env, p, false);
        let state = at(&status, "/state")
            .as_str()
            .unwrap_or("unavailable")
            .to_owned();
        let action = match state.as_str() {
            "installed" => json!({"provider": p, "action": "none", "state": state}),
            "not-installed" | "unavailable" => {
                json!({"provider": p, "action": "skipped", "state": state, "detail": "not installed"})
            }
            _ => {
                let result = install_command(env, install_args(p, a.engine_sha256.as_deref()))?;
                json!({"provider": p, "action": "reinstalled", "previous_state": state, "config_path": result.get("config_path"), "backup": result.get("backup")})
            }
        };
        actions.push(action);
    }
    Ok(json!({ "actions": actions }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UninstallArgs {
    provider: String,
    confirm: bool,
    requested_by: String,
    #[serde(default)]
    passphrase: Option<String>,
    #[serde(default)]
    passphrase_file: Option<String>,
}

/// `integrations.uninstall`: removing hooks removes protection, so it needs the passphrase.
pub fn uninstall_command(env: &Environment, arguments: Value) -> Result<Value, EngineError> {
    not_for_agents(env, "removing an integration")?;
    let a: UninstallArgs = args(arguments)?;
    let p = provider_arg(&a.provider)?;
    require_confirmation(a.confirm, "removing agent hooks")?;
    crate::support::requester(&a.requested_by)?;
    let phrase = passphrase(a.passphrase, a.passphrase_file)?;
    verified(&env.store)?;
    unlock(&env.store, SigningRole::Policy, &phrase, env.clock.now())?;
    let path = config_path(p, &env.process_env)
        .map_err(|e| EngineError::new(ErrorCode::InvalidConfiguration, e.0))?;
    let change = install::uninstall(p, &path, &records_dir(env).join("backups"))
        .map_err(|e| EngineError::new(ErrorCode::InvalidConfiguration, e.0))?;
    let _ = fs::remove_file(record_path(env, p));
    Ok(json!({
        "provider": p,
        "config_path": path,
        "changed": change.changed,
        "handlers_removed": change.removed,
        "backup": change.backup,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SystemUninstallArgs {
    confirm: bool,
    requested_by: String,
    #[serde(default)]
    passphrase: Option<String>,
    #[serde(default)]
    passphrase_file: Option<String>,
    /// Also delete the trust store (signing keys, policy, registry, audit history).
    #[serde(default)]
    purge: bool,
    /// Must be exactly "purge" when `purge` is set.
    #[serde(default)]
    purge_confirmation: Option<String>,
}

/// `system.uninstall`: remove everything AI Defender installed outside its npm package: every
/// agent integration (other hooks and settings are kept, with a backup) and the verified engine
/// copies. The trust store is kept unless `purge` is set with its own confirmation.
///
/// When signing keys exist the passphrase is required, whether or not the rest of the trust
/// store verifies: the owner must always be able to remove the product, and a damaged store
/// must not turn into a way around the password. Without keys nothing is protected, so
/// confirmation suffices. The npm package itself is removed by the CLI afterwards.
pub fn system_uninstall(env: &Environment, arguments: Value) -> Result<Value, EngineError> {
    not_for_agents(env, "uninstalling AI Defender")?;
    let a: SystemUninstallArgs = args(arguments)?;
    require_confirmation(a.confirm, "uninstalling AI Defender")?;
    crate::support::requester(&a.requested_by)?;
    if a.purge && a.purge_confirmation.as_deref() != Some("purge") {
        return Err(EngineError::new(
            ErrorCode::ConfirmationRequired,
            "deleting the trust store needs purge_confirmation \"purge\"",
        )
        .recovery("type purge when asked, or pass --purge --yes deliberately"));
    }
    let root = env.store.root().to_path_buf();
    let protected = env.store.signing_key_path(SigningRole::Policy).exists();
    if protected {
        let phrase = passphrase(a.passphrase, a.passphrase_file)?;
        unlock(&env.store, SigningRole::Policy, &phrase, env.clock.now())?;
    }
    let mut integrations = Vec::new();
    let mut failed = false;
    for p in Provider::ALL {
        let outcome = config_path(p, &env.process_env)
            .map_err(|e| e.0)
            .and_then(|path| {
                install::uninstall(p, &path, &records_dir(env).join("backups"))
                    .map(|change| (path, change))
                    .map_err(|e| e.0)
            });
        match outcome {
            Ok((path, change)) => {
                let _ = fs::remove_file(record_path(env, p));
                integrations.push(json!({
                    "provider": p,
                    "config_path": path,
                    "handlers_removed": change.removed,
                    "backup": change.backup,
                }));
            }
            Err(error) => {
                failed = true;
                integrations.push(json!({ "provider": p, "error": error }));
            }
        }
    }
    if failed {
        return Err(EngineError::new(
            ErrorCode::InvalidConfiguration,
            format!(
                "some agent integrations could not be removed; nothing else was changed: {}",
                Value::Array(integrations)
            ),
        )
        .recovery("fix the reported configuration file, then run the uninstall again"));
    }
    let engines = root.join("engine");
    let engines_removed = match fs::remove_dir_all(&engines) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => {
            return Err(EngineError::new(
                ErrorCode::IoError,
                format!(
                    "the engine copies in {} could not be removed",
                    engines.display()
                ),
            ))
        }
    };
    let projects: Vec<String> = verified(&env.store)
        .map(|t| {
            t.registry
                .projects
                .iter()
                .map(|p| p.root.as_path().join(".agentguard").display().to_string())
                .collect()
        })
        .unwrap_or_default();
    let mut purged = false;
    if a.purge {
        let named_for_us = root.file_name().is_some_and(|n| n == "agentguard");
        if !named_for_us || root.parent().is_none() {
            return Err(EngineError::new(
                ErrorCode::InvalidConfiguration,
                format!(
                    "refusing to delete {}: not an AI Defender trust store",
                    root.display()
                ),
            ));
        }
        match fs::remove_dir_all(&root) {
            Ok(()) => purged = true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(EngineError::new(
                    ErrorCode::IoError,
                    format!("the trust store {} could not be deleted", root.display()),
                ))
            }
        }
    }
    Ok(json!({
        "integrations": integrations,
        "engine_copies_removed": engines_removed,
        "password_verified": protected,
        "trust_store": root,
        "trust_store_deleted": purged,
        "project_configurations": projects,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifyArgs {
    #[serde(default)]
    provider: Option<String>,
    #[serde(default)]
    working_directory: Option<String>,
}

fn check(id: &str, passed: bool, detail: impl Into<String>) -> Value {
    json!({"id": id, "passed": passed, "detail": detail.into()})
}

fn synthetic(env: &Environment, p: Provider, cwd: &str) -> Vec<Value> {
    let quiet: Arc<dyn AuditSink> = Arc::new(MemorySink::new());
    let hook_env = HookEnv {
        store: &env.store,
        clock: &*env.clock,
        caller_env: &env.process_env,
        engine_path: env.engine_path.as_deref(),
    };
    let blocks = |r: &HookResponse| {
        r.exit_code == agentguard_hooks::respond::BLOCK_EXIT
            || r.stdout
                .as_deref()
                .is_some_and(|s| s.contains("\"permissionDecision\":\"deny\""))
    };
    let pre = |payload: Value| {
        agentguard_hooks::run(
            &hook_env,
            p.as_str(),
            "PreToolUse",
            payload.to_string().as_bytes(),
            Some(Arc::clone(&quiet)),
        )
    };
    let invalid = agentguard_hooks::run(
        &hook_env,
        p.as_str(),
        "PreToolUse",
        b"{not json",
        Some(Arc::clone(&quiet)),
    );
    let approve = pre(
        json!({"session_id": "health", "cwd": cwd, "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_use_id": "h1", "tool_input": {"command": "agentguard approve 00000000"}}),
    );
    let config = config_path(p, &env.process_env)
        .map(|c| c.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tamper = match p {
        Provider::Claude => pre(
            json!({"session_id": "health", "cwd": cwd, "hook_event_name": "PreToolUse", "tool_name": "Write", "tool_use_id": "h2", "tool_input": {"file_path": config, "content": "{}"}}),
        ),
        Provider::Codex => pre(
            json!({"session_id": "health", "cwd": cwd, "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_use_id": "h2", "tool_input": {"command": format!("rm {config}")}}),
        ),
    };
    let session = agentguard_hooks::run(
        &hook_env,
        p.as_str(),
        "SessionStart",
        json!({"session_id": "health", "cwd": cwd, "hook_event_name": "SessionStart", "source": "startup"}).to_string().as_bytes(),
        Some(Arc::clone(&quiet)),
    );
    let session_ok = session.exit_code == 0
        && session
            .stdout
            .as_deref()
            .and_then(|s| serde_json::from_str::<Value>(s).ok())
            .is_some_and(|v| {
                v.pointer("/hookSpecificOutput/hookEventName") == Some(&json!("SessionStart"))
            });
    vec![
        check(
            "invalid-payload-blocks",
            blocks(&invalid),
            "a malformed PreToolUse payload is blocked",
        ),
        check(
            "self-approval-blocks",
            blocks(&approve),
            "a Bash call running `ai-defender approve` is blocked",
        ),
        check(
            "hook-config-protected",
            blocks(&tamper),
            "a change to the provider's own hook configuration is blocked",
        ),
        check(
            "session-start-response",
            session_ok,
            "SessionStart returns the documented hookSpecificOutput",
        ),
    ]
}

/// `integrations.verify`.
pub fn verify(env: &Environment, arguments: Value) -> Result<Value, EngineError> {
    let a: VerifyArgs = args(arguments)?;
    let providers = selected(&ProviderArgs {
        provider: a.provider.clone(),
    })?;
    let trust = verified(&env.store).map(|_| ());
    let home = env
        .process_env
        .iter()
        .find(|(k, _)| k == "HOME")
        .map_or_else(|| "/".to_owned(), |(_, v)| v.clone());
    let cwd = a.working_directory.clone().unwrap_or(home);
    let mut results = Vec::new();
    for p in providers {
        let status = provider_status(env, p, true);
        let installed = at(&status, "/installed");
        let mut checks = vec![
            check(
                "trusted-state",
                trust.is_ok(),
                if trust.is_ok() {
                    "trusted state verifies".to_owned()
                } else {
                    "trusted state does not verify; every protected call is blocked".to_owned()
                },
            ),
            check(
                "config-readable",
                at(installed, "/readable") == true,
                "the hook configuration parses",
            ),
            check(
                "events-registered",
                p.events().iter().all(|e| {
                    at(installed, "/events")
                        .as_array()
                        .is_some_and(|a| a.iter().any(|x| x == e.name))
                }),
                format!("events: {}", at(installed, "/events")),
            ),
            check(
                "fails-closed",
                at(installed, "/fails_closed") == true,
                "PreToolUse failures block (onFailure or exit 2)",
            ),
            check(
                "config-permissions",
                at(installed, "/writable_by_others") == false,
                "the configuration is not writable by group or others",
            ),
            check(
                "engine-executable",
                at(&status, "/engine/problems")
                    .as_array()
                    .is_some_and(Vec::is_empty),
                format!("{}", at(&status, "/engine/problems")),
            ),
            check(
                "engine-identity",
                at(&status, "/engine/sha256_matches_install") == true,
                "the engine binary is the one recorded at installation",
            ),
            check(
                "protocol",
                true,
                format!("adapter {ADAPTER_VERSION}, documentation verified {DOCS_VERIFIED}"),
            ),
        ];
        checks.extend(synthetic(env, p, &cwd));
        let passed = checks.iter().all(|c| at(c, "/passed") == true);
        if let Some(mut record) = load_record(env, p) {
            if let Some(map) = record.as_object_mut() {
                map.insert(
                    "last_health_check".into(),
                    json!({"at": now(env), "passed": passed}),
                );
            }
            let _ = save_record(env, p, &record);
        }
        results.push(json!({"provider": p, "passed": passed, "checks": checks, "compatibility": at(&status, "/compatibility")}));
    }
    Ok(json!({ "results": results, "statement": NOT_COMPLETE }))
}
