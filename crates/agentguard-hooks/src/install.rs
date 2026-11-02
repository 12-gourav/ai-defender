//! Installing and removing AgentGuard's hook entries in the providers' user-level hook
//! configuration.
//!
//! | provider | file | AgentGuard handler |
//! |---|---|---|
//! | Claude Code | `~/.claude/settings.json` (`hooks`) | exec form: `command` = the engine's absolute path, `args` = `["hook", "claude", <event>]`; `onFailure: "block"` on `PreToolUse` |
//! | Codex | `~/.codex/hooks.json` (`hooks`) | `command` = `'<engine>' hook codex <event>`, with `\|\| exit 2` on `PreToolUse` so a missing or crashing engine blocks |
//!
//! Every AgentGuard handler carries `statusMessage: "AgentGuard security check"` and names the
//! engine's `hook` subcommand; only handlers with both are AgentGuard's. Installation:
//! - backs up the existing file into the trust store first;
//! - replaces AgentGuard's own handlers (idempotent) and leaves every other key, group and
//!   handler as it was;
//! - writes atomically, keeping the file's mode minus group and other write access.
//!
//! A file that does not parse as a JSON object is never overwritten. Removal deletes only
//! AgentGuard's handlers, and only the groups and keys that held nothing else.

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::provider::{Capability, Provider};

/// Marker on every AgentGuard handler.
pub const MARKER: &str = "AI Defender security check";

/// Markers written by earlier releases (as AgentGuard). Still recognised, so an existing
/// installation is upgraded or removed instead of being duplicated or orphaned.
pub const LEGACY_MARKERS: &[&str] = &["AgentGuard security check"];

/// Largest configuration file read.
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

/// Why a configuration could not be changed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct InstallError(pub String);

fn err(m: impl Into<String>) -> InstallError {
    InstallError(m.into())
}

/// The configuration file for `provider` under `home`, refusing relocated configuration
/// directories AgentGuard does not resolve (`CLAUDE_CONFIG_DIR`, `CODEX_HOME`).
pub fn config_path(
    provider: Provider,
    caller_env: &[(String, String)],
) -> Result<PathBuf, InstallError> {
    let var = |n: &str| {
        caller_env
            .iter()
            .find(|(k, _)| k == n)
            .map(|(_, v)| v.as_str())
    };
    let relocated = match provider {
        Provider::Claude => "CLAUDE_CONFIG_DIR",
        Provider::Codex => "CODEX_HOME",
    };
    if var(relocated).is_some_and(|v| !v.is_empty()) {
        return Err(err(format!(
            "{relocated} is set; AI Defender installs only into the default configuration directory, so it would not be read. Unset it or configure the hooks manually."
        )));
    }
    let home = var("HOME")
        .filter(|h| Path::new(h).is_absolute())
        .ok_or_else(|| err("HOME is not set to an absolute path"))?;
    Ok(match provider {
        Provider::Claude => Path::new(home).join(".claude/settings.json"),
        Provider::Codex => Path::new(home).join(".codex/hooks.json"),
    })
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// AgentGuard's handler for one event.
#[must_use]
pub fn handler(
    provider: Provider,
    engine: &Path,
    event: &str,
    timeout: u64,
    enforcing: bool,
) -> Value {
    let engine = engine.to_string_lossy();
    match provider {
        Provider::Claude => {
            let mut h = json!({
                "type": "command",
                "command": engine,
                "args": ["hook", "claude", event],
                "timeout": timeout,
                "statusMessage": MARKER,
            });
            if enforcing {
                crate::input::set_field(&mut h, "onFailure", json!("block"));
            }
            h
        }
        Provider::Codex => {
            let mut command = format!("{} hook codex {event}", shell_quote(&engine));
            if enforcing {
                command.push_str(" || exit 2");
            }
            json!({
                "type": "command",
                "command": command,
                "timeout": timeout,
                "statusMessage": MARKER,
            })
        }
    }
}

/// Whether `h` is an AgentGuard handler for `provider`.
#[must_use]
pub fn is_managed(provider: Provider, h: &Value) -> bool {
    let marked = h
        .get("statusMessage")
        .and_then(Value::as_str)
        .is_some_and(|m| m == MARKER || LEGACY_MARKERS.contains(&m));
    if !marked {
        return false;
    }
    match provider {
        Provider::Claude => {
            let args = h.get("args").and_then(Value::as_array);
            args.is_some_and(|a| {
                a.first().and_then(Value::as_str) == Some("hook")
                    && a.get(1).and_then(Value::as_str) == Some("claude")
            })
        }
        Provider::Codex => h
            .get("command")
            .and_then(Value::as_str)
            .is_some_and(|c| c.contains(" hook codex ")),
    }
}

/// A configuration file's object, its original bytes (absent for a new file) and its mode.
type Loaded = (Map<String, Value>, Option<Vec<u8>>, u32);

/// Read a configuration file: absent → empty object; anything else must be a regular file
/// (not a symlink), at most 1 MiB, holding a JSON object.
pub fn read_config(path: &Path) -> Result<Loaded, InstallError> {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((Map::new(), None, 0o600)),
        Err(_) => return Err(err(format!("{} cannot be inspected", path.display()))),
    };
    if !meta.file_type().is_file() {
        return Err(err(format!(
            "{} is not a regular file (symlinks are not followed); configure it manually",
            path.display()
        )));
    }
    if meta.len() > MAX_CONFIG_BYTES {
        return Err(err(format!("{} is larger than 1 MiB", path.display())));
    }
    let mut bytes = Vec::new();
    OpenOptions::new()
        .read(true)
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
        .open(path)
        .and_then(|f| f.take(MAX_CONFIG_BYTES + 1).read_to_end(&mut bytes))
        .map_err(|_| err(format!("{} cannot be read", path.display())))?;
    let map = if bytes.iter().all(u8::is_ascii_whitespace) {
        Map::new()
    } else {
        match serde_json::from_slice::<Value>(&bytes) {
            Ok(Value::Object(m)) => m,
            _ => {
                return Err(err(format!(
                    "{} is not a JSON object; it was left unchanged",
                    path.display()
                )))
            }
        }
    };
    Ok((map, Some(bytes), meta.mode() & 0o777))
}

fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<(), InstallError> {
    let parent = path
        .parent()
        .ok_or_else(|| err("configuration path has no parent"))?;
    match DirBuilder::new().mode(0o700).recursive(true).create(parent) {
        Ok(()) => {}
        Err(_) => return Err(err(format!("{} cannot be created", parent.display()))),
    }
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = parent.join(format!(".{name}.agentguard.{}.tmp", std::process::id()));
    let _ = fs::remove_file(&tmp);
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
        .open(&tmp)
        .map_err(|_| err(format!("{} cannot be written", parent.display())))?;
    f.write_all(bytes)
        .and_then(|()| f.sync_all())
        .map_err(|_| err("the configuration could not be written"))?;
    let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(mode));
    fs::rename(&tmp, path).map_err(|_| err("the configuration could not be replaced"))
}

/// The mode a rewritten file keeps: its own, without group or other write access (a hook
/// configuration others can change is a way to remove or replace the hooks).
const fn safe_mode(mode: u32) -> u32 {
    if mode == 0 {
        0o600
    } else {
        mode & !0o022
    }
}

/// Remove AgentGuard's handlers from `hooks`; returns how many were removed. Groups and event
/// keys left empty by the removal are dropped; anything else stays.
fn strip(provider: Provider, hooks: &mut Map<String, Value>) -> usize {
    let mut removed = 0;
    let events: Vec<String> = hooks.keys().cloned().collect();
    for event in events {
        let Some(Value::Array(groups)) = hooks.get_mut(&event) else {
            continue;
        };
        let removed_before = removed;
        groups.retain_mut(|group| {
            let Some(Value::Array(handlers)) = group.get_mut("hooks") else {
                return true;
            };
            let before = handlers.len();
            handlers.retain(|h| !is_managed(provider, h));
            let gone = before - handlers.len();
            removed += gone;
            !(gone > 0 && handlers.is_empty())
        });
        if groups.is_empty() && removed > removed_before {
            hooks.remove(&event);
        }
    }
    removed
}

/// What an install or uninstall did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    /// The configuration file.
    pub path: PathBuf,
    /// Whether its content changed.
    pub changed: bool,
    /// Where the previous content was backed up.
    pub backup: Option<PathBuf>,
    /// AgentGuard handlers removed.
    pub removed: usize,
    /// AgentGuard handlers added.
    pub added: usize,
}

fn backup(
    original: Option<&[u8]>,
    dir: &Path,
    provider: Provider,
) -> Result<Option<PathBuf>, InstallError> {
    let Some(bytes) = original else {
        return Ok(None);
    };
    DirBuilder::new()
        .mode(0o700)
        .recursive(true)
        .create(dir)
        .map_err(|_| err("the backup directory cannot be created"))?;
    let stamp = time::OffsetDateTime::now_utc().unix_timestamp_nanos();
    let path = dir.join(format!("{}-{stamp}.json", provider.as_str()));
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
        .open(&path)
        .map_err(|_| err("the backup could not be created"))?;
    f.write_all(bytes)
        .and_then(|()| f.sync_all())
        .map_err(|_| err("the backup could not be written"))?;
    Ok(Some(path))
}

fn serialize(map: &Map<String, Value>) -> Result<Vec<u8>, InstallError> {
    let mut bytes = serde_json::to_vec_pretty(&Value::Object(map.clone()))
        .map_err(|_| err("serialization failed"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Install AgentGuard's handlers for `provider` into `path`.
pub fn install(
    provider: Provider,
    path: &Path,
    engine: &Path,
    backup_dir: &Path,
) -> Result<Change, InstallError> {
    let (mut map, original, mode) = read_config(path)?;
    let before = map.clone();
    let Value::Object(hooks) = map
        .entry("hooks")
        .or_insert_with(|| Value::Object(Map::new()))
    else {
        return Err(err(format!(
            "`hooks` in {} is not an object; it was left unchanged",
            path.display()
        )));
    };
    let removed = strip(provider, hooks);
    let mut added = 0;
    for spec in provider.events() {
        let enforcing = spec.capability == Capability::PreExecutionEnforcement;
        let mut group = json!({ "hooks": [handler(provider, engine, spec.name, spec.timeout_seconds, enforcing)] });
        if let Some(m) = spec.matcher {
            crate::input::set_field(&mut group, "matcher", json!(m));
        }
        match hooks
            .entry(spec.name)
            .or_insert_with(|| Value::Array(Vec::new()))
        {
            Value::Array(groups) => groups.push(group),
            _ => {
                return Err(err(format!(
                    "`hooks.{}` in {} is not an array; it was left unchanged",
                    spec.name,
                    path.display()
                )))
            }
        }
        added += 1;
    }
    let changed = map != before;
    let backup = if changed {
        backup(original.as_deref(), backup_dir, provider)?
    } else {
        None
    };
    if changed {
        write_atomic(path, &serialize(&map)?, safe_mode(mode))?;
    }
    Ok(Change {
        path: path.to_path_buf(),
        changed,
        backup,
        removed,
        added,
    })
}

/// Remove AgentGuard's handlers for `provider` from `path`.
pub fn uninstall(
    provider: Provider,
    path: &Path,
    backup_dir: &Path,
) -> Result<Change, InstallError> {
    let (mut map, original, mode) = read_config(path)?;
    let mut removed = 0;
    let mut empty = false;
    if let Some(Value::Object(hooks)) = map.get_mut("hooks") {
        removed = strip(provider, hooks);
        empty = hooks.is_empty();
    }
    if removed > 0 && empty {
        map.remove("hooks");
    }
    let changed = removed > 0;
    let backup = if changed {
        backup(original.as_deref(), backup_dir, provider)?
    } else {
        None
    };
    if changed {
        write_atomic(path, &serialize(&map)?, safe_mode(mode))?;
    }
    Ok(Change {
        path: path.to_path_buf(),
        changed,
        backup,
        removed,
        added: 0,
    })
}

/// What is installed for `provider` in `path`.
// A report: each flag is an independent observation.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Installed {
    /// The file exists.
    pub exists: bool,
    /// It parses as a JSON object.
    pub readable: bool,
    /// Events with an AgentGuard handler.
    pub events: Vec<String>,
    /// Engine paths AgentGuard handlers run.
    pub engines: Vec<String>,
    /// Handlers that are not AgentGuard's.
    pub other_handlers: usize,
    /// Whether the PreToolUse handler fails closed (Claude Code `onFailure: "block"`; Codex
    /// `|| exit 2`).
    pub fails_closed: bool,
    /// The file's mode allows group or other writes.
    pub writable_by_others: bool,
}

/// Inspect `path`.
#[must_use]
pub fn inspect(provider: Provider, path: &Path) -> Installed {
    let exists = fs::symlink_metadata(path).is_ok();
    let writable_by_others = fs::metadata(path).is_ok_and(|m| m.mode() & 0o022 != 0);
    let Ok((map, _, _)) = read_config(path) else {
        return Installed {
            exists,
            readable: false,
            events: Vec::new(),
            engines: Vec::new(),
            other_handlers: 0,
            fails_closed: false,
            writable_by_others,
        };
    };
    let mut events = Vec::new();
    let mut engines = Vec::new();
    let mut other = 0;
    let mut fails_closed = false;
    if let Some(Value::Object(hooks)) = map.get("hooks") {
        for (event, groups) in hooks {
            for group in groups.as_array().into_iter().flatten() {
                for h in group
                    .get("hooks")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    if is_managed(provider, h) {
                        if !events.contains(event) {
                            events.push(event.clone());
                        }
                        let engine = match provider {
                            Provider::Claude => {
                                h.get("command").and_then(Value::as_str).map(str::to_owned)
                            }
                            Provider::Codex => {
                                h.get("command").and_then(Value::as_str).and_then(|c| {
                                    c.strip_prefix('\'')
                                        .and_then(|r| r.split_once("' hook codex "))
                                        .map(|(p, _)| p.replace("'\\''", "'"))
                                })
                            }
                        };
                        if let Some(e) = engine {
                            if !engines.contains(&e) {
                                engines.push(e);
                            }
                        }
                        if event == "PreToolUse" {
                            fails_closed = match provider {
                                Provider::Claude => {
                                    h.get("onFailure").and_then(Value::as_str) == Some("block")
                                }
                                Provider::Codex => h
                                    .get("command")
                                    .and_then(Value::as_str)
                                    .is_some_and(|c| c.ends_with("|| exit 2")),
                            };
                        }
                    } else {
                        other += 1;
                    }
                }
            }
        }
    }
    events.sort();
    Installed {
        exists,
        readable: true,
        events,
        engines,
        other_handlers: other,
        fails_closed,
        writable_by_others,
    }
}

/// SHA-256 of a file.
#[must_use]
pub fn file_sha256(path: &Path) -> Option<String> {
    let mut f = OpenOptions::new().read(true).open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(buf.get(..n)?);
    }
    Some(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER: &str = r#"{
  "model": "opus",
  "permissions": {"allow": ["Bash(npm test)"]},
  "hooks": {
    "PreToolUse": [
      {"matcher": "Bash", "hooks": [{"type": "command", "command": "/home/u/bin/my-guard.sh"}]}
    ],
    "Stop": [{"hooks": [{"type": "command", "command": "notify-send done"}]}]
  }
}"#;

    #[test]
    fn install_is_idempotent_preserves_user_entries_and_uninstall_is_exact() {
        for provider in Provider::ALL {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("settings.json");
            fs::write(&path, USER).unwrap();
            let engine = Path::new("/opt/agent guard/agentguard-engine");
            let backups = dir.path().join("backups");
            let first = install(provider, &path, engine, &backups).unwrap();
            assert!(first.changed && first.backup.is_some());
            assert_eq!(fs::read_to_string(first.backup.unwrap()).unwrap(), USER);
            let second = install(provider, &path, engine, &backups).unwrap();
            assert!(!second.changed, "a second install changes nothing");
            let state = inspect(provider, &path);
            assert_eq!(state.events.len(), provider.events().len());
            assert_eq!(state.other_handlers, 2);
            assert!(state.fails_closed);
            assert_eq!(state.engines, ["/opt/agent guard/agentguard-engine"]);
            let v: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            assert_eq!(v["model"], "opus");
            assert_eq!(v["permissions"]["allow"][0], "Bash(npm test)");
            let removed = uninstall(provider, &path, &backups).unwrap();
            assert_eq!(removed.removed, provider.events().len());
            let after: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            let before: Value = serde_json::from_str(USER).unwrap();
            assert_eq!(
                after, before,
                "uninstall restores exactly the user's configuration"
            );
        }
    }

    #[test]
    fn unreadable_or_odd_files_are_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        fs::write(&path, "{ not json").unwrap();
        assert!(install(Provider::Claude, &path, Path::new("/e"), dir.path()).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "{ not json");
        fs::write(&path, r#"{"hooks": []}"#).unwrap();
        assert!(install(Provider::Claude, &path, Path::new("/e"), dir.path()).is_err());
        let link = dir.path().join("link.json");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(install(Provider::Claude, &link, Path::new("/e"), dir.path()).is_err());
        let fresh = dir.path().join("new/settings.json");
        assert!(
            install(Provider::Codex, &fresh, Path::new("/e"), dir.path())
                .unwrap()
                .changed
        );
        assert_eq!(fs::metadata(&fresh).unwrap().mode() & 0o777, 0o600);
    }

    #[test]
    fn legacy_installations_are_recognised_and_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let legacy = json!({"hooks": {"PreToolUse": [{"matcher": "x", "hooks": [{
            "type": "command", "command": "/old/agentguard-engine", "args": ["hook", "claude", "PreToolUse"],
            "timeout": 60, "statusMessage": "AgentGuard security check", "onFailure": "block"}]}]}});
        fs::write(&path, legacy.to_string()).unwrap();
        install(
            Provider::Claude,
            &path,
            Path::new("/new/agentguard-engine"),
            dir.path(),
        )
        .unwrap();
        let state = inspect(Provider::Claude, &path);
        assert_eq!(
            state.engines,
            ["/new/agentguard-engine"],
            "the legacy handler was replaced, not kept"
        );
        assert_eq!(state.other_handlers, 0);
        uninstall(Provider::Claude, &path, dir.path()).unwrap();
        assert_eq!(
            inspect(Provider::Claude, &path).events,
            Vec::<String>::new()
        );
    }

    #[test]
    fn handlers_match_the_documented_shapes() {
        let c = handler(
            Provider::Claude,
            Path::new("/x/agentguard-engine"),
            "PreToolUse",
            60,
            true,
        );
        assert_eq!(
            c,
            json!({"type":"command","command":"/x/agentguard-engine","args":["hook","claude","PreToolUse"],"timeout":60,"statusMessage":MARKER,"onFailure":"block"})
        );
        let x = handler(
            Provider::Codex,
            Path::new("/x/it's/agentguard-engine"),
            "PreToolUse",
            60,
            true,
        );
        assert_eq!(
            x["command"],
            "'/x/it'\\''s/agentguard-engine' hook codex PreToolUse || exit 2"
        );
        let env = [
            ("HOME".to_owned(), "/h".to_owned()),
            ("CODEX_HOME".to_owned(), "/elsewhere".to_owned()),
        ];
        assert!(config_path(Provider::Codex, &env).is_err());
        assert_eq!(
            config_path(Provider::Claude, &env).unwrap(),
            Path::new("/h/.claude/settings.json")
        );
    }
}
