//! Native hook payloads: validation, and normalization into AgentGuard operations.
//!
//! Claude Code and Codex are parsed by separate functions. Their payloads look alike but are
//! documented separately and differ in tools, fields and semantics.
//!
//! Payloads are bounded and must be a JSON object whose `hook_event_name` equals the event in
//! the installed command line, with an absolute `cwd`. Fields providers add later are ignored
//! rather than rejected. A missing or mistyped field AgentGuard relies on is rejected and
//! reported as a possible schema change. Nothing in a payload is believed about identity:
//! - the agent comes from the installed command line;
//! - the project comes from the trusted registry;
//! - payload fields such as `agent_id` are recorded, never trusted;
//! - fields such as `decision` or `approved` are never read.

use std::path::Path;

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::apply_patch::{self, FileChange};
use crate::provider::{EventSpec, Provider};

/// Largest payload read (a `Write` carries the whole file).
pub const MAX_PAYLOAD_BYTES: usize = 8 * 1024 * 1024;

/// Why a payload was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message} ({code})")]
pub struct InputError {
    /// Stable reason code.
    pub code: &'static str,
    /// Why.
    pub message: String,
}

fn reject(code: &'static str, message: impl Into<String>) -> InputError {
    InputError {
        code,
        message: message.into(),
    }
}

/// A validated hook invocation.
#[derive(Debug, Clone)]
pub struct HookInput {
    /// Provider (from the command line).
    pub provider: Provider,
    /// Event (from the command line, matched against the payload).
    pub event: &'static EventSpec,
    /// Provider session identifier, when it has a safe shape (recorded and bound, never
    /// trusted as identity).
    pub session_id: Option<String>,
    /// The session's working directory.
    pub cwd: String,
    /// Tool name, for tool events.
    pub tool_name: Option<String>,
    /// Tool arguments, for tool events.
    pub tool_input: Option<Map<String, Value>>,
    /// Whether the call comes from a subagent (Claude Code `agent_id`); recorded only.
    pub subagent: bool,
}

/// One operation a tool call would perform, as an AgentGuard protocol action.
#[derive(Debug, Clone, PartialEq)]
pub struct Operation {
    /// The protocol action (`category` and fields).
    pub action: Value,
    /// Text the operation writes or adds, for secret inspection (never sent or stored).
    pub content: Option<String>,
}

fn safe_id(v: Option<&Value>) -> Option<String> {
    let s = v?.as_str()?;
    (!s.is_empty()
        && s.len() <= 128
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')))
    .then(|| s.to_owned())
}

fn object(bytes: &[u8]) -> Result<Map<String, Value>, InputError> {
    if bytes.len() > MAX_PAYLOAD_BYTES {
        return Err(reject(
            "hook.payload-too-large",
            "the hook payload exceeds 8 MiB",
        ));
    }
    match serde_json::from_slice::<Value>(bytes) {
        Ok(Value::Object(m)) => Ok(m),
        Ok(_) => Err(reject(
            "hook.payload-invalid",
            "the hook payload is not a JSON object",
        )),
        Err(_) => Err(reject(
            "hook.payload-invalid",
            "the hook payload is not valid JSON",
        )),
    }
}

fn common(
    provider: Provider,
    event: &'static EventSpec,
    m: &Map<String, Value>,
) -> Result<(String, Option<String>), InputError> {
    match m.get("hook_event_name").and_then(Value::as_str) {
        Some(name) if name == event.name => {}
        Some(_) => {
            return Err(reject(
                "hook.event-mismatch",
                "the payload's hook_event_name does not match the installed hook",
            ))
        }
        None => {
            return Err(reject(
                "hook.schema-changed",
                format!(
                "{} payload has no hook_event_name; the provider's hook schema may have changed",
                provider.display()
            ),
            ))
        }
    }
    let cwd = m
        .get("cwd")
        .and_then(Value::as_str)
        .filter(|c| Path::new(c).is_absolute() && !c.contains('\0'))
        .ok_or_else(|| reject("hook.schema-changed", "the payload has no absolute cwd"))?;
    Ok((cwd.to_owned(), safe_id(m.get("session_id"))))
}

/// Tool name and arguments of a tool event.
type ToolFields = (Option<String>, Option<Map<String, Value>>);

fn tool_fields(
    m: &mut Map<String, Value>,
    pre_or_post_tool: bool,
) -> Result<ToolFields, InputError> {
    if !pre_or_post_tool {
        return Ok((None, None));
    }
    let name = m
        .get("tool_name")
        .and_then(Value::as_str)
        .filter(|n| !n.is_empty() && n.len() <= 256)
        .ok_or_else(|| reject("hook.schema-changed", "the payload has no tool_name"))?
        .to_owned();
    let Some(Value::Object(input)) = m.remove("tool_input") else {
        return Err(reject(
            "hook.schema-changed",
            "the payload has no tool_input object",
        ));
    };
    Ok((Some(name), Some(input)))
}

/// Validate a Claude Code payload for `event`.
pub fn parse_claude(bytes: &[u8], event: &'static EventSpec) -> Result<HookInput, InputError> {
    let mut m = object(bytes)?;
    let (cwd, session_id) = common(Provider::Claude, event, &m)?;
    let tools = matches!(
        event.name,
        "PreToolUse" | "PostToolUse" | "PostToolUseFailure"
    );
    let (tool_name, tool_input) = tool_fields(&mut m, tools)?;
    Ok(HookInput {
        provider: Provider::Claude,
        event,
        session_id,
        cwd,
        tool_name,
        tool_input,
        subagent: m.get("agent_id").is_some(),
    })
}

/// Validate a Codex payload for `event`.
pub fn parse_codex(bytes: &[u8], event: &'static EventSpec) -> Result<HookInput, InputError> {
    let mut m = object(bytes)?;
    let (cwd, session_id) = common(Provider::Codex, event, &m)?;
    let tools = matches!(event.name, "PreToolUse" | "PostToolUse");
    let (tool_name, tool_input) = tool_fields(&mut m, tools)?;
    Ok(HookInput {
        provider: Provider::Codex,
        event,
        session_id,
        cwd,
        tool_name,
        tool_input,
        subagent: false,
    })
}

/// Validate a payload for `provider`.
pub fn parse(
    provider: Provider,
    bytes: &[u8],
    event: &'static EventSpec,
) -> Result<HookInput, InputError> {
    match provider {
        Provider::Claude => parse_claude(bytes, event),
        Provider::Codex => parse_codex(bytes, event),
    }
}

// ---------------------------------------------------------------------------------------------
// Normalization
// ---------------------------------------------------------------------------------------------

fn text<'a>(input: &'a Map<String, Value>, key: &str) -> Result<&'a str, InputError> {
    input.get(key).and_then(Value::as_str).ok_or_else(|| {
        reject(
            "hook.schema-changed",
            format!("tool_input.{key} is missing or not a string"),
        )
    })
}

fn absolute(cwd: &str, path: &str) -> Result<String, InputError> {
    if path.is_empty() || path.contains('\0') {
        return Err(reject("hook.payload-invalid", "a tool path is empty"));
    }
    let p = Path::new(path);
    Ok(if p.is_absolute() {
        path.to_owned()
    } else {
        Path::new(cwd).join(p).to_string_lossy().into_owned()
    })
}

/// Set `key` on a JSON object (a no-op on anything else).
pub(crate) fn set_field(v: &mut Value, key: &str, value: Value) {
    if let Some(map) = v.as_object_mut() {
        map.insert(key.to_owned(), value);
    }
}

fn fs(operation: &str, path: &str) -> Value {
    json!({ "category": "filesystem", "operation": operation, "path": path })
}

fn custom(tool: &str, server: Option<&str>) -> Value {
    let mut v = json!({ "category": "custom-tool", "tool": tool });
    if let Some(s) = server {
        set_field(&mut v, "server", json!(s));
    }
    v
}

fn mcp(tool: &str, input: &HookInput) -> Operation {
    let server = tool
        .strip_prefix("mcp__")
        .and_then(|r| r.split("__").next());
    let _ = input;
    Operation {
        action: custom(tool, server),
        content: None,
    }
}

fn host_of(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = host.split(':').next()?;
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// Operations a Claude Code tool call would perform. Tools AgentGuard does not know become a
/// custom-tool action, which policy treats conservatively.
pub fn normalize_claude(input: &HookInput) -> Result<Vec<Operation>, InputError> {
    let (Some(tool), Some(args)) = (&input.tool_name, &input.tool_input) else {
        return Ok(Vec::new());
    };
    let cwd = input.cwd.as_str();
    let op = |action: Value, content: Option<String>| Operation { action, content };
    Ok(match tool.as_str() {
        "Bash" | "PowerShell" => vec![op(
            json!({ "category": "terminal", "command": text(args, "command")? }),
            None,
        )],
        "Read" => vec![op(
            fs("read", &absolute(cwd, text(args, "file_path")?)?),
            None,
        )],
        "Write" => vec![op(
            fs("write", &absolute(cwd, text(args, "file_path")?)?),
            Some(text(args, "content")?.to_owned()),
        )],
        "Edit" => vec![op(
            fs("write", &absolute(cwd, text(args, "file_path")?)?),
            Some(text(args, "new_string")?.to_owned()),
        )],
        "MultiEdit" => {
            let edits = args
                .get("edits")
                .and_then(Value::as_array)
                .ok_or_else(|| reject("hook.schema-changed", "tool_input.edits is missing"))?;
            let content: String = edits
                .iter()
                .filter_map(|e| e.get("new_string").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join("\n");
            vec![op(
                fs("write", &absolute(cwd, text(args, "file_path")?)?),
                Some(content),
            )]
        }
        "NotebookEdit" => vec![op(
            fs("write", &absolute(cwd, text(args, "notebook_path")?)?),
            args.get("new_source")
                .and_then(Value::as_str)
                .map(str::to_owned),
        )],
        "Glob" | "Grep" => {
            let path = args.get("path").and_then(Value::as_str).unwrap_or(cwd);
            vec![op(fs("traverse", &absolute(cwd, path)?), None)]
        }
        "WebFetch" => {
            let url = text(args, "url")?;
            match host_of(url) {
                Some(host) => vec![op(
                    json!({ "category": "network", "operation": "request", "host": host }),
                    None,
                )],
                None => vec![op(custom("WebFetch", None), None)],
            }
        }
        t if t.starts_with("mcp__") => vec![mcp(t, input)],
        other => vec![op(custom(other, None), None)],
    })
}

fn codex_command(args: &Map<String, Value>) -> Result<String, InputError> {
    match args.get("command") {
        Some(Value::String(s)) => Ok(s.clone()),
        Some(Value::Array(parts)) => {
            let words: Vec<String> = parts
                .iter()
                .map(|p| p.as_str().map(str::to_owned))
                .collect::<Option<_>>()
                .ok_or_else(|| {
                    reject(
                        "hook.schema-changed",
                        "tool_input.command has non-string parts",
                    )
                })?;
            // `bash -lc <script>`: the script is the command.
            Ok(match words.as_slice() {
                [sh, flag, script]
                    if matches!(sh.as_str(), "bash" | "sh" | "zsh" | "/bin/bash" | "/bin/sh")
                        && matches!(flag.as_str(), "-c" | "-lc") =>
                {
                    script.clone()
                }
                _ => agentguard_engine::normalize::quote_argv(&words),
            })
        }
        _ => Err(reject(
            "hook.schema-changed",
            "tool_input.command is missing",
        )),
    }
}

/// Operations a Codex tool call would perform.
pub fn normalize_codex(input: &HookInput) -> Result<Vec<Operation>, InputError> {
    let (Some(tool), Some(args)) = (&input.tool_name, &input.tool_input) else {
        return Ok(Vec::new());
    };
    let cwd = input.cwd.as_str();
    Ok(match tool.as_str() {
        "Bash" => vec![Operation {
            action: json!({ "category": "terminal", "command": codex_command(args)? }),
            content: None,
        }],
        "apply_patch" => {
            let patch = codex_command(args)?;
            let changes = apply_patch::parse(&patch)
                .map_err(|e| reject("hook.patch-unreadable", e.to_string()))?;
            let mut ops = Vec::new();
            for change in changes {
                match change {
                    FileChange::Add { path, content } => ops.push(Operation {
                        action: fs("write", &absolute(cwd, &path)?),
                        content: Some(content),
                    }),
                    FileChange::Update {
                        path,
                        move_to,
                        added,
                    } => {
                        let from = absolute(cwd, &path)?;
                        ops.push(Operation {
                            action: fs("write", &from),
                            content: Some(added),
                        });
                        if let Some(to) = move_to {
                            let mut action = fs("rename", &from);
                            set_field(&mut action, "destination", json!(absolute(cwd, &to)?));
                            ops.push(Operation {
                                action,
                                content: None,
                            });
                        }
                    }
                    FileChange::Delete { path } => ops.push(Operation {
                        action: fs("delete", &absolute(cwd, &path)?),
                        content: None,
                    }),
                }
            }
            ops
        }
        t if t.starts_with("mcp__") => vec![mcp(t, input)],
        other => vec![Operation {
            action: custom(other, None),
            content: None,
        }],
    })
}

/// Operations for `input`, by provider.
pub fn normalize(input: &HookInput) -> Result<Vec<Operation>, InputError> {
    match input.provider {
        Provider::Claude => normalize_claude(input),
        Provider::Codex => normalize_codex(input),
    }
}

/// SHA-256 of the tool arguments that determine what the tool does, so an approval cannot be
/// reused for a changed call. Claude Code's free-text `description` is excluded (it does not
/// change what runs); everything else counts.
#[must_use]
pub fn tool_input_digest(input: &HookInput) -> String {
    let mut args = input.tool_input.clone().unwrap_or_default();
    if input.provider == Provider::Claude {
        args.remove("description");
    }
    let canonical = serde_json::to_vec(&json!({
        "tool": input.tool_name,
        "input": canonicalize(&Value::Object(args)),
    }))
    .unwrap_or_default();
    hex::encode(Sha256::digest(canonical))
}

fn canonicalize(v: &Value) -> Value {
    match v {
        Value::Object(m) => {
            let mut sorted: Vec<(&String, &Value)> = m.iter().collect();
            sorted.sort_by(|a, b| a.0.cmp(b.0));
            let mut out = Map::new();
            for (k, v) in sorted {
                out.insert(k.clone(), canonicalize(v));
            }
            Value::Object(out)
        }
        Value::Array(a) => Value::Array(a.iter().map(canonicalize).collect()),
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(p: Provider, name: &str) -> &'static EventSpec {
        p.event(name).unwrap()
    }

    #[test]
    fn claude_payloads_are_validated_and_normalized() {
        let e = ev(Provider::Claude, "PreToolUse");
        let ok = br#"{"session_id":"abc-123","cwd":"/p","hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"src/a.rs","content":"x"},"tool_use_id":"t1","decision":"approve","permissionDecision":"allow"}"#;
        let input = parse_claude(ok, e).unwrap();
        let ops = normalize_claude(&input).unwrap();
        assert_eq!(
            ops[0].action,
            json!({"category":"filesystem","operation":"write","path":"/p/src/a.rs"})
        );
        assert_eq!(ops[0].content.as_deref(), Some("x"));
        for bad in [
            &b"not json"[..],
            b"[]",
            br#"{"cwd":"/p","hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{}}"#,
            br#"{"cwd":"relative","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{}}"#,
            br#"{"cwd":"/p","hook_event_name":"PreToolUse","tool_input":{}}"#,
            br#"{"cwd":"/p","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":"rm -rf /"}"#,
        ] {
            assert!(parse_claude(bad, e).is_err(), "{}", String::from_utf8_lossy(bad));
        }
        let no_command = parse_claude(
            br#"{"cwd":"/p","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{}}"#,
            e,
        )
        .unwrap();
        assert!(normalize_claude(&no_command).is_err());
    }

    #[test]
    fn codex_patches_and_commands_are_normalized() {
        let e = ev(Provider::Codex, "PreToolUse");
        let patch =
            "*** Begin Patch\n*** Add File: a.txt\n+hello\n*** Delete File: b.txt\n*** End Patch\n";
        let payload = json!({"session_id":"s1","cwd":"/p","hook_event_name":"PreToolUse","model":"x","turn_id":"t","tool_name":"apply_patch","tool_use_id":"u","tool_input":{"command": patch}});
        let input = parse_codex(serde_json::to_vec(&payload).unwrap().as_slice(), e).unwrap();
        let ops = normalize_codex(&input).unwrap();
        assert_eq!(ops.len(), 2);
        assert_eq!(ops[1].action["operation"], "delete");
        let bash = json!({"cwd":"/p","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":["bash","-lc","git push origin main"]}});
        let input = parse_codex(serde_json::to_vec(&bash).unwrap().as_slice(), e).unwrap();
        assert_eq!(
            normalize_codex(&input).unwrap()[0].action["command"],
            "git push origin main"
        );
        let garbage = json!({"cwd":"/p","hook_event_name":"PreToolUse","tool_name":"apply_patch","tool_input":{"command":"rm -rf /"}});
        let input = parse_codex(serde_json::to_vec(&garbage).unwrap().as_slice(), e).unwrap();
        assert_eq!(
            normalize_codex(&input).unwrap_err().code,
            "hook.patch-unreadable"
        );
    }

    #[test]
    fn the_digest_ignores_descriptions_but_not_arguments() {
        let e = ev(Provider::Claude, "PreToolUse");
        let p = |cmd: &str, desc: &str| {
            parse_claude(
                serde_json::to_vec(&json!({"cwd":"/p","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":cmd,"description":desc}})).unwrap().as_slice(),
                e,
            )
            .unwrap()
        };
        assert_eq!(
            tool_input_digest(&p("git push origin a", "x")),
            tool_input_digest(&p("git push origin a", "y"))
        );
        assert_ne!(
            tool_input_digest(&p("git push origin a", "x")),
            tool_input_digest(&p("git push origin b", "x"))
        );
    }
}
