//! The canonical AgentGuard authorization protocol.
//!
//! A request is a JSON object describing one action an agent wants to take; the response is the
//! engine's decision. This crate owns the boundary where untrusted bytes become typed values:
//!
//! - [`parse_request`] enforces a size limit, rejects unknown and duplicate fields, checks the
//!   protocol version, validates every field into a core domain type, and resolves every path
//!   through a [`agentguard_core::PathResolver`]. A request either parses completely or is
//!   rejected; there is no partial result.
//! - [`AuthorizationResponse`] keeps the decision and the approval requirement consistent by
//!   construction.
//!
//! Identity fields in a parsed request are still claims. The engine verifies them.
//! The request schema has no field through which a decision, a risk level or an approval can be
//! asserted: such a field is unknown and rejects the request.

#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

pub mod error;
pub mod request;
pub mod response;

pub use error::{ProtocolError, Rejection};
pub use request::{
    parse_request, AuthorizationRequest, ExecutionContext, ProjectClaim, MAX_ATTRIBUTES,
};
pub use response::{ApprovalRequirement, AuthorizationResponse, ResponseError};

/// Protocol identifier carried in every request and response.
pub const PROTOCOL_VERSION: &str = "agentguard.authz.v1";

/// Largest request the parser reads.
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;

// Unix paths throughout; the Windows path rules are tested in agentguard-core.
#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use agentguard_core::path::LexicalResolver;
    use agentguard_core::{Action, Decision, PolicyVersion, RiskLevel, RuleId};
    use serde_json::{json, Value};

    const RID: &str = "6f1c1f0e-8a5b-4c3e-9a7e-1c2b3d4e5f60";

    fn valid() -> Value {
        json!({
            "protocol": PROTOCOL_VERSION,
            "request_id": RID,
            "agent": {"kind": "claude", "version": "2.1.0"},
            "project": {"root": "/work/app"},
            "session_id": "0b1c2d3e-4f50-4617-8899-aabbccddeeff",
            "action": {"category": "filesystem", "operation": "write", "path": "src/main.rs"},
            "working_directory": "/work/app",
            "policy_version": PolicyVersion::compute(b"p").to_hex(),
            "context": {"tool": "Edit", "attributes": {"hook": "pre-tool-use"}}
        })
    }

    fn parse(v: &Value) -> Result<AuthorizationRequest, Rejection> {
        parse_request(&serde_json::to_vec(v).unwrap(), &LexicalResolver)
    }

    #[test]
    fn parses_valid_request_and_resolves_paths() {
        let r = parse(&valid()).unwrap();
        assert_eq!(r.request_id.to_string(), RID);
        assert_eq!(r.agent.to_string(), "claude@2.1.0");
        assert_eq!(r.working_directory.as_str(), "/work/app");
        match &r.action {
            Action::Filesystem(a) => assert_eq!(a.path.as_str(), "/work/app/src/main.rs"),
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(r.context.tool.as_ref().unwrap().as_str(), "Edit");
    }

    #[test]
    fn every_category_parses() {
        let actions = [
            json!({"category": "terminal", "command": "cargo test"}),
            json!({"category": "git", "operation": "push", "remote": "origin", "target_ref": "main", "force": true}),
            json!({"category": "github", "operation": "create-pull-request", "repository": "github:acme/app"}),
            json!({"category": "secrets", "operation": "read", "name": "DB_PASSWORD"}),
            json!({"category": "database", "operation": "drop", "target": "orders", "environment": "production"}),
            json!({"category": "terraform", "operation": "apply", "workspace": "prod"}),
            json!({"category": "network", "operation": "request", "host": "Example.com", "port": 443}),
            json!({"category": "external-transfer", "kind": "upload", "destination": "paste.example"}),
            json!({"category": "custom-tool", "tool": "mcp__db__query", "server": "db"}),
            json!({"category": "package-manager", "operation": "install", "manager": "npm", "packages": ["left-pad"]}),
            json!({"category": "cloud", "operation": "delete", "provider": "aws", "service": "s3", "resource": "bucket-1", "environment": "production"}),
            json!({"category": "configuration", "operation": "modify", "scope": "ci", "path": ".github/workflows/ci.yml"}),
            json!({"category": "unknown", "kind": "vendor-tool", "operation": "frobnicate", "target": "thing"}),
        ];
        for action in actions {
            let mut v = valid();
            v["action"] = action.clone();
            let r = parse(&v).unwrap_or_else(|e| panic!("{action}: {e}"));
            assert_eq!(r.action.category().as_str(), action["category"]);
        }
    }

    #[test]
    fn unknown_operation_parses_as_unknown() {
        let mut v = valid();
        v["action"]["operation"] = json!("shred");
        assert!(parse(&v).unwrap().action.is_unknown_operation());
    }

    #[test]
    fn missing_identity_is_rejected() {
        for field in [
            "agent",
            "project",
            "request_id",
            "policy_version",
            "working_directory",
            "action",
            "protocol",
        ] {
            let mut v = valid();
            v.as_object_mut().unwrap().remove(field);
            let err = parse(&v).unwrap_err();
            assert!(
                matches!(err.error, ProtocolError::Malformed { .. }),
                "{field}: {err}"
            );
        }
        let mut v = valid();
        v["agent"]["kind"] = json!("");
        assert!(parse(&v).is_err());
        let mut v = valid();
        v["agent"]["kind"] = json!("unregistered-agent");
        assert!(parse(&v).is_err());
    }

    #[test]
    fn agent_cannot_assert_a_decision_risk_or_approval() {
        for (field, value) in [
            ("decision", json!("ALLOW")),
            ("risk", json!("low")),
            ("approved", json!(true)),
            ("approval", json!({"fingerprint": "00"})),
        ] {
            let mut v = valid();
            v[field] = value.clone();
            assert!(parse(&v).is_err(), "top-level {field}");
            let mut v = valid();
            v["action"][field] = value;
            assert!(parse(&v).is_err(), "action.{field}");
        }
    }

    #[test]
    fn duplicate_keys_are_rejected() {
        let text = serde_json::to_string(&valid()).unwrap().replacen(
            "\"protocol\"",
            "\"agent\":{\"kind\":\"codex\"},\"protocol\"",
            1,
        );
        assert!(parse_request(text.as_bytes(), &LexicalResolver).is_err());
    }

    #[test]
    fn size_protocol_and_field_validation() {
        let big = vec![b' '; MAX_REQUEST_BYTES + 1];
        assert_eq!(
            parse_request(&big, &LexicalResolver).unwrap_err().error,
            ProtocolError::TooLarge {
                max: MAX_REQUEST_BYTES
            }
        );
        let mut v = valid();
        v["protocol"] = json!("agentguard.authz.v0");
        assert!(matches!(
            parse(&v).unwrap_err().error,
            ProtocolError::UnsupportedProtocol { .. }
        ));
        for (path, value) in [
            ("/working_directory", json!("relative/dir")),
            ("/working_directory", json!("/work/\u{1b}[2J")),
            ("/request_id", json!("not-a-uuid")),
            ("/policy_version", json!("abc")),
            ("/action/path", json!("/a/\u{0}b")),
            ("/action/operation", json!("write; rm -rf /")),
            ("/project/root", json!("../x")),
        ] {
            let mut v = valid();
            *v.pointer_mut(path).unwrap() = value;
            assert!(parse(&v).is_err(), "{path}");
        }
        let mut v = valid();
        let attrs: serde_json::Map<String, Value> = (0..=MAX_ATTRIBUTES)
            .map(|i| (format!("k{i}"), json!("v")))
            .collect();
        v["context"]["attributes"] = Value::Object(attrs);
        assert!(parse(&v).is_err());
    }

    #[test]
    fn rejection_keeps_correlation_but_never_values() {
        let mut v = valid();
        v["action"]["operation"] = json!("ghp_0123456789abcdefghijklmnopqrstuvwxyz rm");
        v["action"]["sneaky"] = json!("ghp_0123456789abcdefghijklmnopqrstuvwxyz");
        let err = parse(&v).unwrap_err();
        assert_eq!(err.request_id.unwrap().to_string(), RID);
        assert!(!err.to_string().contains("ghp_"));
        assert!(!err.to_string().contains("sneaky"));

        let mut v = valid();
        v["action"]["operation"] = json!("ghp_0123456789abcdefghijklmnopqrstuvwxyz rm");
        let err = parse(&v).unwrap_err();
        assert_eq!(err.request_id.unwrap().to_string(), RID);
        assert!(!err.to_string().contains("ghp_"), "{err}");
    }

    #[test]
    fn response_keeps_approval_consistent() {
        let rule = RuleId::new("r").unwrap();
        let f = agentguard_core::OperationFingerprint::from_bytes([1; 32]);
        let r = AuthorizationResponse::new(
            None,
            Decision::RequireApproval,
            RiskLevel::High,
            rule.clone(),
            "x",
            None,
            Some(f),
        );
        assert!(r.approval.required);
        assert!(r.check().is_ok());
        assert!(!r.permits_execution());
        let downgraded = AuthorizationResponse::new(
            None,
            Decision::RequireApproval,
            RiskLevel::High,
            rule.clone(),
            "x",
            None,
            None,
        );
        assert_eq!(downgraded.decision, Decision::Deny);
        let allow = AuthorizationResponse::new(
            None,
            Decision::Allow,
            RiskLevel::Low,
            rule,
            "x",
            None,
            Some(f),
        );
        assert!(!allow.approval.required);
        assert!(allow.permits_execution());
        let mut forged = allow.clone();
        forged.approval.required = true;
        assert!(forged.check().is_err());
        assert!(!forged.permits_execution());
        let json = serde_json::to_string(&allow).unwrap();
        assert!(json.contains("\"decision\":\"ALLOW\""));
        assert_eq!(
            serde_json::from_str::<AuthorizationResponse>(&json).unwrap(),
            allow
        );
    }

    /// Property: arbitrary bytes, and arbitrary single-field corruptions of a valid request,
    /// never panic the parser; corruptions that remove or retype a field are always rejected.
    #[test]
    fn property_parser_total_and_strict() {
        let mut rng = fastrand::Rng::with_seed(0x5eed_a11c);
        for _ in 0..2000 {
            let len = rng.usize(0..512);
            let bytes: Vec<u8> = (0..len).map(|_| rng.u8(..)).collect();
            let _ = parse_request(&bytes, &LexicalResolver);
        }
        let paths = [
            "/protocol",
            "/request_id",
            "/agent",
            "/agent/kind",
            "/project",
            "/project/root",
            "/action",
            "/action/category",
            "/action/operation",
            "/action/path",
            "/working_directory",
            "/policy_version",
        ];
        let replacements = [json!(null), json!(1), json!([]), json!({}), json!(true)];
        for _ in 0..2000 {
            let mut v = valid();
            let path = paths[rng.usize(..paths.len())];
            if rng.bool() {
                let (parent, key) = path.rsplit_once('/').unwrap();
                let target = if parent.is_empty() {
                    &mut v
                } else {
                    v.pointer_mut(parent).unwrap()
                };
                target.as_object_mut().unwrap().remove(key);
            } else {
                *v.pointer_mut(path).unwrap() =
                    replacements[rng.usize(..replacements.len())].clone();
            }
            assert!(parse(&v).is_err(), "corrupted {path} still parsed");
        }
    }
}
