//! Authorization requests: the wire schema and its validation into typed values.

use std::collections::BTreeMap;

use agentguard_core::action::{
    CloudAction, CloudOp, ConfigOp, ConfigurationAction, CustomToolAction, DatabaseAction,
    DatabaseOp, FileOp, FilesystemAction, GitAction, GitHubAction, GitHubOp, GitOp, InlineContent,
    NetworkAction, NetworkOp, PackageAction, PackageOp, SecretAction, SecretOp, TerminalAction,
    TerraformAction, TerraformOp, TransferAction, TransferKind, UnknownAction, MAX_PACKAGES,
};
use agentguard_core::ConfigScope;
use agentguard_core::{
    Action, AgentIdentity, AgentVersion, BoundedText, Environment, Host, Name, NormalizedPath,
    PathResolver, PolicyVersion, ProjectId, RepositoryId, RequestId, SessionId,
};
use serde::{Deserialize, Serialize};

use crate::error::{ProtocolError, Rejection};
use crate::{MAX_REQUEST_BYTES, PROTOCOL_VERSION};

/// Maximum number of free-form context attributes.
pub const MAX_ATTRIBUTES: usize = 16;

// ---------------------------------------------------------------------------------------------
// Wire schema. Every struct denies unknown fields, so a field the engine does not understand
// (for example an agent-supplied `decision`, `risk` or `approved`) rejects the whole request
// instead of being silently ignored. Duplicate keys are rejected by the derived deserialisers.
// ---------------------------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRequest {
    protocol: String,
    request_id: String,
    agent: WireAgent,
    project: WireProject,
    #[serde(default)]
    session_id: Option<String>,
    action: WireAction,
    working_directory: String,
    policy_version: String,
    #[serde(default)]
    context: WireContext,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireAgent {
    kind: String,
    #[serde(default)]
    version: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireProject {
    root: String,
    #[serde(default)]
    id: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct WireContext {
    #[serde(default)]
    tool: Option<String>,
    #[serde(default)]
    attributes: BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(tag = "category", rename_all = "kebab-case", deny_unknown_fields)]
enum WireAction {
    Filesystem {
        operation: String,
        path: String,
        #[serde(default)]
        destination: Option<String>,
        #[serde(default)]
        remote: Option<String>,
        #[serde(default)]
        content: Option<String>,
    },
    Terminal {
        command: String,
    },
    Git {
        operation: String,
        #[serde(default)]
        remote: Option<String>,
        #[serde(default)]
        target_ref: Option<String>,
        #[serde(default)]
        force: bool,
    },
    #[serde(rename = "github")]
    GitHub {
        operation: String,
        #[serde(default)]
        repository: Option<String>,
    },
    Secrets {
        operation: String,
        name: String,
    },
    Database {
        operation: String,
        target: String,
        #[serde(default)]
        environment: Option<String>,
    },
    Terraform {
        operation: String,
        #[serde(default)]
        workspace: Option<String>,
        #[serde(default)]
        environment: Option<String>,
    },
    Network {
        operation: String,
        host: String,
        #[serde(default)]
        port: Option<u16>,
    },
    ExternalTransfer {
        kind: String,
        destination: String,
    },
    CustomTool {
        tool: String,
        #[serde(default)]
        server: Option<String>,
    },
    PackageManager {
        operation: String,
        manager: String,
        #[serde(default)]
        packages: Vec<String>,
        #[serde(default)]
        global: bool,
    },
    Cloud {
        operation: String,
        provider: String,
        service: String,
        #[serde(default)]
        resource: Option<String>,
        #[serde(default)]
        environment: Option<String>,
    },
    Configuration {
        operation: String,
        scope: String,
        #[serde(default)]
        key: Option<String>,
        #[serde(default)]
        path: Option<String>,
    },
    Unknown {
        kind: String,
        operation: String,
        #[serde(default)]
        target: Option<String>,
    },
}

// ---------------------------------------------------------------------------------------------
// Validated request.
// ---------------------------------------------------------------------------------------------

/// The project a request claims to belong to. A claim only: the engine resolves the project
/// independently from its trusted registry and denies when the claim disagrees.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProjectClaim {
    /// Claimed root, resolved through the path resolver.
    pub root: NormalizedPath,
    /// Claimed identifier, when supplied.
    pub id: Option<ProjectId>,
}

/// Informational context from the integration. Never an input to a decision: it is recorded
/// for audit only.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ExecutionContext {
    /// The integration's own name for the tool (for example `Bash`).
    pub tool: Option<Name>,
    /// Up to [`MAX_ATTRIBUTES`] bounded key/value pairs.
    pub attributes: BTreeMap<Name, BoundedText<256>>,
}

/// A validated authorization request. Every field has passed its type's validation and every
/// path has been resolved; the identity fields are still *claims* until the engine verifies
/// them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthorizationRequest {
    /// Unique request ID, echoed in the response.
    pub request_id: RequestId,
    /// Claimed agent.
    pub agent: AgentIdentity,
    /// Claimed project.
    pub project: ProjectClaim,
    /// Session, where the integration has one.
    pub session: Option<SessionId>,
    /// The action.
    pub action: Action,
    /// Resolved working directory.
    pub working_directory: NormalizedPath,
    /// The policy version the requester expects to be evaluated under.
    pub policy_version: PolicyVersion,
    /// Informational context.
    pub context: ExecutionContext,
}

/// Parse and validate a request. Relative paths in the action resolve against the working
/// directory, which must itself be absolute.
pub fn parse_request(
    input: &[u8],
    resolver: &dyn PathResolver,
) -> Result<AuthorizationRequest, Rejection> {
    if input.len() > MAX_REQUEST_BYTES {
        return Err(Rejection {
            request_id: None,
            error: ProtocolError::TooLarge {
                max: MAX_REQUEST_BYTES,
            },
        });
    }
    let wire: WireRequest = serde_json::from_slice(input).map_err(|e| Rejection {
        request_id: salvage_request_id(input),
        error: ProtocolError::from_json(&e),
    })?;
    let request_id = wire.request_id.parse::<RequestId>().ok();
    validate(wire, resolver).map_err(|error| Rejection { request_id, error })
}

/// Recover a well-formed request ID from a request that failed schema validation, so the
/// denial can be correlated. Returns `None` for anything that is not a JSON object with a
/// valid UUID `request_id`.
fn salvage_request_id(input: &[u8]) -> Option<RequestId> {
    #[derive(Deserialize)]
    struct OnlyId {
        request_id: String,
    }
    serde_json::from_slice::<OnlyId>(input)
        .ok()
        .and_then(|v| v.request_id.parse().ok())
}

fn validate(
    wire: WireRequest,
    resolver: &dyn PathResolver,
) -> Result<AuthorizationRequest, ProtocolError> {
    if wire.protocol != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedProtocol {
            expected: PROTOCOL_VERSION,
        });
    }
    let request_id = wire
        .request_id
        .parse()
        .map_err(ProtocolError::invalid("request_id"))?;
    let agent = AgentIdentity {
        kind: wire
            .agent
            .kind
            .parse()
            .map_err(ProtocolError::invalid("agent.kind"))?,
        version: wire
            .agent
            .version
            .map(AgentVersion::new)
            .transpose()
            .map_err(ProtocolError::invalid("agent.version"))?,
    };
    // No base is passed, so a relative working directory is rejected by the resolver.
    let working_directory = resolver
        .resolve(None, &wire.working_directory)
        .map_err(ProtocolError::invalid("working_directory"))?;
    let project = ProjectClaim {
        root: resolver
            .resolve(None, &wire.project.root)
            .map_err(ProtocolError::invalid("project.root"))?,
        id: wire
            .project
            .id
            .map(|id| id.parse())
            .transpose()
            .map_err(ProtocolError::invalid("project.id"))?,
    };
    Ok(AuthorizationRequest {
        request_id,
        agent,
        project,
        session: wire
            .session_id
            .map(|s| s.parse())
            .transpose()
            .map_err(ProtocolError::invalid("session_id"))?,
        action: validate_action(wire.action, &working_directory, resolver)?,
        working_directory,
        policy_version: wire
            .policy_version
            .parse()
            .map_err(ProtocolError::invalid("policy_version"))?,
        context: validate_context(wire.context)?,
    })
}

fn validate_context(wire: WireContext) -> Result<ExecutionContext, ProtocolError> {
    if wire.attributes.len() > MAX_ATTRIBUTES {
        return Err(ProtocolError::Invalid {
            field: "context.attributes",
            source: agentguard_core::SecurityError::TextTooLong {
                field: "attributes",
                max: MAX_ATTRIBUTES,
            },
        });
    }
    let mut attributes = BTreeMap::new();
    for (key, value) in wire.attributes {
        attributes.insert(
            Name::new(key).map_err(ProtocolError::invalid("context.attributes"))?,
            BoundedText::new(value).map_err(ProtocolError::invalid("context.attributes"))?,
        );
    }
    Ok(ExecutionContext {
        tool: wire
            .tool
            .map(Name::new)
            .transpose()
            .map_err(ProtocolError::invalid("context.tool"))?,
        attributes,
    })
}

fn opt_name(value: Option<String>, field: &'static str) -> Result<Option<Name>, ProtocolError> {
    value
        .map(Name::new)
        .transpose()
        .map_err(ProtocolError::invalid(field))
}

fn opt_env(value: Option<&str>) -> Result<Environment, ProtocolError> {
    value
        .map_or(Ok(Environment::Unknown), Environment::parse)
        .map_err(ProtocolError::invalid("action.environment"))
}

fn filesystem_action(
    operation: &str,
    path: &str,
    destination: Option<String>,
    remote: Option<String>,
    content: Option<String>,
    cwd: &NormalizedPath,
    resolver: &dyn PathResolver,
) -> Result<FilesystemAction, ProtocolError> {
    Ok(FilesystemAction {
        op: FileOp::parse(operation).map_err(ProtocolError::invalid("action.operation"))?,
        path: resolver
            .resolve(Some(cwd), path)
            .map_err(ProtocolError::invalid("action.path"))?,
        destination: destination
            .map(|d| resolver.resolve(Some(cwd), &d))
            .transpose()
            .map_err(ProtocolError::invalid("action.destination"))?,
        remote: remote
            .map(Host::new)
            .transpose()
            .map_err(ProtocolError::invalid("action.remote"))?,
        content: content
            .map(InlineContent::new)
            .transpose()
            .map_err(ProtocolError::invalid("action.content"))?,
    })
}

fn validate_action(
    wire: WireAction,
    cwd: &NormalizedPath,
    resolver: &dyn PathResolver,
) -> Result<Action, ProtocolError> {
    let op = "action.operation";
    Ok(match wire {
        WireAction::Filesystem {
            operation,
            path,
            destination,
            remote,
            content,
        } => Action::Filesystem(filesystem_action(
            &operation,
            &path,
            destination,
            remote,
            content,
            cwd,
            resolver,
        )?),
        WireAction::Terminal { command } => Action::Terminal(TerminalAction {
            command: BoundedText::new_non_empty(command)
                .map_err(ProtocolError::invalid("action.command"))?,
        }),
        WireAction::Git {
            operation,
            remote,
            target_ref,
            force,
        } => Action::Git(GitAction {
            op: GitOp::parse(&operation).map_err(ProtocolError::invalid(op))?,
            remote: opt_name(remote, "action.remote")?,
            target_ref: opt_name(target_ref, "action.target_ref")?,
            force,
        }),
        WireAction::GitHub {
            operation,
            repository,
        } => Action::GitHub(GitHubAction {
            op: GitHubOp::parse(&operation).map_err(ProtocolError::invalid(op))?,
            repository: repository
                .map(|r| RepositoryId::parse(&r))
                .transpose()
                .map_err(ProtocolError::invalid("action.repository"))?,
        }),
        WireAction::Secrets { operation, name } => Action::Secrets(SecretAction {
            op: SecretOp::parse(&operation).map_err(ProtocolError::invalid(op))?,
            name: Name::new(name).map_err(ProtocolError::invalid("action.name"))?,
        }),
        WireAction::Database {
            operation,
            target,
            environment,
        } => Action::Database(DatabaseAction {
            op: DatabaseOp::parse(&operation).map_err(ProtocolError::invalid(op))?,
            target: Name::new(target).map_err(ProtocolError::invalid("action.target"))?,
            environment: opt_env(environment.as_deref())?,
        }),
        WireAction::Terraform {
            operation,
            workspace,
            environment,
        } => Action::Terraform(TerraformAction {
            op: TerraformOp::parse(&operation).map_err(ProtocolError::invalid(op))?,
            workspace: opt_name(workspace, "action.workspace")?,
            environment: opt_env(environment.as_deref())?,
        }),
        WireAction::Network {
            operation,
            host,
            port,
        } => Action::Network(NetworkAction {
            op: NetworkOp::parse(&operation).map_err(ProtocolError::invalid(op))?,
            host: Host::new(host).map_err(ProtocolError::invalid("action.host"))?,
            port,
        }),
        WireAction::ExternalTransfer { kind, destination } => {
            Action::ExternalTransfer(TransferAction {
                kind: TransferKind::parse(&kind).map_err(ProtocolError::invalid("action.kind"))?,
                destination: Host::new(destination)
                    .map_err(ProtocolError::invalid("action.destination"))?,
            })
        }
        WireAction::CustomTool { tool, server } => Action::CustomTool(CustomToolAction {
            tool: Name::new(tool).map_err(ProtocolError::invalid("action.tool"))?,
            server: opt_name(server, "action.server")?,
        }),
        WireAction::PackageManager {
            operation,
            manager,
            packages,
            global,
        } => {
            if packages.len() > MAX_PACKAGES {
                return Err(ProtocolError::Invalid {
                    field: "action.packages",
                    source: agentguard_core::SecurityError::TextTooLong {
                        field: "packages",
                        max: MAX_PACKAGES,
                    },
                });
            }
            Action::PackageManager(PackageAction {
                op: PackageOp::parse(&operation).map_err(ProtocolError::invalid(op))?,
                manager: Name::new(manager).map_err(ProtocolError::invalid("action.manager"))?,
                packages: packages
                    .into_iter()
                    .map(Name::new)
                    .collect::<Result<_, _>>()
                    .map_err(ProtocolError::invalid("action.packages"))?,
                global,
            })
        }
        WireAction::Cloud {
            operation,
            provider,
            service,
            resource,
            environment,
        } => Action::Cloud(CloudAction {
            op: CloudOp::parse(&operation).map_err(ProtocolError::invalid(op))?,
            provider: Name::new(provider).map_err(ProtocolError::invalid("action.provider"))?,
            service: Name::new(service).map_err(ProtocolError::invalid("action.service"))?,
            resource: opt_name(resource, "action.resource")?,
            environment: opt_env(environment.as_deref())?,
        }),
        WireAction::Configuration {
            operation,
            scope,
            key,
            path,
        } => Action::Configuration(ConfigurationAction {
            op: ConfigOp::parse(&operation).map_err(ProtocolError::invalid(op))?,
            scope: ConfigScope::parse(&scope).map_err(ProtocolError::invalid("action.scope"))?,
            key: opt_name(key, "action.key")?,
            path: path
                .map(|p| resolver.resolve(Some(cwd), &p))
                .transpose()
                .map_err(ProtocolError::invalid("action.path"))?,
        }),
        WireAction::Unknown {
            kind,
            operation,
            target,
        } => Action::Unknown(UnknownAction {
            kind: Name::new(kind).map_err(ProtocolError::invalid("action.kind"))?,
            operation: Name::new(operation).map_err(ProtocolError::invalid(op))?,
            target: target
                .map(BoundedText::new)
                .transpose()
                .map_err(ProtocolError::invalid("action.target"))?,
        }),
    })
}
