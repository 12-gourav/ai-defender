//! Data disclosure assessment: where an operation would send data, and whether that data is
//! secret.
//!
//! The assessment describes; policy decides. The mandatory baseline denies secret data flowing
//! to any external or unknown destination and secret data copied into ordinary files; profile
//! and global rules decide everything else. A known or allow-listed host never makes secret
//! disclosure acceptable by itself.

use agentguard_core::action::{FileOp, GitOp, PackageOp};
use agentguard_core::Action;
use agentguard_secrets::{Evidence, Severity};
use serde::Serialize;

use crate::normalize::{CommandAnalysis, CommandClass};
use crate::resource::{ResourceClassification, ResourceKind};

/// Where data would go.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, serde::Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum Destination {
    /// Nothing leaves the resource (delete, permission change).
    None,
    /// A file inside the project.
    LocalProjectFile,
    /// A file on this machine outside the project.
    LocalFile,
    /// The agent's context: what the agent reads or sees in command output reaches the agent
    /// and, for hosted models, its provider.
    AgentContext,
    /// The repository history (a commit).
    GitHistory,
    /// A Git remote.
    GitRemote,
    /// A package registry.
    PackageRegistry,
    /// A hosted AI service.
    AiService,
    /// A cloud, SaaS or code-hosting API.
    ExternalApi,
    /// Another network destination.
    ExternalNetwork,
    /// Cannot be determined (interpreters, containers, unmodelled tools).
    Unknown,
}

impl Destination {
    /// Kebab-case name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Destination::None => "none",
            Destination::LocalProjectFile => "local-project-file",
            Destination::LocalFile => "local-file",
            Destination::AgentContext => "agent-context",
            Destination::GitHistory => "git-history",
            Destination::GitRemote => "git-remote",
            Destination::PackageRegistry => "package-registry",
            Destination::AiService => "ai-service",
            Destination::ExternalApi => "external-api",
            Destination::ExternalNetwork => "external-network",
            Destination::Unknown => "unknown",
        }
    }

    /// Whether data leaves this machine or may do so (unknown counts as external).
    #[must_use]
    pub const fn is_external(self) -> bool {
        matches!(
            self,
            Destination::GitRemote
                | Destination::PackageRegistry
                | Destination::AiService
                | Destination::ExternalApi
                | Destination::ExternalNetwork
                | Destination::Unknown
        )
    }
}

/// Hosted AI service endpoints (suffix match). Informational: the destination class is
/// recorded for audit and rules; it grants nothing.
const AI_SERVICE_HOSTS: &[&str] = &[
    "api.openai.com",
    "openai.azure.com",
    "api.anthropic.com",
    "generativelanguage.googleapis.com",
    "aiplatform.googleapis.com",
    "api.mistral.ai",
    "api.cohere.ai",
    "api.cohere.com",
    "api.groq.com",
    "openrouter.ai",
    "api.together.xyz",
    "api.deepseek.com",
    "api.x.ai",
    "api-inference.huggingface.co",
];

fn host_destination(host: &str) -> Destination {
    let host = host.to_ascii_lowercase();
    if AI_SERVICE_HOSTS
        .iter()
        .any(|h| host == *h || host.ends_with(&format!(".{h}")))
        || (host.starts_with("bedrock-runtime.") && host.ends_with(".amazonaws.com"))
    {
        Destination::AiService
    } else {
        Destination::ExternalNetwork
    }
}

/// The disclosure assessment of one operation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DisclosureAssessment {
    /// Where the data goes.
    pub destination: Option<Destination>,
    /// The destination host, when stated.
    pub host: Option<String>,
    /// Whether the data is secret: a sensitive resource, or detected secrets at or above the
    /// blocking severity.
    pub secret_data: bool,
    /// Detected secrets in the content involved (counts and severities only).
    pub evidence: Evidence,
    /// Whether secret data would land in an ordinary (non-sensitive) local file.
    pub into_ordinary_file: bool,
}

/// What [`assess`] needs beyond the action.
pub struct DisclosureInput<'a> {
    /// The action.
    pub action: &'a Action,
    /// Terminal analysis, for commands.
    pub command: Option<&'a CommandAnalysis>,
    /// The classified resource (sources and destinations combined).
    pub resource: &'a ResourceClassification,
    /// The kind of the destination path alone (copy, rename, archive), when there is one.
    pub destination_kind: Option<ResourceKind>,
    /// Whether the source (not the destination) is a sensitive resource.
    pub source_sensitive: bool,
    /// Content evidence.
    pub evidence: Evidence,
    /// Detected secrets at or above this severity are secret data.
    pub block: Severity,
}

fn command_destination(c: &CommandAnalysis) -> Destination {
    let commit =
        c.executable.as_deref() == Some("git") && c.subcommand.as_deref() == Some("commit");
    match c.class {
        _ if commit => Destination::GitHistory,
        CommandClass::Network => Destination::ExternalNetwork,
        CommandClass::VcsRemote => Destination::GitRemote,
        CommandClass::PackagePublish => Destination::PackageRegistry,
        CommandClass::InfraChange | CommandClass::InfraRead => Destination::ExternalApi,
        CommandClass::Interpreter
        | CommandClass::Container
        | CommandClass::Unknown
        | CommandClass::Privileged
        | CommandClass::Bypass => Destination::Unknown,
        _ => Destination::AgentContext,
    }
}

/// Assess one operation.
#[must_use]
pub fn assess(input: &DisclosureInput<'_>) -> DisclosureAssessment {
    let detected = input.evidence.at_least(input.block);
    let resource_secret = input.resource.kind.is_secret()
        || input
            .resource
            .sensitive
            .is_some_and(crate::sensitive::SensitiveCategory::is_protected_resource);
    let local = |inside: bool| {
        if inside {
            Destination::LocalProjectFile
        } else {
            Destination::LocalFile
        }
    };
    let inside = input.resource.location == crate::resource::ResourceLocation::InsideProject;
    let (destination, host, secret_data) = match input.action {
        Action::Filesystem(a) => match a.op {
            FileOp::Read | FileOp::List | FileOp::Traverse => {
                (Destination::AgentContext, None, resource_secret || detected)
            }
            FileOp::Write | FileOp::Append => (local(inside), None, detected),
            FileOp::Copy | FileOp::Rename | FileOp::Archive => {
                (local(inside), None, input.source_sensitive || detected)
            }
            FileOp::Upload => {
                let host = a.remote.as_ref().map(ToString::to_string);
                (
                    host.as_deref()
                        .map_or(Destination::Unknown, host_destination),
                    host,
                    resource_secret || detected,
                )
            }
            FileOp::Download => (
                local(inside),
                a.remote.as_ref().map(ToString::to_string),
                false,
            ),
            _ => (Destination::None, None, false),
        },
        Action::Terminal(_) => {
            let d = input
                .command
                .map_or(Destination::Unknown, command_destination);
            (d, None, resource_secret || detected)
        }
        Action::Git(g) => match g.op {
            GitOp::Commit => (Destination::GitHistory, None, detected),
            GitOp::Push => (
                Destination::GitRemote,
                g.remote.as_ref().map(ToString::to_string),
                detected,
            ),
            _ => (Destination::LocalProjectFile, None, false),
        },
        Action::GitHub(_) => (Destination::ExternalApi, None, detected),
        Action::Secrets(_) => (Destination::AgentContext, None, true),
        Action::Network(n) => (
            host_destination(n.host.as_str()),
            Some(n.host.to_string()),
            detected,
        ),
        Action::ExternalTransfer(t) => (
            host_destination(t.destination.as_str()),
            Some(t.destination.to_string()),
            detected,
        ),
        Action::PackageManager(p) if p.op == PackageOp::Publish => {
            (Destination::PackageRegistry, None, detected)
        }
        Action::PackageManager(_) => (Destination::ExternalNetwork, None, false),
        Action::Database(_) | Action::Terraform(_) | Action::Cloud(_) => {
            (Destination::ExternalApi, None, detected)
        }
        Action::Configuration(_) => (local(inside), None, detected),
        Action::CustomTool(_) | Action::Unknown(_) => (Destination::Unknown, None, detected),
    };
    let destination_ordinary = input.destination_kind.is_none_or(|k| !k.is_secret());
    let into_ordinary_file = secret_data
        && matches!(
            destination,
            Destination::LocalProjectFile | Destination::LocalFile
        )
        && destination_ordinary
        && match input.action {
            Action::Filesystem(a) => matches!(
                a.op,
                FileOp::Write | FileOp::Append | FileOp::Copy | FileOp::Archive | FileOp::Rename
            ),
            _ => false,
        };
    DisclosureAssessment {
        destination: Some(destination),
        host,
        secret_data,
        evidence: input.evidence,
        into_ordinary_file,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts() {
        assert_eq!(host_destination("api.openai.com"), Destination::AiService);
        assert_eq!(
            host_destination("myorg.openai.azure.com"),
            Destination::AiService
        );
        assert_eq!(
            host_destination("bedrock-runtime.us-east-1.amazonaws.com"),
            Destination::AiService
        );
        assert_eq!(
            host_destination("evil-openai.com"),
            Destination::ExternalNetwork
        );
        assert_eq!(
            host_destination("example.com"),
            Destination::ExternalNetwork
        );
        assert!(Destination::Unknown.is_external());
        assert!(!Destination::AgentContext.is_external());
    }
}
