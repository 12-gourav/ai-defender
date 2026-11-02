//! Risk classification.
//!
//! A pure, deterministic function of the normalised action and its resource. It assesses how
//! bad the action could be (level, contributing factors, reversibility, scope) and how sure the
//! classification is; it never decides whether the action may happen. Policy may deny a
//! low-risk action and may allow (or require approval for) a high-risk one, within the engine's
//! floors. Uncertainty is reported, never resolved by guessing.

use agentguard_core::action::{
    CloudOp, ConfigOp, DatabaseOp, FileOp, GitHubOp, GitOp, NetworkOp, PackageOp, SecretOp,
    TerraformOp,
};
use agentguard_core::{Action, ProjectIdentity, RiskLevel};
use serde::Serialize;

use crate::normalize::{analyze_command, CommandAnalysis, CommandClass, Confidence};
use crate::resource::{
    classify_action, DefaultResourceClassifier, ResourceClassification, ResourceKind,
    ResourceLocation,
};

/// Why an action was rated as it was.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RiskFactor {
    /// The operation name is not recognised.
    UnknownOperation,
    /// A path lies outside the project.
    OutsideProject,
    /// A path looks like it holds credentials.
    SensitivePath,
    /// Data is destroyed.
    Destructive,
    /// History is rewritten or overwritten.
    HistoryRewrite,
    /// A remote system is changed.
    RemoteWrite,
    /// Secret material is read or changed.
    CredentialAccess,
    /// The target is production, or its environment is not stated.
    ProductionTarget,
    /// Infrastructure is changed.
    InfrastructureChange,
    /// Arbitrary code runs.
    ArbitraryExecution,
    /// The command matches a known dangerous pattern.
    DangerousCommand,
    /// The target is this machine, a private network, or a metadata endpoint.
    PrivateNetworkTarget,
    /// Data leaves the machine.
    DataEgress,
    /// Repository or account settings change.
    PermissionChange,
    /// Security configuration or trusted state is touched.
    SecurityConfiguration,
    /// Elevated privileges are requested.
    PrivilegeEscalation,
    /// Dependencies (third-party code that runs locally) change.
    SupplyChain,
    /// The action cannot be undone.
    Irreversible,
    /// The classification is uncertain.
    UncertainClassification,
    /// An attempt to bypass AgentGuard or the agent's safety controls.
    BypassAttempt,
}

/// How far the effects of an action reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ImpactScope {
    /// Nothing outside the agent's process (reads).
    Local,
    /// The project directory.
    Project,
    /// This machine beyond the project.
    Machine,
    /// Another system.
    Remote,
}

/// The classifier's verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RiskAssessment {
    /// Overall level: the highest any rule assigned.
    pub level: RiskLevel,
    /// Contributing factors, sorted and de-duplicated.
    pub factors: Vec<RiskFactor>,
    /// How sure the classification of the operation is.
    pub confidence: Confidence,
    /// Whether the effect can be undone locally.
    pub reversible: bool,
    /// How far the effect reaches.
    pub scope: ImpactScope,
}

struct Builder {
    level: RiskLevel,
    factors: Vec<RiskFactor>,
}

impl Builder {
    const fn new(level: RiskLevel) -> Self {
        Self {
            level,
            factors: Vec::new(),
        }
    }

    fn raise(&mut self, level: RiskLevel, factor: RiskFactor) {
        self.level = self.level.max(level);
        self.factors.push(factor);
    }
}

/// Command fragments that are dangerous wherever they appear, kept as a safety net beneath the
/// structured analysis (they also catch spellings the tokeniser classifies as unknown).
const CRITICAL_COMMAND_PATTERNS: &[&str] = &[
    "rm -rf /",
    "rm -fr /",
    "rm -rf ~",
    "rm -rf $home",
    "mkfs",
    "dd if=",
    ":(){",
    "> /dev/sd",
    "chmod -r 777 /",
    "| sh",
    "|sh",
    "| bash",
    "|bash",
];
const HIGH_COMMAND_PATTERNS: &[&str] = &[
    "sudo ",
    "su -",
    "rm -rf",
    "rm -fr",
    "rm -r",
    "chmod ",
    "chown ",
    "curl ",
    "wget ",
    "ssh ",
    "scp ",
    "rsync ",
    "nc ",
    "ncat ",
    "eval ",
    "base64 -d",
    "git push",
    "kubectl ",
    "terraform ",
    "docker ",
    "crontab",
    "systemctl ",
];

/// Classify `action` for `project` without a verified context: resources are classified with
/// no protected roots and terminal path arguments are not resolved. Kept for callers that only
/// have an action; the engine itself uses [`assess`] on a normalised action.
#[must_use]
pub fn classify(action: &Action, project: &ProjectIdentity) -> RiskAssessment {
    let command = match action {
        Action::Terminal(t) => Some(analyze_command(t.command.as_str())),
        _ => None,
    };
    let resource = classify_action(action, project, &DefaultResourceClassifier::default());
    let confidence = match (action, &command) {
        (_, Some(c)) => c.confidence,
        (Action::CustomTool(_) | Action::Unknown(_), None) => Confidence::Low,
        _ => Confidence::High,
    };
    assess_parts(action, &resource, command.as_ref(), confidence)
}

/// Assess a normalised action.
#[must_use]
pub fn assess(action: &crate::normalize::SecurityAction) -> RiskAssessment {
    assess_parts(
        &action.action,
        &action.resource,
        action.command.as_ref(),
        action.confidence,
    )
}

/// Assess from parts. Deterministic.
#[must_use]
pub fn assess_parts(
    action: &Action,
    resource: &ResourceClassification,
    command: Option<&CommandAnalysis>,
    confidence: Confidence,
) -> RiskAssessment {
    use RiskFactor as F;
    use RiskLevel::{High, Low, Medium};

    let mut b = Builder::new(Low);
    if action.is_unknown_operation() {
        b.raise(High, F::UnknownOperation);
    }
    assess_resource(&mut b, action, resource);
    match action {
        Action::Filesystem(a) => {
            let outside = resource.location != ResourceLocation::InsideProject;
            match a.op {
                // Unknown operations were already raised above.
                FileOp::Read | FileOp::List | FileOp::Traverse | FileOp::Unknown(_) => {}
                FileOp::Write
                | FileOp::Rename
                | FileOp::Append
                | FileOp::Copy
                | FileOp::Archive => {
                    b.raise(if outside { High } else { Medium }, F::Destructive);
                }
                FileOp::Download => {
                    b.raise(Medium, F::DataEgress);
                    b.raise(if outside { High } else { Medium }, F::Destructive);
                }
                FileOp::Upload => b.raise(High, F::DataEgress),
                FileOp::Delete | FileOp::ChangePermissions => b.raise(High, F::Destructive),
            }
        }
        Action::Terminal(t) => assess_terminal(&mut b, t.command.as_str(), command),
        Action::Git(g) => assess_git(&mut b, &g.op, g.force),
        Action::GitHub(g) => assess_github(&mut b, &g.op),
        Action::Secrets(s) => assess_secret(&mut b, &s.op),
        Action::Database(d) => {
            let prod = d.environment.is_production_like();
            assess_database(&mut b, &d.op, prod);
        }
        Action::Terraform(t) => {
            let prod = t.environment.is_production_like();
            assess_terraform(&mut b, &t.op, prod);
        }
        Action::Cloud(c) => {
            let prod = c.environment.is_production_like();
            assess_cloud(&mut b, &c.op, prod);
        }
        Action::Network(n) => {
            b.raise(Medium, F::DataEgress);
            if matches!(n.op, NetworkOp::Connect | NetworkOp::Unknown(_)) {
                b.raise(High, F::DataEgress);
            }
            if n.host.is_local_or_private() {
                b.raise(High, F::PrivateNetworkTarget);
            }
        }
        Action::ExternalTransfer(t) => {
            b.raise(High, F::DataEgress);
            if t.kind.is_unknown() || t.destination.is_local_or_private() {
                b.raise(RiskLevel::Critical, F::DataEgress);
            }
        }
        Action::PackageManager(p) => assess_package(&mut b, &p.op, p.global),
        Action::Configuration(c) => {
            if !matches!(c.op, ConfigOp::Read) {
                let level = if matches!(resource.kind, ResourceKind::SecurityConfiguration) {
                    High
                } else {
                    Medium
                };
                b.raise(level, F::PermissionChange);
            }
        }
        Action::CustomTool(_) => b.raise(Medium, F::ArbitraryExecution),
        Action::Unknown(_) => b.raise(High, F::UncertainClassification),
    }
    if confidence == Confidence::Low {
        b.raise(Medium, F::UncertainClassification);
    }
    let reversible = !is_irreversible(action, command);
    if !reversible {
        b.factors.push(F::Irreversible);
    }
    let scope = impact_scope(action, resource, command);
    b.factors.sort_unstable();
    b.factors.dedup();
    RiskAssessment {
        level: b.level,
        factors: b.factors,
        confidence,
        reversible,
        scope,
    }
}

fn assess_resource(b: &mut Builder, action: &Action, resource: &ResourceClassification) {
    use RiskFactor as F;
    use RiskLevel::{High, Medium};
    let local = matches!(
        action,
        Action::Filesystem(_) | Action::Terminal(_) | Action::Configuration(_)
    );
    if !local {
        return;
    }
    match resource.location {
        ResourceLocation::OutsideProject => b.raise(Medium, F::OutsideProject),
        ResourceLocation::TrustedState => b.raise(High, F::SecurityConfiguration),
        _ => {}
    }
    match resource.kind {
        k if k.is_secret() => b.raise(High, F::SensitivePath),
        ResourceKind::SecurityConfiguration if !action.is_read_only() => {
            b.raise(High, F::SecurityConfiguration);
        }
        ResourceKind::GitRepository if !action.is_read_only() => b.raise(High, F::HistoryRewrite),
        _ => {}
    }
}

fn assess_terminal(b: &mut Builder, text: &str, command: Option<&CommandAnalysis>) {
    use CommandClass as C;
    use RiskFactor as F;
    use RiskLevel::{Critical, High, Medium};
    b.raise(Medium, F::ArbitraryExecution);
    let lower = text.to_ascii_lowercase();
    if CRITICAL_COMMAND_PATTERNS.iter().any(|p| lower.contains(p)) {
        b.raise(Critical, F::DangerousCommand);
    } else if HIGH_COMMAND_PATTERNS.iter().any(|p| lower.contains(p)) {
        b.raise(High, F::DangerousCommand);
    }
    let Some(c) = command else { return };
    if c.pipes_into_interpreter {
        b.raise(Critical, F::DangerousCommand);
    }
    if c.privileged {
        b.raise(High, F::PrivilegeEscalation);
    }
    match c.class {
        C::ReadOnly
        | C::VcsRead
        | C::DevTool
        | C::VcsLocal
        | C::InfraRead
        | C::FileWrite
        | C::Unknown
        | C::VcsWrite
        | C::Interpreter => {}
        C::PackageChange => b.raise(High, F::SupplyChain),
        C::PackagePublish | C::VcsRemote => b.raise(High, F::RemoteWrite),
        C::Network => b.raise(High, F::DataEgress),
        C::PermissionChange => b.raise(High, F::PermissionChange),
        C::Container | C::Privileged => b.raise(High, F::PrivilegeEscalation),
        C::InfraChange => b.raise(High, F::InfrastructureChange),
        C::SecretAccess => b.raise(High, F::CredentialAccess),
        C::Destructive => b.raise(High, F::Destructive),
        C::Bypass => b.raise(Critical, F::BypassAttempt),
    }
}

fn assess_git(b: &mut Builder, op: &GitOp, force: bool) {
    use RiskFactor as F;
    use RiskLevel::{Critical, High, Medium};
    match op {
        // Unknown operations were already raised by the caller.
        GitOp::Status
        | GitOp::Diff
        | GitOp::Log
        | GitOp::Show
        | GitOp::BranchList
        | GitOp::Unknown(_) => {}
        GitOp::Add
        | GitOp::Stash
        | GitOp::Fetch
        | GitOp::Pull
        | GitOp::Clone
        | GitOp::Checkout
        | GitOp::Switch
        | GitOp::Branch
        | GitOp::Commit => b.raise(Medium, F::Destructive),
        GitOp::Merge | GitOp::Rebase | GitOp::Reset | GitOp::Tag => {
            b.raise(High, F::HistoryRewrite);
        }
        GitOp::Clean => b.raise(High, F::Destructive),
        GitOp::Push => b.raise(High, F::RemoteWrite),
        GitOp::Config => b.raise(High, F::PermissionChange),
    }
    if force {
        b.raise(Critical, F::HistoryRewrite);
    }
}

fn assess_github(b: &mut Builder, op: &GitHubOp) {
    use RiskFactor as F;
    use RiskLevel::{Critical, High, Medium};
    match op {
        GitHubOp::Read => {}
        GitHubOp::Comment | GitHubOp::CreateIssue | GitHubOp::CreatePullRequest => {
            b.raise(Medium, F::RemoteWrite);
        }
        GitHubOp::MergePullRequest | GitHubOp::CreateRelease | GitHubOp::TriggerWorkflow => {
            b.raise(High, F::RemoteWrite);
        }
        GitHubOp::ModifySettings => b.raise(Critical, F::PermissionChange),
        GitHubOp::DeleteRepository => b.raise(Critical, F::Destructive),
        GitHubOp::Unknown(_) => b.raise(High, F::RemoteWrite),
    }
}

fn assess_secret(b: &mut Builder, op: &SecretOp) {
    use RiskFactor as F;
    use RiskLevel::{Critical, High, Medium};
    match op {
        SecretOp::List => b.raise(Medium, F::CredentialAccess),
        SecretOp::Read => b.raise(High, F::CredentialAccess),
        SecretOp::Write | SecretOp::Delete | SecretOp::Unknown(_) => {
            b.raise(Critical, F::CredentialAccess);
        }
    }
}

fn assess_database(b: &mut Builder, op: &DatabaseOp, prod: bool) {
    use RiskFactor as F;
    use RiskLevel::{Critical, High, Medium};
    if prod {
        b.raise(Medium, F::ProductionTarget);
    }
    match op {
        DatabaseOp::Read => b.raise(if prod { High } else { Medium }, F::DataEgress),
        DatabaseOp::Write | DatabaseOp::BulkLoad | DatabaseOp::Migrate => {
            b.raise(if prod { Critical } else { High }, F::Destructive);
        }
        DatabaseOp::SchemaChange
        | DatabaseOp::Drop
        | DatabaseOp::Admin
        | DatabaseOp::Unknown(_) => {
            b.raise(Critical, F::Destructive);
        }
    }
}

fn assess_terraform(b: &mut Builder, op: &TerraformOp, prod: bool) {
    use RiskFactor as F;
    use RiskLevel::{Critical, High, Medium};
    if prod {
        b.raise(Medium, F::ProductionTarget);
    }
    match op {
        TerraformOp::Init | TerraformOp::Validate | TerraformOp::Plan => {
            b.raise(Medium, F::InfrastructureChange);
        }
        TerraformOp::Apply | TerraformOp::Import => {
            b.raise(if prod { Critical } else { High }, F::InfrastructureChange);
        }
        TerraformOp::Destroy | TerraformOp::StateModify | TerraformOp::Unknown(_) => {
            b.raise(Critical, F::InfrastructureChange);
        }
    }
}

fn assess_cloud(b: &mut Builder, op: &CloudOp, prod: bool) {
    use RiskFactor as F;
    use RiskLevel::{Critical, High, Medium};
    if prod {
        b.raise(Medium, F::ProductionTarget);
    }
    match op {
        CloudOp::Read | CloudOp::List => b.raise(Medium, F::InfrastructureChange),
        CloudOp::Create | CloudOp::Modify => {
            b.raise(if prod { Critical } else { High }, F::InfrastructureChange);
        }
        CloudOp::Delete => b.raise(if prod { Critical } else { High }, F::Destructive),
        CloudOp::ModifyIam | CloudOp::Unknown(_) => b.raise(Critical, F::PermissionChange),
    }
}

fn assess_package(b: &mut Builder, op: &PackageOp, global: bool) {
    use RiskFactor as F;
    use RiskLevel::{High, Low};
    match op {
        PackageOp::List | PackageOp::Audit => b.raise(Low, F::DataEgress),
        PackageOp::Install | PackageOp::Uninstall | PackageOp::Update | PackageOp::Unknown(_) => {
            b.raise(High, F::SupplyChain);
        }
        PackageOp::Publish => b.raise(High, F::RemoteWrite),
    }
    if global {
        b.raise(High, F::PrivilegeEscalation);
    }
}

fn is_irreversible(action: &Action, command: Option<&CommandAnalysis>) -> bool {
    match action {
        Action::Filesystem(a) => matches!(a.op, FileOp::Delete),
        Action::Terminal(_) => command.is_some_and(|c| {
            matches!(
                c.class,
                CommandClass::Destructive
                    | CommandClass::VcsRemote
                    | CommandClass::PackagePublish
                    | CommandClass::InfraChange
                    | CommandClass::Network
                    | CommandClass::Bypass
            )
        }),
        Action::Git(g) => g.force || matches!(g.op, GitOp::Push | GitOp::Clean),
        Action::GitHub(g) => !matches!(g.op, GitHubOp::Read),
        Action::Secrets(s) => matches!(s.op, SecretOp::Write | SecretOp::Delete),
        Action::Database(d) => !matches!(d.op, DatabaseOp::Read),
        Action::Terraform(t) => matches!(
            t.op,
            TerraformOp::Apply
                | TerraformOp::Destroy
                | TerraformOp::StateModify
                | TerraformOp::Import
        ),
        Action::Cloud(c) => !matches!(c.op, CloudOp::Read | CloudOp::List),
        Action::Network(_) | Action::ExternalTransfer(_) => true,
        Action::PackageManager(p) => matches!(p.op, PackageOp::Publish),
        Action::Configuration(_) | Action::CustomTool(_) | Action::Unknown(_) => false,
    }
}

fn impact_scope(
    action: &Action,
    resource: &ResourceClassification,
    command: Option<&CommandAnalysis>,
) -> ImpactScope {
    use crate::normalize::Capability;
    let remote_class = command.is_some_and(|c| {
        c.class.capabilities().contains(Capability::Network)
            || c.class.capabilities().contains(Capability::RemoteWrite)
    });
    let global_package = matches!(action, Action::PackageManager(p) if p.global);
    if resource.location == ResourceLocation::Remote || remote_class {
        ImpactScope::Remote
    } else if matches!(
        resource.location,
        ResourceLocation::OutsideProject | ResourceLocation::TrustedState
    ) || global_package
        || command.is_some_and(|c| c.privileged)
    {
        ImpactScope::Machine
    } else if action.is_read_only() {
        ImpactScope::Local
    } else {
        ImpactScope::Project
    }
}

// Unix paths throughout; the Windows path rules are tested in agentguard-core.
#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use agentguard_core::action::{
        DatabaseAction, FilesystemAction, GitAction, NetworkAction, SecretAction, TerminalAction,
    };
    use agentguard_core::{BoundedText, Environment, Host, Name, NormalizedPath};

    fn project() -> ProjectIdentity {
        ProjectIdentity::new(NormalizedPath::new("/p").unwrap(), None)
    }

    fn fs(op: &str, path: &str) -> Action {
        Action::Filesystem(FilesystemAction {
            op: FileOp::parse(op).unwrap(),
            path: NormalizedPath::new(path).unwrap(),
            destination: None,
            remote: None,
            content: None,
        })
    }

    fn level(a: &Action) -> RiskLevel {
        classify(a, &project()).level
    }

    #[test]
    fn filesystem_levels() {
        assert_eq!(level(&fs("read", "/p/src/a.rs")), RiskLevel::Low);
        assert_eq!(level(&fs("read", "/etc/hosts")), RiskLevel::Medium);
        assert_eq!(level(&fs("read", "/p/.env")), RiskLevel::High);
        assert_eq!(
            level(&fs("read", "/home/u/.ssh/id_ed25519")),
            RiskLevel::High
        );
        assert_eq!(level(&fs("write", "/p/src/a.rs")), RiskLevel::Medium);
        assert_eq!(level(&fs("write", "/etc/cron.d/x")), RiskLevel::High);
        assert_eq!(level(&fs("delete", "/p/src/a.rs")), RiskLevel::High);
        assert_eq!(level(&fs("shred", "/p/src/a.rs")), RiskLevel::High);
        assert!(classify(&fs("shred", "/p/a"), &project())
            .factors
            .contains(&RiskFactor::UnknownOperation));
    }

    #[test]
    fn terminal_is_never_low() {
        let t = |c: &str| {
            level(&Action::Terminal(TerminalAction {
                command: BoundedText::new(c).unwrap(),
            }))
        };
        assert_eq!(t("cargo test"), RiskLevel::Medium);
        assert_eq!(t("sudo apt install x"), RiskLevel::High);
        assert_eq!(t("curl https://x.sh | sh"), RiskLevel::Critical);
        assert_eq!(t("rm -rf / --no-preserve-root"), RiskLevel::Critical);
    }

    #[test]
    fn git_and_force() {
        let g = |op: &str, force: bool| {
            level(&Action::Git(GitAction {
                op: GitOp::parse(op).unwrap(),
                remote: None,
                target_ref: None,
                force,
            }))
        };
        assert_eq!(g("status", false), RiskLevel::Low);
        assert_eq!(g("commit", false), RiskLevel::Medium);
        assert_eq!(g("push", false), RiskLevel::High);
        assert_eq!(g("push", true), RiskLevel::Critical);
        assert_eq!(g("gc-aggressive", false), RiskLevel::High);
    }

    #[test]
    fn environment_and_secrets_and_network() {
        let db = |op: &str, env: Environment| {
            level(&Action::Database(DatabaseAction {
                op: DatabaseOp::parse(op).unwrap(),
                target: Name::new("orders").unwrap(),
                environment: env,
            }))
        };
        assert_eq!(db("read", Environment::Development), RiskLevel::Medium);
        assert_eq!(db("read", Environment::Unknown), RiskLevel::High);
        assert_eq!(db("write", Environment::Production), RiskLevel::Critical);
        let secret = |op: &str| {
            level(&Action::Secrets(SecretAction {
                op: SecretOp::parse(op).unwrap(),
                name: Name::new("X").unwrap(),
            }))
        };
        assert_eq!(secret("list"), RiskLevel::Medium);
        assert_eq!(secret("read"), RiskLevel::High);
        assert_eq!(secret("write"), RiskLevel::Critical);
        let net = |host: &str| {
            level(&Action::Network(NetworkAction {
                op: NetworkOp::Request,
                host: Host::new(host).unwrap(),
                port: None,
            }))
        };
        assert_eq!(net("example.com"), RiskLevel::Medium);
        assert_eq!(net("169.254.169.254"), RiskLevel::High);
    }

    #[test]
    fn deterministic() {
        let a = fs("write", "/p/.env");
        assert_eq!(classify(&a, &project()), classify(&a, &project()));
    }

    #[test]
    fn confidence_reversibility_and_scope() {
        let term = |c: &str| {
            classify(
                &Action::Terminal(TerminalAction {
                    command: BoundedText::new(c).unwrap(),
                }),
                &project(),
            )
        };
        let unknown = term("frobnicate --all");
        assert_eq!(unknown.confidence, Confidence::Low);
        assert!(unknown
            .factors
            .contains(&RiskFactor::UncertainClassification));
        assert_eq!(term("cargo test").confidence, Confidence::High);
        let push = term("git push origin main");
        assert!(!push.reversible);
        assert_eq!(push.scope, ImpactScope::Remote);
        assert_eq!(
            term("claude --dangerously-skip-permissions").level,
            RiskLevel::Critical
        );
        let read = classify(&fs("read", "/p/src/a.rs"), &project());
        assert!(read.reversible);
        assert_eq!(read.scope, ImpactScope::Local);
        assert!(!classify(&fs("delete", "/p/src/a.rs"), &project()).reversible);
        assert_eq!(
            classify(&fs("read", "/etc/hosts"), &project()).scope,
            ImpactScope::Machine
        );
    }

    #[test]
    fn new_categories() {
        use agentguard_core::action::{
            CloudAction, CloudOp, PackageAction, PackageOp, UnknownAction,
        };
        let pkg = |op: PackageOp, global: bool| {
            classify(
                &Action::PackageManager(PackageAction {
                    op,
                    manager: Name::new("npm").unwrap(),
                    packages: vec![],
                    global,
                }),
                &project(),
            )
        };
        assert_eq!(pkg(PackageOp::Install, false).level, RiskLevel::High);
        assert!(pkg(PackageOp::Install, true)
            .factors
            .contains(&RiskFactor::PrivilegeEscalation));
        assert_eq!(pkg(PackageOp::List, false).level, RiskLevel::Low);
        let cloud = |op: CloudOp, env: Environment| {
            classify(
                &Action::Cloud(CloudAction {
                    op,
                    provider: Name::new("aws").unwrap(),
                    service: Name::new("s3").unwrap(),
                    resource: None,
                    environment: env,
                }),
                &project(),
            )
            .level
        };
        assert_eq!(
            cloud(CloudOp::Delete, Environment::Production),
            RiskLevel::Critical
        );
        assert_eq!(
            cloud(CloudOp::Delete, Environment::Development),
            RiskLevel::High
        );
        assert_eq!(
            cloud(CloudOp::ModifyIam, Environment::Development),
            RiskLevel::Critical
        );
        let unknown = classify(
            &Action::Unknown(UnknownAction {
                kind: Name::new("vendor").unwrap(),
                operation: Name::new("frob").unwrap(),
                target: None,
            }),
            &project(),
        );
        assert_eq!(unknown.level, RiskLevel::High);
        assert_eq!(unknown.confidence, Confidence::Low);
    }
}
