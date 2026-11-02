//! Authorised trust operations.
//!
//! Every operation that changes trusted state:
//! 1. is requested by a human ([`Approver::Human`]); an agent requester is refused;
//! 2. verifies the current store completely first (a tampered store cannot be updated, only
//!    recovered);
//! 3. is authorised by a signature from a key the store already trusts for it: a policy signer
//!    for policies and registrations, the root key for key-set changes;
//! 4. validates the change (layer rules, baseline compatibility, registration rules);
//! 5. writes new versions, records old and new versions, and audits the outcome.
//!
//! The signing key is supplied by the caller for the duration of the call and never stored.
//! There is no development shortcut: an unsigned or self-signed change is always rejected.

use std::path::{Path, PathBuf};

use agentguard_audit::{AuditSink, SecurityEvent, TrustEventKind, TrustRecord};
use agentguard_core::{BoundedText, Name, PolicyVersion, ProjectId, RepositoryId};
use agentguard_engine::approval::Approver;
use agentguard_engine::PolicyEvaluator;
use time::OffsetDateTime;

use crate::canonical::{whole_seconds, ContentHash, Signed, VersionRef};
use crate::crypto::{PublicKey, Purpose, Signer};
use crate::error::TrustError;
use crate::hierarchy::{
    validate_document, EffectivePolicy, Layer, Provenance, MANDATORY_BASELINE_VERSION,
};
use crate::integrity::{IntegrityBody, INTEGRITY_SCHEMA};
use crate::keys::{KeyEntry, KeyRole, KeySetBody, RootAnchor, KEYSET_SCHEMA};
use crate::manifest::{ManifestBody, PolicyDocument, PolicyScope, MANIFEST_SCHEMA};
use crate::registry::{
    canonical_project_root, DirectoryIdentity, ProjectRegistration, RegistryBody, TrustStatus,
    REGISTRY_SCHEMA,
};
use crate::store::{create_new_object, PendingObject, TrustStore, VerifiedTrust};

/// A proposed policy change.
#[derive(Debug, Clone)]
pub struct PolicyUpdateRequest {
    /// Which layer.
    pub scope: PolicyScope,
    /// The proposed policy (replaces the layer's current policy).
    pub policy: PolicyDocument,
    /// Who asks.
    pub requested_by: Approver,
    /// Why.
    pub reason: BoundedText<256>,
}

/// The outcome of an authorised policy update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateReceipt {
    /// Which layer.
    pub scope: PolicyScope,
    /// The version replaced, if any.
    pub previous: Option<VersionRef>,
    /// The new version.
    pub current: VersionRef,
    /// The effective policy version for this layer's projects after the update (for the
    /// global layer: with no project restrictions).
    pub effective_version: PolicyVersion,
}

struct Audit<'a> {
    sink: &'a dyn AuditSink,
    actor: String,
}

impl Audit<'_> {
    fn record(
        &self,
        kind: TrustEventKind,
        subject: &str,
        detail: &str,
        versions: (Option<String>, Option<String>),
        project: Option<ProjectId>,
    ) -> Result<(), TrustError> {
        let event = SecurityEvent::Trust(Box::new(TrustRecord {
            kind,
            subject: subject.to_owned(),
            detail: detail.to_owned(),
            old_version: versions.0,
            new_version: versions.1,
            actor: Some(self.actor.clone()),
            project,
        }));
        self.sink
            .record(event.into_audit_event())
            .map(|_| ())
            .map_err(|_| TrustError::Io {
                object: "trust audit log",
                action: "written",
            })
    }

    /// Record a rejection. Best effort: the operation already failed closed.
    fn rejected(&self, subject: &str, error: &TrustError, project: Option<ProjectId>) {
        if error.is_integrity_failure() {
            let _ = self.record(
                error.event_kind(),
                subject,
                &error.to_string(),
                (None, None),
                project,
            );
        }
        let _ = self.record(
            TrustEventKind::PolicyUpdateRejected,
            subject,
            &error.to_string(),
            (None, None),
            project,
        );
    }
}

fn actor_of(requested_by: &Approver) -> String {
    match requested_by {
        Approver::Human { name } => format!("human:{name}"),
        Approver::Agent(agent) => format!("agent:{agent}"),
    }
}

fn human(requested_by: &Approver) -> Result<&Name, TrustError> {
    match requested_by {
        Approver::Human { name } => Ok(name),
        Approver::Agent(_) => Err(TrustError::SelfApproval),
    }
}

fn require_policy_signer(trust: &VerifiedTrust, signer: &dyn Signer) -> Result<(), TrustError> {
    if trust.keyset.policy_signers().contains(&signer.public_key()) {
        Ok(())
    } else {
        Err(TrustError::UnauthorizedSigner)
    }
}

fn subject_of(scope: PolicyScope) -> &'static str {
    match scope {
        PolicyScope::Global => "global policy",
        PolicyScope::Project(_) => "project policy",
    }
}

fn manifest_body(
    scope: PolicyScope,
    previous: Option<VersionRef>,
    policy: PolicyDocument,
    reason: BoundedText<256>,
    authorized_by: Name,
    now: OffsetDateTime,
) -> Result<ManifestBody, TrustError> {
    Ok(ManifestBody {
        schema: MANIFEST_SCHEMA.to_owned(),
        scope,
        sequence: previous.map_or(1, |p| p.sequence + 1),
        previous: previous.map(|p| p.hash),
        policy_hash: ContentHash::of(&policy)?,
        policy,
        reason,
        authorized_by,
        issued_at: now,
    })
}

fn signed_ref<T: serde::Serialize + serde::de::DeserializeOwned>(
    signed: &Signed<T>,
    sequence: u64,
) -> Result<VersionRef, TrustError> {
    Ok(VersionRef {
        sequence,
        hash: signed.body_hash()?,
    })
}

/// A new registry version with `projects`, signed by `signer`.
fn next_registry(
    trust: &VerifiedTrust,
    mut projects: Vec<ProjectRegistration>,
    signer: &dyn Signer,
    now: OffsetDateTime,
) -> Result<(Signed<RegistryBody>, VersionRef), TrustError> {
    projects.sort_by_key(|p| p.id);
    let body = RegistryBody {
        schema: REGISTRY_SCHEMA.to_owned(),
        sequence: trust.registry.sequence + 1,
        previous: Some(trust.integrity.registry.hash),
        projects,
        issued_at: now,
    };
    body.validate()?;
    let sequence = body.sequence;
    let envelope = Signed::sign(body, Purpose::Registry, signer)?;
    let pin = signed_ref(&envelope, sequence)?;
    Ok((envelope, pin))
}

/// Initialise an empty store: the root anchor, a key set holding `policy_signer`, an empty
/// global policy, an empty registry and the first integrity state. Refuses to run if any
/// trusted state exists, and refuses a root key that differs from an administrator-provisioned
/// system anchor.
pub fn initialize(
    store: &TrustStore,
    root_signer: &dyn Signer,
    policy_signer: &dyn Signer,
    policy_signer_label: Name,
    requested_by: &Approver,
    now: OffsetDateTime,
) -> Result<(), TrustError> {
    let name = human(requested_by)?.clone();
    if store.has_state() {
        return Err(TrustError::AlreadyInitialized);
    }
    let now = whole_seconds(now);
    let anchor = RootAnchor::new(root_signer.public_key(), now);
    store.check_new_root(&anchor)?;
    store.ensure_layout()?;

    let keyset = Signed::sign(
        KeySetBody {
            schema: KEYSET_SCHEMA.to_owned(),
            sequence: 1,
            previous: None,
            keys: vec![KeyEntry {
                public_key: policy_signer.public_key(),
                role: KeyRole::PolicySigner,
                label: policy_signer_label,
                added_at: now,
            }],
            issued_at: now,
        },
        Purpose::KeySet,
        root_signer,
    )?;
    let global = Signed::sign(
        manifest_body(
            PolicyScope::Global,
            None,
            PolicyDocument::default(),
            BoundedText::lossy("initial empty global policy"),
            name,
            now,
        )?,
        Purpose::PolicyManifest,
        policy_signer,
    )?;
    let registry = Signed::sign(
        RegistryBody {
            schema: REGISTRY_SCHEMA.to_owned(),
            sequence: 1,
            previous: None,
            projects: Vec::new(),
            issued_at: now,
        },
        Purpose::Registry,
        policy_signer,
    )?;
    let integrity = Signed::sign(
        IntegrityBody {
            schema: INTEGRITY_SCHEMA.to_owned(),
            sequence: 1,
            root_key: anchor.public_key.key_id(),
            keyset: signed_ref(&keyset, 1)?,
            global_policy: signed_ref(&global, 1)?,
            registry: signed_ref(&registry, 1)?,
            issued_at: now,
        },
        Purpose::Integrity,
        policy_signer,
    )?;
    create_new_object(&store.root_anchor_path(), &anchor, "root anchor")?;
    store.commit(
        &[
            PendingObject::new(store.keyset_path(1), &keyset, "key set")?,
            PendingObject::new(
                store.manifest_path(PolicyScope::Global, 1),
                &global,
                "global policy manifest",
            )?,
            PendingObject::new(store.registry_path(1), &registry, "project registry")?,
        ],
        &integrity,
    )?;
    let sink = store.open_audit_log()?;
    Audit {
        sink: &sink,
        actor: actor_of(requested_by),
    }
    .record(
        TrustEventKind::TrustInitialized,
        "trust store",
        &format!("initialised with root key {}", anchor.public_key.key_id()),
        (None, Some("1".to_owned())),
        None,
    )
}

/// Update a policy layer.
pub fn update_policy(
    store: &TrustStore,
    request: PolicyUpdateRequest,
    signer: &dyn Signer,
    now: OffsetDateTime,
    audit: &dyn AuditSink,
) -> Result<UpdateReceipt, TrustError> {
    let audit = Audit {
        sink: audit,
        actor: actor_of(&request.requested_by),
    };
    let subject = subject_of(request.scope);
    let project = match request.scope {
        PolicyScope::Project(id) => Some(id),
        PolicyScope::Global => None,
    };
    audit.record(
        TrustEventKind::PolicyUpdateRequested,
        subject,
        request.reason.as_str(),
        (None, None),
        project,
    )?;
    match apply_policy_update(store, request, signer, whole_seconds(now)) {
        Ok(receipt) => {
            audit.record(
                TrustEventKind::PolicyUpdateAuthorized,
                subject,
                &format!("committed by key {}", signer.public_key().key_id()),
                (
                    receipt.previous.map(|p| p.to_string()),
                    Some(receipt.current.to_string()),
                ),
                project,
            )?;
            Ok(receipt)
        }
        Err(e) => {
            audit.rejected(subject, &e, project);
            Err(e)
        }
    }
}

fn apply_policy_update(
    store: &TrustStore,
    request: PolicyUpdateRequest,
    signer: &dyn Signer,
    now: OffsetDateTime,
) -> Result<UpdateReceipt, TrustError> {
    let name = human(&request.requested_by)?.clone();
    let trust = store.load()?;
    require_policy_signer(&trust, signer)?;
    let scope = request.scope;
    let (layer, registration) = match scope {
        PolicyScope::Global => (Layer::Global, None),
        PolicyScope::Project(id) => {
            let registration = trust
                .registry
                .get(&id)
                .filter(|p| p.status == TrustStatus::Trusted)
                .ok_or(TrustError::ProjectRejected {
                    rule: "the project is not registered and trusted",
                })?;
            (Layer::Project, Some(registration.clone()))
        }
    };
    validate_document(layer, &request.policy)?;

    // Baseline compatibility: the merged policy must build with the proposed layer in place.
    let previous = match scope {
        PolicyScope::Global => Some(trust.integrity.global_policy),
        PolicyScope::Project(_) => registration.as_ref().and_then(|r| r.approved_policy),
    };
    let (global_doc, project_doc) = match scope {
        PolicyScope::Global => (&request.policy, None),
        PolicyScope::Project(_) => (&trust.global.policy, Some(&request.policy)),
    };
    let body = manifest_body(
        scope,
        previous,
        request.policy.clone(),
        request.reason,
        name,
        now,
    )?;
    let sequence = body.sequence;
    let manifest = Signed::sign(body, Purpose::PolicyManifest, signer)?;
    let current = signed_ref(&manifest, sequence)?;
    let effective = EffectivePolicy::merge(
        global_doc,
        project_doc,
        Provenance {
            mandatory: MANDATORY_BASELINE_VERSION,
            global: Some(trust.integrity.global_policy),
            project: Some(current),
        },
    )?;

    let mut objects = vec![PendingObject::new(
        store.manifest_path(scope, sequence),
        &manifest,
        scope.object(),
    )?];
    let integrity = match registration {
        None => trust.integrity.next(None, Some(current), None, now),
        Some(mut entry) => {
            entry.approved_policy = Some(current);
            let mut projects: Vec<_> = trust
                .registry
                .projects
                .iter()
                .filter(|p| p.id != entry.id)
                .cloned()
                .collect();
            projects.push(entry);
            let (registry, pin) = next_registry(&trust, projects, signer, now)?;
            objects.push(PendingObject::new(
                store.registry_path(pin.sequence),
                &registry,
                "project registry",
            )?);
            trust.integrity.next(None, None, Some(pin), now)
        }
    };
    let integrity = Signed::sign(integrity, Purpose::Integrity, signer)?;
    store.commit(&objects, &integrity)?;
    Ok(UpdateReceipt {
        scope,
        previous,
        current,
        effective_version: effective.version(),
    })
}

/// Register (or re-trust a revoked) project at `path`.
pub fn register_project(
    store: &TrustStore,
    path: &Path,
    repository: Option<RepositoryId>,
    requested_by: &Approver,
    signer: &dyn Signer,
    now: OffsetDateTime,
    audit: &dyn AuditSink,
) -> Result<ProjectRegistration, TrustError> {
    let audit = Audit {
        sink: audit,
        actor: actor_of(requested_by),
    };
    let subject = "project registration";
    let result = (|| {
        human(requested_by)?;
        let now = whole_seconds(now);
        let trust = store.load()?;
        require_policy_signer(&trust, signer)?;
        let root = canonical_project_root(path, store.root())?;
        let id = ProjectId::derive(&root);
        let existing = trust.registry.get(&id);
        if existing.is_some_and(|p| p.status == TrustStatus::Trusted) {
            return Err(TrustError::ProjectRejected {
                rule: "the project is already registered",
            });
        }
        let registration = ProjectRegistration {
            id,
            directory: DirectoryIdentity::observe(&root)?,
            root,
            status: TrustStatus::Trusted,
            approved_policy: existing.and_then(|p| p.approved_policy),
            repository,
            registered_at: now,
        };
        let mut projects: Vec<_> = trust
            .registry
            .projects
            .iter()
            .filter(|p| p.id != id)
            .cloned()
            .collect();
        projects.push(registration.clone());
        let (registry, pin) = next_registry(&trust, projects, signer, now)?;
        let integrity = Signed::sign(
            trust.integrity.next(None, None, Some(pin), now),
            Purpose::Integrity,
            signer,
        )?;
        store.commit(
            &[PendingObject::new(
                store.registry_path(pin.sequence),
                &registry,
                "project registry",
            )?],
            &integrity,
        )?;
        Ok(registration)
    })();
    match result {
        Ok(registration) => {
            audit.record(
                TrustEventKind::ProjectRegistered,
                &format!("project {}", registration.root),
                "registered and trusted",
                (None, None),
                Some(registration.id),
            )?;
            Ok(registration)
        }
        Err(e) => {
            audit.rejected(subject, &e, None);
            Err(e)
        }
    }
}

/// Revoke a project's trust. Requests from it are then treated as unregistered.
pub fn revoke_project(
    store: &TrustStore,
    id: &ProjectId,
    requested_by: &Approver,
    signer: &dyn Signer,
    now: OffsetDateTime,
    audit: &dyn AuditSink,
) -> Result<(), TrustError> {
    let audit = Audit {
        sink: audit,
        actor: actor_of(requested_by),
    };
    let result = (|| {
        human(requested_by)?;
        let now = whole_seconds(now);
        let trust = store.load()?;
        require_policy_signer(&trust, signer)?;
        let projects: Vec<_> = trust
            .registry
            .projects
            .iter()
            .map(|p| {
                let mut p = p.clone();
                if &p.id == id {
                    p.status = TrustStatus::Revoked;
                }
                p
            })
            .collect();
        if !trust
            .registry
            .get(id)
            .is_some_and(|p| p.status == TrustStatus::Trusted)
        {
            return Err(TrustError::ProjectRejected {
                rule: "the project is not registered and trusted",
            });
        }
        let (registry, pin) = next_registry(&trust, projects, signer, now)?;
        let integrity = Signed::sign(
            trust.integrity.next(None, None, Some(pin), now),
            Purpose::Integrity,
            signer,
        )?;
        store.commit(
            &[PendingObject::new(
                store.registry_path(pin.sequence),
                &registry,
                "project registry",
            )?],
            &integrity,
        )
    })();
    match result {
        Ok(()) => audit.record(
            TrustEventKind::ProjectTrustRevoked,
            "project",
            "trust revoked",
            (None, None),
            Some(*id),
        ),
        Err(e) => {
            audit.rejected("project revocation", &e, Some(*id));
            Err(e)
        }
    }
}

/// Replace the policy-signing key set. Requires the root key. Every current trusted object is
/// re-issued under the root key in the same commit, so objects signed by a removed key stop
/// being current immediately.
pub fn rotate_keyset(
    store: &TrustStore,
    keys: Vec<(PublicKey, Name)>,
    requested_by: &Approver,
    root_signer: &dyn Signer,
    now: OffsetDateTime,
    audit: &dyn AuditSink,
) -> Result<(), TrustError> {
    let audit = Audit {
        sink: audit,
        actor: actor_of(requested_by),
    };
    match apply_rotation(store, keys, requested_by, root_signer, whole_seconds(now)) {
        Ok((old, new)) => audit.record(
            TrustEventKind::KeySetRotated,
            "key set",
            &format!("rotated by root key {}", root_signer.public_key().key_id()),
            (Some(old.to_string()), Some(new.to_string())),
            None,
        ),
        Err(e) => {
            if matches!(e, TrustError::KeyChange { .. }) {
                let _ = audit.record(
                    TrustEventKind::KeyChangeRejected,
                    "key set",
                    &e.to_string(),
                    (None, None),
                    None,
                );
            }
            audit.rejected("key set", &e, None);
            Err(e)
        }
    }
}

fn apply_rotation(
    store: &TrustStore,
    keys: Vec<(PublicKey, Name)>,
    requested_by: &Approver,
    root_signer: &dyn Signer,
    now: OffsetDateTime,
) -> Result<(VersionRef, VersionRef), TrustError> {
    let name = human(requested_by)?.clone();
    let trust = store.load()?;
    if root_signer.public_key() != trust.root.public_key {
        return Err(TrustError::KeyChange {
            rule: "key set changes must be signed by the root key",
        });
    }
    let keyset_body = KeySetBody {
        schema: KEYSET_SCHEMA.to_owned(),
        sequence: trust.keyset.sequence + 1,
        previous: Some(trust.integrity.keyset.hash),
        keys: keys
            .into_iter()
            .map(|(public_key, label)| KeyEntry {
                public_key,
                role: KeyRole::PolicySigner,
                label,
                added_at: now,
            })
            .collect(),
        issued_at: now,
    };
    keyset_body.validate()?;
    let keyset_seq = keyset_body.sequence;
    let keyset = Signed::sign(keyset_body, Purpose::KeySet, root_signer)?;
    let keyset_pin = signed_ref(&keyset, keyset_seq)?;
    let mut objects = vec![PendingObject::new(
        store.keyset_path(keyset_seq),
        &keyset,
        "key set",
    )?];

    let reason = BoundedText::lossy("re-issued under the root key during key rotation");
    let mut reissue = |scope: PolicyScope, previous: VersionRef, policy: &PolicyDocument| {
        let body = manifest_body(
            scope,
            Some(previous),
            policy.clone(),
            reason.clone(),
            name.clone(),
            now,
        )?;
        let seq = body.sequence;
        let signed = Signed::sign(body, Purpose::PolicyManifest, root_signer)?;
        objects.push(PendingObject::new(
            store.manifest_path(scope, seq),
            &signed,
            scope.object(),
        )?);
        signed_ref(&signed, seq)
    };
    let global_pin = reissue(
        PolicyScope::Global,
        trust.integrity.global_policy,
        &trust.global.policy,
    )?;
    let mut projects = trust.registry.projects.clone();
    for project in &mut projects {
        if let (Some(pin), Some(manifest)) = (
            project.approved_policy,
            trust.project_policies.get(&project.id),
        ) {
            project.approved_policy = Some(reissue(
                PolicyScope::Project(project.id),
                pin,
                &manifest.policy,
            )?);
        }
    }
    let (registry, registry_pin) = next_registry(&trust, projects, root_signer, now)?;
    objects.push(PendingObject::new(
        store.registry_path(registry_pin.sequence),
        &registry,
        "project registry",
    )?);
    let integrity = Signed::sign(
        trust
            .integrity
            .next(Some(keyset_pin), Some(global_pin), Some(registry_pin), now),
        Purpose::Integrity,
        root_signer,
    )?;
    store.commit(&objects, &integrity)?;
    Ok((trust.integrity.keyset, keyset_pin))
}

/// Recovery from tampering or a lost key: move the whole trust store aside (never delete or
/// regenerate it in place) so an authorised human can inspect it and initialise a new one.
/// Until then every protected operation is denied. Returns where the old store now is.
pub fn quarantine(
    store: &TrustStore,
    requested_by: &Approver,
    now: OffsetDateTime,
) -> Result<PathBuf, TrustError> {
    human(requested_by)?;
    if let Ok(sink) = store.open_audit_log() {
        let _ = Audit {
            sink: &sink,
            actor: actor_of(requested_by),
        }
        .record(
            TrustEventKind::IntegrityFailed,
            "trust store",
            "quarantined for recovery by an authorised human",
            (None, None),
            None,
        );
    }
    let name = store
        .root()
        .file_name()
        .ok_or(TrustError::Io {
            object: "trust store",
            action: "named",
        })?
        .to_string_lossy()
        .into_owned();
    let target = store
        .root()
        .with_file_name(format!("{name}.quarantine-{}", now.unix_timestamp()));
    std::fs::rename(store.root(), &target).map_err(|_| TrustError::Io {
        object: "trust store",
        action: "quarantined",
    })?;
    Ok(target)
}
