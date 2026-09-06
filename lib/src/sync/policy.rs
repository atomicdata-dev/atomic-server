//! Sync admission and quota policy.
//!
//! The default ([`OpenPolicy`]) is permissive, so local-first and self-hosted
//! peers keep their current behavior with no configuration at all. A managed
//! node installs a concrete policy on its [`crate::Db`] (see
//! `Db::set_sync_policy`); the engine consults it before importing a
//! `SYNC_PUSH`.
//!
//! The open core ships only the *mechanism* here (the trait + a generic
//! allowlist/quota impl). The control-plane client that *populates* a managed
//! policy at runtime lives outside the open core — see
//! `atomic-saas/planning/FOSS_SELF_HOST_GUARDRAILS.md`.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// Why a write to a drive was, or wasn't, admitted. Lets callers surface an
/// accurate error: a drive that isn't enrolled is a different problem from one
/// that's enrolled but over its storage quota — reporting the former as the
/// latter ("quota exceeded" for a drive that was never enrolled) is confusing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmitDecision {
    /// The write is allowed.
    Admitted,
    /// The drive isn't enrolled/allowlisted here (and isn't within a bootstrap
    /// grace window).
    NotEnrolled,
    /// The drive is enrolled but at or over its storage quota.
    OverQuota,
}

impl AdmitDecision {
    pub fn is_admitted(self) -> bool {
        matches!(self, AdmitDecision::Admitted)
    }
}

/// Admission + quota decisions for incoming drive sync. A [`crate::Db`] consults
/// its installed policy before admitting a write to a drive (SYNC_PUSH, commit,
/// blob, or realtime update).
pub trait SyncPolicy: Send + Sync {
    /// Whether this process may import data for `drive_subject` at all.
    fn drive_is_allowed(&self, drive_subject: &str) -> bool;

    /// Whether `drive_subject` is under its storage quota. Only meaningful when
    /// the drive is allowed.
    fn drive_within_quota(&self, drive_subject: &str) -> bool;

    /// Classify a write to `drive_subject` so callers can report *why* it was
    /// refused. The default composes the allowlist + quota checks; a policy with
    /// a bootstrap grace (see [`AllowlistPolicy`]) overrides this to admit a
    /// freshly-created drive while its enrollment propagates.
    ///
    /// Callers must only pass **drive** subjects — never agent (`did:ad:agent:…`)
    /// or other non-drive subjects, which are outside the enrollment model.
    fn admit_decision(&self, drive_subject: &str) -> AdmitDecision {
        if !self.drive_is_allowed(drive_subject) {
            AdmitDecision::NotEnrolled
        } else if !self.drive_within_quota(drive_subject) {
            AdmitDecision::OverQuota
        } else {
            AdmitDecision::Admitted
        }
    }

    /// Whether a write to `drive_subject` should be admitted right now.
    fn admit_drive_write(&self, drive_subject: &str) -> bool {
        self.admit_decision(drive_subject).is_admitted()
    }

    /// Whether `agent` may bring a drive this node has **never hosted** into
    /// existence here.
    ///
    /// This is the one question [`admit_decision`](Self::admit_decision) cannot
    /// answer, because it is about the *writer*, not the drive: a node that
    /// refuses every unknown drive can never be set up, and a node that accepts
    /// every unknown drive is free storage for the internet. Consulted only
    /// where a drive is genuinely new — the bootstrap paths — and never as a
    /// substitute for `admit_decision` on an existing one.
    ///
    /// Deliberately has no default: "may a stranger create a workspace here"
    /// has no answer that is safe to inherit by omission.
    fn may_enroll_drive(&self, drive_subject: &str, agent: &crate::agents::ForAgent) -> bool;

    /// Remember that this node now hosts `drive_subject`, so later writes to it
    /// are admitted. A no-op for policies with nothing to remember.
    fn enroll_drive(&self, _drive_subject: &str) {}

    /// What to tell whoever was refused, in their language rather than ours.
    ///
    /// The person reading this is usually not an operator: they clicked
    /// "create account" on someone else's server. "Drive … is not enrolled for
    /// sync on this node" tells them nothing they can act on, and reads like a
    /// malfunction rather than a decision.
    fn not_enrolled_message(&self, drive_subject: &str) -> String {
        format!("Drive {drive_subject} is not enrolled for sync on this node.")
    }
}

/// The default policy: every drive is allowed and there are no quotas. This is
/// what self-hosted and local-first nodes use, and is the [`crate::Db`] default
/// when nothing is installed.
#[derive(Debug, Default, Clone, Copy)]
pub struct OpenPolicy;

impl SyncPolicy for OpenPolicy {
    fn drive_is_allowed(&self, _drive_subject: &str) -> bool {
        true
    }

    fn drive_within_quota(&self, _drive_subject: &str) -> bool {
        true
    }

    /// Any authenticated agent. This is what "open" means for a localhost
    /// node — an upgrade must not change who may write — but
    /// [`crate::agents::ForAgent::Public`] never creates a drive. An
    /// unauthenticated `SYNC_PUSH` used to bootstrap a stranger's workspace
    /// onto an open node; AUTH-before-SYNC closed the wire, and this closes
    /// the library path.
    fn may_enroll_drive(&self, _drive_subject: &str, agent: &crate::agents::ForAgent) -> bool {
        !matches!(agent, crate::agents::ForAgent::Public)
    }
}

/// Per-drive quota configuration.
#[derive(Clone, Default)]
pub struct DrivePolicy {
    pub quota_bytes: Option<u64>,
}

/// A generic allowlist-plus-quota policy: only enrolled drives may sync, each
/// with an optional byte quota checked against the last reported usage.
///
/// This is a generic mechanism the open core ships; a control-plane client
/// (managed SaaS, or a self-hoster's own multi-tenant tooling) populates it at
/// runtime via [`set_drive_policies`](Self::set_drive_policies) and
/// [`record_drive_usage`](Self::record_drive_usage). It is interior-mutable so
/// it can be shared as `Arc<dyn SyncPolicy>` while being refreshed.
#[derive(Default)]
pub struct AllowlistPolicy {
    inner: RwLock<AllowlistState>,
}

/// Default bootstrap grace: how long a not-yet-allowlisted drive may keep syncing
/// after its first write on this node, so onboarding / first-backup can complete
/// while the enrollment propagates to the allowlist.
const DEFAULT_GRACE: Duration = Duration::from_secs(600);

struct AllowlistState {
    allowed: HashMap<String, DrivePolicy>,
    usage: HashMap<String, u64>,
    /// First time a *non-allowlisted* drive attempted a write on this node.
    first_seen: HashMap<String, Instant>,
    grace: Duration,
}

impl Default for AllowlistState {
    fn default() -> Self {
        Self {
            allowed: HashMap::new(),
            usage: HashMap::new(),
            first_seen: HashMap::new(),
            grace: DEFAULT_GRACE,
        }
    }
}

impl AllowlistPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the allowlist (drive subject -> optional byte quota). Drives
    /// absent from the list are rejected by [`Self::drive_is_allowed`].
    pub fn set_drive_policies<I, S>(&self, drives: I)
    where
        I: IntoIterator<Item = (S, Option<u64>)>,
        S: Into<String>,
    {
        let map = drives
            .into_iter()
            .map(|(subject, quota_bytes)| (subject.into(), DrivePolicy { quota_bytes }))
            .collect();
        if let Ok(mut guard) = self.inner.write() {
            guard.allowed = map;
        }
    }

    /// Add one drive to the allowlist, leaving the rest of it alone.
    ///
    /// [`set_drive_policies`](Self::set_drive_policies) replaces the whole list,
    /// which is right for a control plane pushing the current truth and wrong
    /// for a node enrolling the drive it just accepted — that would drop every
    /// other drive it hosts.
    pub fn enroll(&self, drive_subject: impl Into<String>) {
        if let Ok(mut guard) = self.inner.write() {
            guard
                .allowed
                .entry(drive_subject.into())
                .or_insert_with(DrivePolicy::default);
        }
    }

    /// The drive subjects currently allowed (i.e. the drives this node hosts).
    /// Used to scope the control-plane usage report to hosted drives.
    pub fn allowed_drive_subjects(&self) -> Vec<String> {
        self.inner
            .read()
            .map(|guard| guard.allowed.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// Record the latest per-drive usage (bytes) for quota checks.
    pub fn record_drive_usage<I, S>(&self, usage: I)
    where
        I: IntoIterator<Item = (S, u64)>,
        S: Into<String>,
    {
        if let Ok(mut guard) = self.inner.write() {
            for (subject, bytes) in usage {
                guard.usage.insert(subject.into(), bytes);
            }
        }
    }

    /// Set the bootstrap grace window (how long a not-yet-allowlisted drive may
    /// keep syncing after its first write here). `Duration::ZERO` disables grace.
    pub fn set_grace(&self, grace: Duration) {
        if let Ok(mut guard) = self.inner.write() {
            guard.grace = grace;
        }
    }

    /// Admission decision at a given instant (testable core of
    /// [`SyncPolicy::admit_decision`]). Allowlisted drives are admitted iff
    /// within quota; a non-allowlisted drive is admitted only while inside its
    /// bootstrap grace, measured from its first write here.
    fn decide_at(&self, drive_subject: &str, now: Instant) -> AdmitDecision {
        if self.drive_is_allowed(drive_subject) {
            return if self.drive_within_quota(drive_subject) {
                AdmitDecision::Admitted
            } else {
                AdmitDecision::OverQuota
            };
        }

        let Ok(mut guard) = self.inner.write() else {
            return AdmitDecision::NotEnrolled;
        };
        let grace = guard.grace;
        let first = *guard
            .first_seen
            .entry(drive_subject.to_string())
            .or_insert(now);

        if now.saturating_duration_since(first) < grace {
            AdmitDecision::Admitted
        } else {
            AdmitDecision::NotEnrolled
        }
    }
}

impl SyncPolicy for AllowlistPolicy {
    fn drive_is_allowed(&self, drive_subject: &str) -> bool {
        self.inner
            .read()
            .map(|guard| guard.allowed.contains_key(drive_subject))
            .unwrap_or(false)
    }

    fn drive_within_quota(&self, drive_subject: &str) -> bool {
        let Ok(guard) = self.inner.read() else {
            return false;
        };
        let Some(policy) = guard.allowed.get(drive_subject) else {
            return false; // not enrolled — rejected by the allowlist anyway
        };
        match policy.quota_bytes {
            Some(quota) => guard.usage.get(drive_subject).copied().unwrap_or(0) < quota,
            None => true,
        }
    }

    fn admit_decision(&self, drive_subject: &str) -> AdmitDecision {
        self.decide_at(drive_subject, Instant::now())
    }

    /// Nobody, by asking. A managed node's allowlist is the control plane's to
    /// populate; a drive appears here because it was enrolled out of band, not
    /// because someone pushed it.
    fn may_enroll_drive(&self, _drive_subject: &str, _agent: &crate::agents::ForAgent) -> bool {
        false
    }

    fn enroll_drive(&self, drive_subject: &str) {
        self.enroll(drive_subject);
    }
}

/// Only one agent may put new drives on this node.
///
/// The self-hosted counterpart to [`AllowlistPolicy`]: same allowlist, but
/// populated locally and synchronously instead of by a control plane. A node
/// running this hosts the drives it already had plus whatever its owner creates,
/// and refuses to become storage for anybody else.
///
/// What it does **not** touch: reading, ACL on existing resources, or writes by
/// collaborators to a drive that is already hosted. A guest invited to a drive
/// keeps working exactly as before — they just cannot genesis a drive of their
/// own here. Treating "has write on some hosted drive" as "may enroll a new
/// one" would be the same hole with extra steps.
pub struct OwnerPolicy {
    /// The owner's agent DID. Compared verbatim: an agent DID *is* a public
    /// key, so equality is the whole check.
    owner_agent: String,
    hosted: AllowlistPolicy,
}

impl OwnerPolicy {
    /// `owner_agent` is the DID (`did:ad:agent:…`), never a secret.
    ///
    /// Grace is zero, unlike a managed node's. A managed allowlist lags its
    /// control plane, so a freshly-enrolled drive needs a window to sync in;
    /// enrollment here is local and immediate, and that window is precisely how
    /// long a stranger would have to dump a drive before anyone noticed.
    pub fn new(owner_agent: impl Into<String>) -> Self {
        let hosted = AllowlistPolicy::new();
        hosted.set_grace(Duration::ZERO);

        Self {
            owner_agent: owner_agent.into(),
            hosted,
        }
    }

    /// Enroll the drives this node already stores.
    ///
    /// A node that ran Open and then gained an owner must keep serving what is
    /// already on its disk — including drives belonging to people the owner
    /// invited, or created before the switch. Gating those retroactively would
    /// turn on a security feature by deleting access to existing data.
    pub fn enroll_existing<I, S>(&self, drive_subjects: I)
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        for subject in drive_subjects {
            self.hosted.enroll(subject);
        }
    }
}

impl SyncPolicy for OwnerPolicy {
    fn drive_is_allowed(&self, drive_subject: &str) -> bool {
        self.hosted.drive_is_allowed(drive_subject)
    }

    fn drive_within_quota(&self, drive_subject: &str) -> bool {
        self.hosted.drive_within_quota(drive_subject)
    }

    fn admit_decision(&self, drive_subject: &str) -> AdmitDecision {
        self.hosted.admit_decision(drive_subject)
    }

    fn may_enroll_drive(&self, _drive_subject: &str, agent: &crate::agents::ForAgent) -> bool {
        match agent {
            // The node acting on its own behalf: initialization, migrations,
            // importing a backup. Refusing this would mean a gated node could
            // not finish booting.
            crate::agents::ForAgent::Sudo => true,
            crate::agents::ForAgent::AgentSubject(subject) => subject.as_str() == self.owner_agent,
            // An unauthenticated request is never the owner. Stated rather than
            // left to fall out of the comparison, because this is the case the
            // whole policy exists for.
            crate::agents::ForAgent::Public => false,
        }
    }

    fn enroll_drive(&self, drive_subject: &str) {
        self.hosted.enroll(drive_subject);
    }

    fn not_enrolled_message(&self, _drive_subject: &str) -> String {
        "This server does not host new Drives. Its owner runs it for their own \
         data, so you cannot create a workspace here.\n\n\
         You can still read anything they published, and open any Drive you were \
         invited to. To keep your own data, run your own server or use a hosted \
         one."
            .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::agents::ForAgent;

    const OWNER: &str = "did:ad:agent:ownerkey";
    const STRANGER: &str = "did:ad:agent:strangerkey";

    fn agent(subject: &str) -> ForAgent {
        ForAgent::AgentSubject(crate::Subject::from_raw(subject, None))
    }

    #[test]
    fn an_open_node_takes_a_drive_from_anyone_authenticated() {
        assert!(OpenPolicy.may_enroll_drive("did:ad:drive:new", &agent(STRANGER)));
        assert!(OpenPolicy.may_enroll_drive("did:ad:drive:new", &ForAgent::Sudo));
        assert!(
            !OpenPolicy.may_enroll_drive("did:ad:drive:new", &ForAgent::Public),
            "Public never creates a drive, even on an open node"
        );
    }

    #[test]
    fn only_the_owner_may_enroll_a_new_drive() {
        let policy = OwnerPolicy::new(OWNER);

        assert!(policy.may_enroll_drive("did:ad:drive:new", &agent(OWNER)));
        assert!(!policy.may_enroll_drive("did:ad:drive:new", &agent(STRANGER)));
        assert!(!policy.may_enroll_drive("did:ad:drive:new", &ForAgent::Public));
        // The node itself, so a gated node can still finish booting.
        assert!(policy.may_enroll_drive("did:ad:drive:new", &ForAgent::Sudo));
    }

    #[test]
    fn a_stranger_drive_is_refused_with_no_grace_window() {
        let policy = OwnerPolicy::new(OWNER);

        // Managed nodes admit an unknown drive briefly while enrollment
        // propagates. That window is exactly the abuse this mode closes, so the
        // very first attempt must be refused — not the second.
        assert_eq!(
            policy.admit_decision("did:ad:drive:stranger"),
            AdmitDecision::NotEnrolled
        );
        assert_eq!(
            policy.admit_decision("did:ad:drive:stranger"),
            AdmitDecision::NotEnrolled
        );
    }

    #[test]
    fn an_enrolled_drive_keeps_writing() {
        let policy = OwnerPolicy::new(OWNER);
        policy.enroll_drive("did:ad:drive:mine");

        assert_eq!(
            policy.admit_decision("did:ad:drive:mine"),
            AdmitDecision::Admitted
        );
    }

    #[test]
    fn drives_already_on_disk_survive_the_switch() {
        // Turning the gate on must not revoke access to data that is already
        // here — including a guest's drive created while the node was open.
        let policy = OwnerPolicy::new(OWNER);
        policy.enroll_existing(["did:ad:drive:from-before", "did:ad:drive:a-guests"]);

        for existing in ["did:ad:drive:from-before", "did:ad:drive:a-guests"] {
            assert_eq!(
                policy.admit_decision(existing),
                AdmitDecision::Admitted,
                "{existing}"
            );
        }
        assert_eq!(
            policy.admit_decision("did:ad:drive:brand-new"),
            AdmitDecision::NotEnrolled
        );
    }

    #[test]
    fn enrolling_one_drive_does_not_drop_the_others() {
        let policy = AllowlistPolicy::new();
        policy.set_drive_policies([("did:ad:drive:a", None), ("did:ad:drive:b", None)]);
        policy.enroll("did:ad:drive:c");

        let mut hosted = policy.allowed_drive_subjects();
        hosted.sort();
        assert_eq!(
            hosted,
            ["did:ad:drive:a", "did:ad:drive:b", "did:ad:drive:c"]
        );
    }

    #[test]
    fn the_refusal_explains_itself_to_a_visitor() {
        let message = OwnerPolicy::new(OWNER).not_enrolled_message("did:ad:drive:x");

        // No jargon, and no drive subject: the person reading this did not ask
        // for a drive by name, they clicked a button.
        assert!(!message.contains("enrolled"), "{message}");
        assert!(!message.contains("did:ad:drive:x"), "{message}");
        // It has to say what they *can* still do.
        assert!(message.contains("invited"), "{message}");
    }

    #[test]
    fn a_managed_allowlist_is_never_enrolled_by_asking() {
        let policy = AllowlistPolicy::new();
        assert!(!policy.may_enroll_drive("did:ad:drive:new", &agent(OWNER)));
    }

    #[test]
    fn open_policy_allows_everything() {
        let p = OpenPolicy;
        assert!(p.drive_is_allowed("did:ad:anything"));
        assert!(p.drive_within_quota("did:ad:anything"));
    }

    #[test]
    fn allowlist_rejects_unenrolled_and_enforces_quota() {
        let p = AllowlistPolicy::new();
        // Empty allowlist: nothing is allowed.
        assert!(!p.drive_is_allowed("did:ad:a"));
        assert!(!p.drive_within_quota("did:ad:a"));

        // Enroll `a` with a 100-byte quota, `b` with no quota.
        p.set_drive_policies([
            ("did:ad:a".to_string(), Some(100u64)),
            ("did:ad:b".to_string(), None),
        ]);
        assert!(p.drive_is_allowed("did:ad:a"));
        assert!(p.drive_is_allowed("did:ad:b"));
        assert!(!p.drive_is_allowed("did:ad:c"));

        // Under quota.
        assert!(p.drive_within_quota("did:ad:a"));
        p.record_drive_usage([("did:ad:a".to_string(), 100u64)]);
        // At/over quota.
        assert!(!p.drive_within_quota("did:ad:a"));
        // No quota -> always within.
        assert!(p.drive_within_quota("did:ad:b"));
    }

    #[test]
    fn open_policy_admits_every_write() {
        assert!(OpenPolicy.admit_drive_write("did:ad:anything"));
    }

    #[test]
    fn admits_allowlisted_drive_and_rejects_over_quota() {
        let p = AllowlistPolicy::new();
        p.set_drive_policies([("did:ad:a".to_string(), Some(100u64))]);
        assert!(p.admit_drive_write("did:ad:a"));

        p.record_drive_usage([("did:ad:a".to_string(), 100u64)]);
        assert!(!p.admit_drive_write("did:ad:a")); // over quota
    }

    #[test]
    fn grace_admits_new_drive_then_rejects_after_window() {
        let p = AllowlistPolicy::new();
        p.set_grace(Duration::from_secs(600));

        let t0 = Instant::now();
        // First write to an un-enrolled drive: admitted (records first-seen).
        assert!(p.decide_at("did:ad:new", t0).is_admitted());
        // Still within grace 5 min later.
        assert!(p
            .decide_at("did:ad:new", t0 + Duration::from_secs(300))
            .is_admitted());
        // Past the grace window: rejected as not-enrolled.
        assert_eq!(
            p.decide_at("did:ad:new", t0 + Duration::from_secs(601)),
            AdmitDecision::NotEnrolled
        );
    }

    #[test]
    fn zero_grace_rejects_unenrolled_immediately() {
        let p = AllowlistPolicy::new();
        p.set_grace(Duration::ZERO);
        assert_eq!(
            p.decide_at("did:ad:new", Instant::now()),
            AdmitDecision::NotEnrolled
        );
    }

    #[test]
    fn enrolling_during_grace_makes_admission_permanent() {
        let p = AllowlistPolicy::new();
        p.set_grace(Duration::from_secs(600));
        let t0 = Instant::now();

        assert!(p.decide_at("did:ad:d", t0).is_admitted()); // grace

        // Enrollment lands.
        p.set_drive_policies([("did:ad:d".to_string(), None)]);

        // Long after grace would have expired, still admitted because allowlisted.
        assert!(p
            .decide_at("did:ad:d", t0 + Duration::from_secs(10_000))
            .is_admitted());
    }

    #[test]
    fn decision_distinguishes_not_enrolled_from_over_quota() {
        let p = AllowlistPolicy::new();
        p.set_grace(Duration::ZERO); // no grace, so unenrolled is decisive
        let t0 = Instant::now();

        // Never enrolled → NotEnrolled (not a quota problem).
        assert_eq!(p.decide_at("did:ad:c", t0), AdmitDecision::NotEnrolled);

        // Enrolled with a 100-byte quota, under it → Admitted.
        p.set_drive_policies([("did:ad:a".to_string(), Some(100u64))]);
        assert_eq!(p.decide_at("did:ad:a", t0), AdmitDecision::Admitted);

        // Now at/over quota → OverQuota, NOT NotEnrolled.
        p.record_drive_usage([("did:ad:a".to_string(), 100u64)]);
        assert_eq!(p.decide_at("did:ad:a", t0), AdmitDecision::OverQuota);
    }
}
