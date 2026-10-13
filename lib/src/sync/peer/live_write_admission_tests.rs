use super::*;
use crate::Db;
use std::collections::HashMap;

/// Regression coverage for the live-sync write bypass: `apply_state_update`
/// / `apply_destroy` used to run with no ACL check and no admission-gate
/// check at all once a connection reached live mode. `admitted_for_drive`
/// is what closes it — these tests exercise it directly (rather than via a
/// full two-peer Iroh handshake) so the ACL and admission-gate layers are
/// each provable in isolation.
/// The relay case: a server holding our drive authenticates as its OWN
/// agent, which can't write our drive — so gating on the transport peer's
/// identity dropped every update it relayed back (a phone stopped receiving
/// a browser's edits once its drive already existed on the server). When WE
/// dialed the peer (`trust_owned`), an update to a drive our own agent owns
/// is accepted; a peer dialing into us gets no such relaxation.
#[tokio::test]
async fn relayed_write_to_our_own_drive_accepted_only_when_we_dialed() {
    let db = Db::init_temp("relay_owned_drive").await.unwrap();
    // Alice is this device's agent and owns the drive.
    let (_alice, drive) = db.setup("Alice").await.unwrap();
    // The server: a different agent with no rights to Alice's drive.
    let server = db.create_agent(Some("Server")).await.unwrap();
    let server_agent = ForAgent::AgentSubject(server.subject.clone());

    // Peer dialed into us (trust_owned=false): the server's own identity
    // can't write our drive, so its relayed write is refused.
    let mut cache = HashMap::new();
    assert!(
        !admitted_for_drive(&db, &server_agent, &drive, false, &mut cache).await,
        "a peer that dialed us may not write our drive on its own identity"
    );

    // We dialed the server (trust_owned=true): it is relaying updates to a
    // drive we own, which is the whole point of pairing with it.
    let mut cache = HashMap::new();
    assert!(
        admitted_for_drive(&db, &server_agent, &drive, true, &mut cache).await,
        "a server we dialed must be able to relay updates to our own drive"
    );
}

#[tokio::test]
async fn owner_admitted_stranger_rejected() {
    let db = Db::init_temp("live_admission_owner_vs_stranger")
        .await
        .unwrap();
    let (alice, drive) = db.setup("Alice").await.unwrap();
    let mallory = db.create_agent(Some("Mallory")).await.unwrap();

    let mut cache = HashMap::new();
    assert!(
        admitted_for_drive(
            &db,
            &ForAgent::AgentSubject(alice.subject.clone()),
            &drive,
            false,
            &mut cache
        )
        .await,
        "the drive's own owner must be admitted"
    );

    let mut cache = HashMap::new();
    assert!(
        !admitted_for_drive(
            &db,
            &ForAgent::AgentSubject(mallory.subject.clone()),
            &drive,
            false,
            &mut cache
        )
        .await,
        "an unrelated agent with no rights to the drive must be rejected"
    );
}

#[tokio::test]
async fn missing_drive_is_not_a_free_pass_for_public() {
    let db = Db::init_temp("live_admission_missing_public")
        .await
        .unwrap();
    let mut cache = HashMap::new();
    assert!(
        !admitted_for_drive(&db, &ForAgent::Public, "did:ad:brandnew", false, &mut cache).await,
        "Public must not live-write a drive this node has never stored"
    );
}

#[tokio::test]
async fn missing_drive_on_owner_mode_admits_only_the_owner() {
    let db = Db::init_temp("live_admission_missing_owner").await.unwrap();
    let (owner, _) = db.setup("Owner").await.unwrap();
    let stranger = db.create_agent(Some("Stranger")).await.unwrap();
    db.set_sync_policy(std::sync::Arc::new(crate::sync::policy::OwnerPolicy::new(
        owner.subject.to_string(),
    )));

    let missing = "did:ad:notonthisnode";
    let mut cache = HashMap::new();
    assert!(
        !admitted_for_drive(
            &db,
            &ForAgent::AgentSubject(stranger.subject.clone()),
            missing,
            false,
            &mut cache
        )
        .await,
        "a stranger must not live-write a drive this node has never stored"
    );

    let mut cache = HashMap::new();
    assert!(
        admitted_for_drive(
            &db,
            &ForAgent::AgentSubject(owner.subject.clone()),
            missing,
            false,
            &mut cache
        )
        .await,
        "the owner may live-write a drive arriving for the first time"
    );
    assert!(
        db.sync_policy().admit_drive_write(missing),
        "admitting the owner must enroll the drive"
    );
}

/// The admission gate (allowlist/quota) is checked too, not just the ACL —
/// even the rightful owner is rejected once their drive isn't admitted
/// (e.g. a managed node whose allowlist doesn't include this drive).
#[tokio::test]
async fn owner_rejected_when_drive_not_admitted() {
    let db = Db::init_temp("live_admission_policy_gate").await.unwrap();
    let (alice, drive) = db.setup("Alice").await.unwrap();

    let policy = std::sync::Arc::new(crate::sync::policy::AllowlistPolicy::new());
    policy.set_grace(std::time::Duration::ZERO);
    db.set_sync_policy(policy);

    let mut cache = HashMap::new();
    assert!(
        !admitted_for_drive(
            &db,
            &ForAgent::AgentSubject(alice.subject.clone()),
            &drive,
            false,
            &mut cache
        )
        .await,
        "the owner's ACL rights don't matter if the drive isn't admitted by policy"
    );
}

/// The cache actually gets populated after the first check, so a burst of
/// frames to the same drive on one connection doesn't re-walk the rights
/// hierarchy every time.
#[tokio::test]
async fn verdict_is_cached_after_first_check() {
    let db = Db::init_temp("live_admission_cache").await.unwrap();
    let (alice, drive) = db.setup("Alice").await.unwrap();

    let mut cache = HashMap::new();
    assert!(!cache.contains_key(&drive));
    admitted_for_drive(
        &db,
        &ForAgent::AgentSubject(alice.subject.clone()),
        &drive,
        false,
        &mut cache,
    )
    .await;
    assert_eq!(cache.get(&drive), Some(&true));
}

/// F3 follow-up: a `drive_cache` verdict computed under a weaker
/// identity (e.g. `Public`, before a late AUTH frame) must not survive
/// the identity change — otherwise a peer that proves a stronger
/// identity mid-connection keeps being rejected for a drive it now
/// legitimately has rights to, until reconnect.
#[tokio::test]
async fn stale_public_verdict_cleared_after_late_auth_upgrades_identity() {
    let db = Db::init_temp("live_admission_cache_identity_change")
        .await
        .unwrap();
    let (alice, drive) = db.setup("Alice").await.unwrap();

    // Simulate the connection starting as Public and getting rejected
    // for Alice's drive — the verdict lands in the cache.
    let mut cache = HashMap::new();
    assert!(
        !admitted_for_drive(&db, &ForAgent::Public, &drive, false, &mut cache).await,
        "Public should not be admitted for Alice's drive"
    );
    assert_eq!(cache.get(&drive), Some(&false));

    // A late AUTH frame strengthens the session to Alice herself.
    let previous = ForAgent::Public;
    let upgraded = ForAgent::AgentSubject(alice.subject.clone());
    invalidate_drive_cache_on_identity_change(&upgraded, &previous, &mut cache);
    assert!(
        !cache.contains_key(&drive),
        "the stale Public verdict must be gone after the identity change"
    );

    // Re-checking now correctly admits Alice — proving the clear
    // wasn't just cosmetic; a *stale* cache would have kept returning
    // the cached `false` regardless of the new identity.
    assert!(
        admitted_for_drive(&db, &upgraded, &drive, false, &mut cache).await,
        "Alice must be admitted for her own drive once the stale cache is cleared"
    );
}

/// Sanity check for the inverse: no identity change means no
/// invalidation — the whole point of the cache (skip re-walking rights
/// on every frame) would be defeated by clearing it unconditionally.
#[tokio::test]
async fn cache_survives_when_identity_is_unchanged() {
    let db = Db::init_temp("live_admission_cache_identity_stable")
        .await
        .unwrap();
    let (alice, drive) = db.setup("Alice").await.unwrap();

    let mut cache = HashMap::new();
    admitted_for_drive(
        &db,
        &ForAgent::AgentSubject(alice.subject.clone()),
        &drive,
        false,
        &mut cache,
    )
    .await;
    assert_eq!(cache.get(&drive), Some(&true));

    let same = ForAgent::AgentSubject(alice.subject.clone());
    invalidate_drive_cache_on_identity_change(&same, &same, &mut cache);
    assert_eq!(
        cache.get(&drive),
        Some(&true),
        "an unchanged identity must not clear the cache"
    );
}
