//! Forwarding calls to another node, over a real Iroh connection.
//!
//! Node B holds the apps and is the drive's host. Node A has no app: it syncs
//! the drive from B and has B as a known peer for it. The Iroh router and the
//! call handler are process globals (as in `atomic_lib`'s `iroh_e2e`), so the
//! networked scenarios share one node pair inside one test; the rights that
//! need no network are separate tests that call [`serve`] directly.

use std::sync::Arc;

use atomic_lib::{
    agents::{Agent, ForAgent},
    sync::{call::set_call_handler, peer, protocol::CallBudgetWire, protocol::CallRequest},
    Db, Storelike,
};
use serde_json::json;

use super::{
    call_as, call_entry, call_export, code,
    forward::{serve, IrohForwarder, ServedCalls},
    tests::{
        count_of, counter_resource, install, owner, share, CALLER, CALLER_MANIFEST, CALLER_WASM,
        COUNTER, COUNTER_MANIFEST, COUNTER_WASM,
    },
    CallBudget, HostAbiRegistry, MAX_CALL_DEPTH,
};
use crate::plugins::{manifest::ExportEffect, test_fixture::fixture};

fn wire(effects: Option<Vec<&str>>) -> CallBudgetWire {
    CallBudgetWire {
        calls: 1_000_000,
        fuel: u64::MAX,
        effects: effects.map(|e| e.into_iter().map(String::from).collect()),
        secrets: true,
    }
}

fn request(drive: &str, caller: &str, args: serde_json::Value) -> CallRequest {
    CallRequest {
        drive: drive.into(),
        interface: COUNTER.into(),
        function: "increment".into(),
        args: args.to_string(),
        caller: caller.into(),
        depth: 1,
        budget: wire(None),
    }
}

#[actix_rt::test]
async fn a_call_with_no_local_provider_runs_on_the_peer_that_has_the_app() {
    // -- Node B: the drive, both apps, a resource to count on.
    let f = fixture("host_abi_forward_b").await;
    let db_b = Arc::new(f.appstate.store.clone());
    let counter = install(&f, "counter", COUNTER_MANIFEST, COUNTER_WASM).await;
    let _caller = install(&f, "caller", CALLER_MANIFEST, CALLER_WASM).await;
    let (subject, property) = counter_resource(&f).await;
    // A reader of the drive who may even write the resource, but not the drive.
    let reader = Agent::new(None).unwrap().subject.to_string();
    share(&db_b, &f.drive, &[&reader], &[]).await;
    share(
        &db_b,
        &subject,
        &[&counter.agent, &reader],
        &[&counter.agent, &reader],
    )
    .await;
    let registry_b = Arc::new(HostAbiRegistry::new());
    registry_b.refresh(&db_b, &f.drive).await;
    set_call_handler(Arc::new(ServedCalls {
        registry: registry_b.clone(),
    }));
    let (node_b, router_b) = peer::start(f.appstate.store.clone()).await.unwrap();

    // -- Node A: the same person's other device. It syncs the drive, and has no
    // app it can run (the release is not part of a drive sync).
    let db_a = Db::init_temp("host_abi_forward_a").await.unwrap();
    db_a.load_agent_from_secret(&db_b.get_default_agent().unwrap().build_secret().unwrap())
        .await
        .unwrap();
    let ep_a = atomic_lib::sync::call::Endpoint::builder()
        .discovery_n0()
        .discovery_local_network()
        .bind()
        .await
        .unwrap();
    ep_a.add_node_addr(router_b.endpoint().node_addr().await.unwrap())
        .unwrap();
    // B's owner paired with A: B serves calls only for peers it knows.
    peer::add_known_peer(&db_b, &ep_a.node_id().to_string(), "a");
    peer::sync_drive_with_peer_using(&ep_a, &node_b.to_string(), &f.drive, &db_a, true)
        .await
        .unwrap();
    peer::add_known_peer_for_drive(&db_a, &node_b.to_string(), "b", &f.drive);
    let db_a = Arc::new(db_a);
    let registry_a = Arc::new(HostAbiRegistry::new());
    registry_a.set_forwarder(Arc::new(IrohForwarder::using(ep_a.clone())));
    registry_a.refresh(&db_a, &f.drive).await;
    assert!(
        registry_a.providers(&f.drive, COUNTER).is_empty(),
        "node A cannot run the counter itself"
    );
    let args = json!({"subject": subject, "property": property});

    // -- The call is forwarded, returns the same result, and the count is on B.
    let result = super::call_for_agent(
        &registry_a,
        &db_a,
        &f.drive,
        COUNTER,
        "increment",
        &args.to_string(),
        owner(&db_b),
        Arc::new(CallBudget::default()),
    )
    .await
    .unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&result).unwrap(),
        json!({"count": 1})
    );
    assert_eq!(count_of(&db_b, &subject, &property).await, 1);
    // The count is on B, where the app ran. A may get it too, through the live
    // sync it has with B, but it could not have written it: it has no app.

    // -- A caller who cannot write B's drive is forbidden there, for a write.
    let err = call_as(
        &registry_a,
        &db_a,
        &f.drive,
        COUNTER,
        "increment",
        &args.to_string(),
        ForAgent::AgentSubject(reader.as_str().into()),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code, code::FORBIDDEN, "{err:?}");
    assert_eq!(
        count_of(&db_b, &subject, &property).await,
        1,
        "nothing written"
    );

    // -- A read-only budget on A is read-only on B.
    registry_a.refresh(&db_a, &f.drive).await;
    let reads_only = || Arc::new(CallBudget::default().only(vec![ExportEffect::Read]));
    let err = call_entry(
        &registry_a,
        &db_a,
        &f.drive,
        COUNTER,
        "increment",
        &args.to_string(),
        owner(&db_b),
        reads_only(),
        super::ENTRY_TIMEOUT,
    )
    .await
    .unwrap_err();
    assert_eq!(err.code, code::FORBIDDEN, "{err:?}");
    assert_eq!(
        count_of(&db_b, &subject, &property).await,
        1,
        "nothing written"
    );
    // The same budget still runs a read there, and an app that calls on from B
    // cannot reach a write.
    let ok = call_entry(
        &registry_a,
        &db_a,
        &f.drive,
        CALLER,
        "recurse",
        &json!({"n": 0, "limit": 2}).to_string(),
        owner(&db_b),
        reads_only(),
        super::ENTRY_TIMEOUT,
    )
    .await;
    assert!(ok.is_ok(), "{ok:?}");
    let err = call_entry(
        &registry_a,
        &db_a,
        &f.drive,
        CALLER,
        "bump-twice",
        &args.to_string(),
        owner(&db_b),
        reads_only(),
        super::ENTRY_TIMEOUT,
    )
    .await
    .unwrap_err();
    assert_eq!(err.code, code::FORBIDDEN, "{err:?}");
    assert_eq!(
        count_of(&db_b, &subject, &property).await,
        1,
        "nothing written"
    );

    // -- Depth counts across the hop: the last allowed hop on A is one too many
    // on B.
    let err = call_export(
        &registry_a,
        &db_a,
        &f.drive,
        COUNTER,
        "increment",
        &args.to_string(),
        owner(&db_b),
        MAX_CALL_DEPTH - 1,
        Arc::new(CallBudget::default()),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code, code::DEPTH_EXCEEDED, "{err:?}");

    // -- A drive no peer syncs is answered as before.
    let err = call_as(
        &registry_a,
        &db_a,
        "did:ad:somewhere-else",
        COUNTER,
        "increment",
        &args.to_string(),
        owner(&db_b),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code, code::NOT_FOUND, "{err:?}");
}

#[actix_rt::test]
async fn the_forwarding_node_cannot_vouch_for_more_than_it_may_do_itself() {
    let f = fixture("host_abi_forward_via").await;
    let db = Arc::new(f.appstate.store.clone());
    let counter = install(&f, "counter", COUNTER_MANIFEST, COUNTER_WASM).await;
    let (subject, property) = counter_resource(&f).await;
    let node_agent = Agent::new(None).unwrap().subject.to_string();
    share(&db, &f.drive, &[&node_agent], &[]).await;
    share(&db, &subject, &[&counter.agent], &[&counter.agent]).await;
    let registry = Arc::new(HostAbiRegistry::new());
    registry.refresh(&db, &f.drive).await;
    let owner_subject = owner(&db).to_string();
    let args = json!({"subject": subject, "property": property});
    let ask = |via: ForAgent, caller: &str| {
        serve(
            registry.clone(),
            db.clone(),
            via,
            request(&f.drive, caller, args.clone()),
        )
    };

    // The caller (the owner) may write; the node that forwards may only read.
    let refused = ask(
        ForAgent::AgentSubject(node_agent.as_str().into()),
        &owner_subject,
    )
    .await
    .error
    .expect("refused");
    assert_eq!(refused.code, code::FORBIDDEN, "{refused:?}");
    assert_eq!(count_of(&db, &subject, &property).await, 0);

    // A node that may write vouches for the owner.
    let done = ask(owner(&db), &owner_subject).await;
    assert_eq!(done.result.as_deref(), Some(r#"{"count":1}"#), "{done:?}");

    // It cannot name `sudo` or the public as the caller, nor be nobody itself.
    for caller in [
        atomic_lib::urls::SUDO_AGENT,
        atomic_lib::urls::PUBLIC_AGENT,
        "",
    ] {
        let refused = ask(owner(&db), caller).await.error.expect("refused");
        assert_eq!(refused.code, code::FORBIDDEN, "{caller}: {refused:?}");
    }
    let refused = ask(ForAgent::Public, &owner_subject)
        .await
        .error
        .expect("refused");
    assert_eq!(refused.code, code::FORBIDDEN, "{refused:?}");
    assert_eq!(count_of(&db, &subject, &property).await, 1);
}

#[actix_rt::test]
async fn a_forwarded_call_is_never_made_as_an_installations_own_agent() {
    let f = fixture("host_abi_forward_own_agent").await;
    let db = Arc::new(f.appstate.store.clone());
    let counter = install(&f, "counter", COUNTER_MANIFEST, COUNTER_WASM).await;
    let _caller = install(&f, "caller", CALLER_MANIFEST, CALLER_WASM).await;
    let node_agent = owner(&db).to_string();
    // The app's agent can read the drive, so a read export would run for it.
    share(&db, &f.drive, &[&counter.agent], &[]).await;
    let registry = Arc::new(HostAbiRegistry::new());
    registry.refresh(&db, &f.drive).await;
    let read = |caller: &str| CallRequest {
        interface: CALLER.into(),
        function: "recurse".into(),
        args: json!({"n": 0, "limit": 2}).to_string(),
        ..request(&f.drive, caller, json!({}))
    };

    let ok = serve(
        registry.clone(),
        db.clone(),
        ForAgent::AgentSubject(node_agent.as_str().into()),
        read(&node_agent),
    )
    .await;
    assert!(ok.error.is_none(), "a person may call: {ok:?}");

    let refused = serve(
        registry.clone(),
        db.clone(),
        ForAgent::AgentSubject(node_agent.as_str().into()),
        read(&counter.agent),
    )
    .await
    .error
    .expect("refused");
    assert_eq!(refused.code, code::FORBIDDEN, "{refused:?}");
    assert!(refused.message.contains("own agent"), "{refused:?}");

    // The check does not depend on the app being loaded on this node.
    let unloaded = serve(
        Arc::new(HostAbiRegistry::new()),
        db.clone(),
        ForAgent::AgentSubject(node_agent.as_str().into()),
        read(&counter.agent),
    )
    .await
    .error
    .expect("refused");
    assert!(unloaded.message.contains("own agent"), "{unloaded:?}");
}

#[test]
fn a_budget_from_the_wire_is_never_wider_than_the_nodes_own() {
    let via = ForAgent::Public;
    let budget = CallBudget::from_wire(&wire(Some(vec!["read", "nonsense"])), via.clone());
    assert_eq!(budget.calls_left(), super::CHAIN_CALLS);
    assert_eq!(budget.fuel_left(), super::CHAIN_FUEL);
    assert!(
        !budget.may_forward(),
        "a served call is not forwarded again"
    );

    // An unknown effect is dropped, never read as "any": only reads remain.
    assert!(budget.allows(ExportEffect::Read).is_ok());
    assert!(budget.allows(ExportEffect::Write).is_err());
    let none = CallBudget::from_wire(&wire(Some(vec!["nonsense"])), via.clone());
    assert!(none.allows(ExportEffect::Read).is_err());

    // What the sender narrowed stays narrow.
    let small = CallBudgetWire {
        calls: 2,
        fuel: 7,
        effects: None,
        secrets: false,
    };
    let budget = CallBudget::from_wire(&small, via);
    assert_eq!((budget.calls_left(), budget.fuel_left()), (2, 7));
    assert!(!budget.wire(1, 1).secrets);
}
