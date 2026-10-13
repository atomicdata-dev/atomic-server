lazy_static::lazy_static! {
    pub static ref OPTS: CommitOpts = CommitOpts {
        validate_schema: true,
        validate_constraints: true,
        validate_signature: true,
        validate_timestamp: true,
        validate_loro_causality: true,
        validate_rights: false,
        validate_for_agent: None,
        update_index: true,
        source_id: None,
    };
}

use super::*;
use crate::{agents::Agent, Store, Storelike};

/// Helper: build a store with a known agent whose private key we control.
async fn store_with_known_agent() -> (crate::Store, Agent) {
    let store = Store::init().await.unwrap();
    store.set_base_url("http://localhost:9883");
    store.populate().await.unwrap();
    let private_key = "CapMWIhFUT+w7ANv9oCPqrHrwZpkP2JhzF9JnyT6WcI=";
    let agent = Agent::new_from_private_key(None, private_key).unwrap();
    store
        .add_resource(&agent.to_resource().unwrap())
        .await
        .unwrap();
    (store, agent)
}

fn rights_opts() -> CommitOpts {
    CommitOpts {
        validate_signature: true,
        validate_rights: true,
        ..CommitOpts::no_validations_no_index()
    }
}

/// A parentless DID drive whose `write` names `owner`; returns its DID.
async fn owned_drive(store: &Store, owner: &Agent) -> String {
    let mut b = CommitBuilder::new("placeholder".into());
    b.set(
        urls::IS_A.into(),
        Value::from(vec![urls::DRIVE.to_string()]),
    );
    b.set(
        urls::WRITE.into(),
        Value::from(vec![owner.subject.to_string()]),
    );
    let commit = Commit::create_did(b, owner, store).await.unwrap();
    store
        .apply_commit(commit, &rights_opts())
        .await
        .expect("anyone may create a parentless DID drive")
        .resource_new
        .unwrap()
        .get_subject()
        .to_string()
}

mod basic;
mod did;
mod property;
mod rights;
mod validation;
