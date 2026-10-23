//! Bringing one agent's work along when the person signs in as another.
//!
//! A person can end up holding two identities (two secrets): one made in the
//! web app, one in a phone app. When this device holds identity **A** and the
//! person signs in as **B**, A's drives are made B's too:
//!
//! 1. A, still able to sign, adds B to `write` on every drive A can write.
//! 2. Those drives are added to the `drives` list on B's private drive (B's
//!    "home"), signed by B.
//!
//! Nothing is copied or re-signed. A's commits stay A's. See
//! `planning/identity-bring-along.md`.
//!
//! Both agents need their private key: one commit is signed by each. Callers
//! have both secrets at sign-in time (A is the agent that was signed in, B is
//! the secret just entered). Archiving A's secret is the caller's job.

use super::Db;
use crate::{
    agents::{Agent, ForAgent},
    errors::AtomicResult,
    storelike::Query,
    urls, Storelike, Value,
};

/// What [`Db::bring_along`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct BringAlong {
    /// The drives that now belong to B: B was added to their `write`, and/or
    /// they were added to B's drive list. Empty when there was nothing to do,
    /// which includes every run after the first.
    pub drives: Vec<String>,
}

impl Db {
    /// The drive subjects `agent` lists: the legacy `Agent.drives` property and
    /// the `drives` list on its private drive. The private drive itself is not
    /// part of the result. Stored state only, nothing is fetched.
    async fn listed_drives_of(&self, agent: &Agent) -> AtomicResult<(Vec<String>, String)> {
        let private_key = agent
            .private_key
            .as_ref()
            .ok_or("Bringing work along needs the agent's private key")?;
        let home = crate::genesis::GenesisCert::private_drive_subject(private_key)?;

        let mut listed: Vec<String> = Vec::new();
        let mut add = |value: Option<&Value>| {
            if let Some(Value::ResourceArray(arr)) = value {
                for s in arr {
                    let s = s.to_string();
                    if s != home && !listed.contains(&s) {
                        listed.push(s);
                    }
                }
            }
        };
        if let Ok(resource) = self.get_resource_shallow(&agent.subject) {
            add(resource.get(urls::DRIVES).ok());
        }
        if let Ok(resource) = self.get_resource_shallow(&home.as_str().into()) {
            add(resource.get(urls::DRIVES).ok());
        }
        Ok((listed, home))
    }

    /// Does the drive hold anything besides its own properties?
    async fn drive_has_children(&self, drive: &str) -> bool {
        let mut query = Query::new_prop_val(urls::PARENT, drive);
        query.limit = Some(1);
        query.for_agent = ForAgent::Sudo;
        self.query(&query)
            .await
            .map(|r| r.count > 0)
            .unwrap_or(false)
    }

    /// Is `agent` named in the drive's `write`?
    ///
    /// Deliberately not `hierarchy::check_write`: that grants the store's
    /// default agent root access to everything, and during a sign-in the
    /// default agent is one of the two agents involved, so it would call
    /// every drive writable for it. A drive is a root (no parent to inherit
    /// from), so its own `write` list is the whole answer. A public write
    /// grant does not count: it is nobody's work in particular.
    fn names_writer(&self, agent: &Agent, drive: &crate::Resource) -> bool {
        let Ok(Value::ResourceArray(write)) = drive.get(urls::WRITE) else {
            return false;
        };
        let wanted = self.normalize_subject(&agent.subject);
        write.iter().any(|w| {
            let migrated = crate::agents::migrate_legacy_agent_subject(&w.to_string());
            self.normalize_subject(&migrated.as_str().into()) == wanted
        })
    }

    /// The drives of `from` that can come along: the ones it lists, plus its
    /// private drive when that holds something beyond its drive list; only the
    /// ones `from` can write and that are stored on this device.
    async fn bringable_drives(&self, from: &Agent) -> AtomicResult<Vec<crate::Resource>> {
        let (listed, home) = self.listed_drives_of(from).await?;
        let mut candidates = listed;
        if self.drive_has_children(&home).await {
            candidates.push(home);
        }
        let mut out = Vec::new();
        for subject in candidates {
            let Ok(resource) = self.get_resource_shallow(&subject.as_str().into()) else {
                continue;
            };
            if self.names_writer(from, &resource) {
                out.push(resource);
            }
        }
        Ok(out)
    }

    /// Would [`Self::bring_along`] have something to bring for `from`? True when
    /// `from` can write at least one drive other than an empty private drive.
    /// Asked before signing in as someone else, to decide whether to ask or
    /// report anything. It does not look at the target: after a successful run
    /// it still answers true, while `bring_along` brings nothing.
    pub async fn has_work_to_bring(&self, from: &Agent) -> AtomicResult<bool> {
        Ok(!self.bringable_drives(from).await?.is_empty())
    }

    /// Make `from`'s work `to`'s too: `from` adds `to` to `write` on each drive
    /// it can write, then those drives are listed on `to`'s private drive,
    /// signed by `to`. Both writes are applied locally and sync like any edit.
    ///
    /// Idempotent: a drive `to` already writes and lists is skipped, so a
    /// second run (or one after a crash halfway) returns an empty
    /// [`BringAlong`] and errors on nothing. Does not touch the default agent.
    /// A no-op when `from` and `to` are the same agent.
    pub async fn bring_along(&self, from: &Agent, to: &Agent) -> AtomicResult<BringAlong> {
        let mut result = BringAlong::default();
        if from.subject == to.subject {
            return Ok(result);
        }
        let drives = self.bringable_drives(from).await?;
        if drives.is_empty() {
            return Ok(result);
        }
        let to_private_key = to
            .private_key
            .as_ref()
            .ok_or("Bringing work along needs the target agent's private key")?;
        let to_home = crate::genesis::GenesisCert::private_drive_subject(to_private_key)?;
        let to_subject = to.subject.to_string();

        // B's home may not be on this device yet (a fresh sign-in). The
        // derived genesis is the same everywhere, so it merges on sync.
        if !self.has_stored_resource(&to_home.as_str().into()) {
            self.ensure_private_drive_for(to).await?;
        }

        for drive in drives {
            let drive_subject = drive.get_subject().to_string();
            if drive_subject == to_home {
                continue;
            }
            let mut changed = false;

            // 1. A adds B to `write`.
            let mut write: Vec<crate::values::SubResource> = match drive.get(urls::WRITE) {
                Ok(Value::ResourceArray(arr)) => arr.clone(),
                _ => Vec::new(),
            };
            if !self.names_writer(to, &drive) {
                write.push(to_subject.clone().into());
                let mut editable = self.get_resource(&drive_subject.as_str().into()).await?;
                editable.set_unsafe(urls::WRITE.into(), Value::ResourceArray(write))?;
                editable.save_as(from, self).await?;
                changed = true;
            }

            // 2. B lists the drive.
            let mut home = self.get_resource(&to_home.as_str().into()).await?;
            let mut listed: Vec<crate::values::SubResource> = match home.get(urls::DRIVES) {
                Ok(Value::ResourceArray(arr)) => arr.clone(),
                _ => Vec::new(),
            };
            if !listed.iter().any(|d| d.to_string() == drive_subject) {
                listed.push(drive_subject.clone().into());
                home.set_unsafe(urls::DRIVES.into(), Value::ResourceArray(listed))?;
                home.save_as(to, self).await?;
                changed = true;
            }

            if changed {
                result.drives.push(drive_subject);
            }
        }
        Ok(result)
    }
}
