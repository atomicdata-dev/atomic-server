//! Plugin metadata, secrets, app agents, schedules and triggers for [`Db`].

use super::*;

impl Db {
    pub fn get_plugin_meta(&self, key: &PluginMetaKey) -> AtomicResult<Option<PluginMeta>> {
        let Some(plugin_meta_bin) = self.kv.get(Tree::PluginMeta, &key.encode()?)? else {
            return Ok(None);
        };
        let plugin_meta = PluginMeta::from_bytes(&plugin_meta_bin)?;

        Ok(Some(plugin_meta))
    }

    pub fn set_plugin_meta(
        &self,
        key: &PluginMetaKey,
        plugin_meta: &PluginMeta,
    ) -> AtomicResult<()> {
        self.kv
            .insert(Tree::PluginMeta, &key.encode()?, &plugin_meta.encode()?)?;
        Ok(())
    }

    pub fn delete_plugin_meta(&self, key: &PluginMetaKey) -> AtomicResult<()> {
        self.kv.remove(Tree::PluginMeta, &key.encode()?)?;
        Ok(())
    }

    pub fn set_plugin_secret(
        &self,
        key: &PluginSecretKey,
        secret: &PluginSecret,
    ) -> AtomicResult<()> {
        PluginSecretKey::validate_name(&key.name)?;

        let mut stored = secret.clone();
        stored.value = self.wrap_secret(&secret.value)?;

        self.kv
            .insert(Tree::PluginSecret, &key.encode()?, &stored.encode()?)?;
        Ok(())
    }

    /// Runs `f` with the secret's value if it exists and allows `origin`.
    ///
    /// Records the use before returning, so "used 0 times in 90 days" is a
    /// question the UI can answer when someone is deciding whether to revoke.
    pub fn use_plugin_secret<T>(
        &self,
        key: &PluginSecretKey,
        origin: &str,
        at: i64,
        f: impl FnOnce(&str) -> T,
    ) -> AtomicResult<Option<T>> {
        let encoded_key = key.encode()?;

        let Some(bin) = self.kv.get(Tree::PluginSecret, &encoded_key)? else {
            return Ok(None);
        };

        let mut secret = PluginSecret::from_bytes(&bin)?;

        if !secret.allows(origin) {
            return Ok(None);
        }

        // References are one hop, same drive, and restricted by BOTH origin lists.
        // Rotating/revoking the connection affects every bound plugin immediately.
        let resolved = if let Some(target) = &secret.connection {
            if target.drive != key.drive {
                return Err("cross-drive credential reference".into());
            }
            let Some(bytes) = self.kv.get(Tree::PluginSecret, &target.encode()?)? else {
                return Ok(None);
            };
            let shared = PluginSecret::from_bytes(&bytes)?;
            if shared.connection.is_some() || !shared.allows(origin) {
                return Ok(None);
            }
            self.unwrap_secret(&shared.value)?
        } else {
            self.unwrap_secret(&secret.value)?
        };
        let out = f(&resolved);

        secret.record_use(at);
        self.kv
            .insert(Tree::PluginSecret, &encoded_key, &secret.encode()?)?;

        Ok(Some(out))
    }

    /// What may be said about a secret: never its value.
    pub fn get_plugin_secret_info(
        &self,
        key: &PluginSecretKey,
    ) -> AtomicResult<Option<PluginSecretInfo>> {
        let Some(bin) = self.kv.get(Tree::PluginSecret, &key.encode()?)? else {
            return Ok(None);
        };

        Ok(Some(PluginSecretInfo::of(
            &key.name,
            &PluginSecret::from_bytes(&bin)?,
        )))
    }

    /// Describes every secret a plugin has. Never their values.
    /// Records the key an app signs with, wrapped like every other secret.
    pub fn set_app_agent(&self, key: &AppAgentKey, agent: &AppAgent) -> AtomicResult<()> {
        let mut stored = agent.clone();
        stored.secret = self.wrap_secret(&agent.secret)?;
        stored.revoked = false;

        self.kv
            .insert(Tree::AppAgent, &key.encode()?, &stored.encode()?)?;
        Ok(())
    }

    /// Which DID an app writes as, without opening its key.
    pub fn get_app_agent_info(&self, key: &AppAgentKey) -> AtomicResult<Option<AppAgentInfo>> {
        Ok(match self.get_app_agent_state(key)? {
            AppAgentState::Active(info) => Some(info),
            _ => None,
        })
    }

    /// Read identity and lifecycle atomically, so revocation cannot look legacy
    /// between separate existence and status probes.
    pub fn get_app_agent_state(&self, key: &AppAgentKey) -> AtomicResult<AppAgentState> {
        let Some(bin) = self.kv.get(Tree::AppAgent, &key.encode()?)? else {
            return Ok(AppAgentState::Legacy);
        };
        let stored = AppAgent::from_bytes(&bin)?;
        Ok(if stored.revoked {
            AppAgentState::Revoked
        } else {
            AppAgentState::Active(stored.info())
        })
    }

    /// Runs `f` with the app's signing agent.
    ///
    /// A closure rather than a return value, for the same reason
    /// `use_plugin_secret` is one: nothing that hands a private key back to a
    /// caller can promise where it goes next.
    pub fn with_app_agent<T>(
        &self,
        key: &AppAgentKey,
        f: impl FnOnce(&crate::agents::Agent) -> T,
    ) -> AtomicResult<Option<T>> {
        let Some(bin) = self.kv.get(Tree::AppAgent, &key.encode()?)? else {
            return Ok(None);
        };

        let stored = AppAgent::from_bytes(&bin)?;
        if stored.revoked {
            return Ok(None);
        }
        let secret = self.unwrap_secret(&stored.secret)?;
        let agent = crate::agents::Agent::from_secret(&secret)?;

        Ok(Some(f(&agent)))
    }

    pub fn delete_app_agent(&self, key: &AppAgentKey) -> AtomicResult<()> {
        // Replace the encrypted key and state in one KV write. Keep no secret,
        // but remember that this installation must not use the legacy signer.
        let mut tombstone = AppAgent::new(String::new(), String::new(), 0);
        tombstone.revoked = true;
        self.kv
            .insert(Tree::AppAgent, &key.encode()?, &tombstone.encode()?)?;
        self.flush()?;
        Ok(())
    }

    pub fn app_agent_was_revoked(&self, key: &AppAgentKey) -> AtomicResult<bool> {
        Ok(matches!(
            self.get_app_agent_state(key)?,
            AppAgentState::Revoked
        ))
    }

    /// Secrets this node could not open with nobody present.
    ///
    /// A secret wrapped only by a user's credential has no unattended path —
    /// that is the trade for the server not being able to read it, not a gap.
    /// So arming a schedule or a trigger has to ask this first, while the
    /// person is there to be told, rather than discovering it at 3am and
    /// leaving an error nobody reads until the week is out.
    pub fn plugin_secrets_needing_a_person(
        &self,
        drive: &str,
        plugin: &str,
    ) -> AtomicResult<Vec<String>> {
        let prefix = PluginSecretKey::plugin_prefix(drive, plugin);
        let mut blocked = Vec::new();

        for entry in self.kv.scan_prefix(Tree::PluginSecret, &prefix) {
            let (key, value) = entry?;
            let stored = PluginSecret::from_bytes(&value)?;

            // Anything this node can already open is fine, wrapped or not:
            // a secret from before there was a key reads as plaintext.
            if self.unwrap_secret(&stored.value).is_err() {
                blocked.push(PluginSecretKey::name_from_key(&key)?);
            }
        }

        blocked.sort();

        Ok(blocked)
    }

    pub fn list_plugin_secrets(
        &self,
        drive: &str,
        plugin: &str,
    ) -> AtomicResult<Vec<PluginSecretInfo>> {
        let prefix = PluginSecretKey::plugin_prefix(drive, plugin);
        let mut out = Vec::new();

        for entry in self.kv.scan_prefix(Tree::PluginSecret, &prefix) {
            let (key, value) = entry?;
            let name = PluginSecretKey::name_from_key(&key)?;
            out.push(PluginSecretInfo::of(
                &name,
                &PluginSecret::from_bytes(&value)?,
            ));
        }

        out.sort_by(|a, b| a.name.cmp(&b.name));

        Ok(out)
    }

    pub fn delete_plugin_secret(&self, key: &PluginSecretKey) -> AtomicResult<()> {
        self.kv.remove(Tree::PluginSecret, &key.encode()?)?;
        Ok(())
    }

    pub fn set_plugin_schedule(
        &self,
        key: &PluginScheduleKey,
        schedule: &PluginSchedule,
    ) -> AtomicResult<()> {
        self.kv
            .insert(Tree::PluginSchedule, &key.encode()?, &schedule.encode()?)?;
        Ok(())
    }

    pub fn get_plugin_schedule(
        &self,
        key: &PluginScheduleKey,
    ) -> AtomicResult<Option<PluginSchedule>> {
        let Some(bin) = self.kv.get(Tree::PluginSchedule, &key.encode()?)? else {
            return Ok(None);
        };

        Ok(Some(PluginSchedule::from_bytes(&bin)?))
    }

    pub fn delete_plugin_schedule(&self, key: &PluginScheduleKey) -> AtomicResult<()> {
        self.kv.remove(Tree::PluginSchedule, &key.encode()?)?;
        Ok(())
    }

    /// Every schedule due at `now`.
    ///
    /// A whole-tree scan on purpose: one entry per scheduled plugin is a very
    /// small set, and an index keyed by due-time would have to be rewritten on
    /// every run for no gain at this size.
    pub fn due_plugin_schedules(
        &self,
        now: i64,
    ) -> AtomicResult<Vec<(PluginScheduleKey, PluginSchedule)>> {
        let mut due = Vec::new();

        for entry in self.kv.iter_tree(Tree::PluginSchedule) {
            let (key, value) = entry?;
            let schedule = PluginSchedule::from_bytes(&value)?;

            if schedule.is_due(now) {
                due.push((PluginScheduleKey::from_bytes(&key)?, schedule));
            }
        }

        Ok(due)
    }

    /// Exclusion scoped to this database and plugin operation namespace.
    pub async fn lock_plugin(&self, key: &str) -> tokio::sync::OwnedMutexGuard<()> {
        self.plugin_locks.lock(key).await
    }

    pub fn set_plugin_trigger(
        &self,
        key: &PluginTriggerKey,
        trigger: &PluginTrigger,
    ) -> AtomicResult<()> {
        // The store only fires membership events for queries it watches, so
        // registering the filter is part of storing the trigger rather than a
        // separate step someone can forget — a trigger that was never watched
        // would sit there looking armed and never fire.
        trigger.query.watch(self)?;

        self.kv
            .insert(Tree::PluginTrigger, &key.encode()?, &trigger.encode()?)?;
        Ok(())
    }

    pub fn get_plugin_trigger(
        &self,
        key: &PluginTriggerKey,
    ) -> AtomicResult<Option<PluginTrigger>> {
        let Some(bin) = self.kv.get(Tree::PluginTrigger, &key.encode()?)? else {
            return Ok(None);
        };

        Ok(Some(PluginTrigger::from_bytes(&bin)?))
    }

    pub fn delete_plugin_trigger(&self, key: &PluginTriggerKey) -> AtomicResult<()> {
        // The watched query stays. Another plugin — or a live `SUBSCRIBE_QUERY`
        // — may be watching the same filter, and unwatching one that is still
        // in use would silently stop delivering to it.
        self.kv.remove(Tree::PluginTrigger, &key.encode()?)?;
        Ok(())
    }

    /// Every trigger whose query is the one that just changed.
    ///
    /// A whole-tree scan, for the same reason `due_plugin_schedules` is one:
    /// there is one entry per triggered plugin, which is a very small set. An
    /// index keyed by query id would be another thing to keep in step for no
    /// gain at this size.
    pub fn plugin_triggers_for_query(
        &self,
        query_id: &[u8],
    ) -> AtomicResult<Vec<(PluginTriggerKey, PluginTrigger)>> {
        let mut found = Vec::new();

        for entry in self.kv.iter_tree(Tree::PluginTrigger) {
            let (key, value) = entry?;
            let trigger = PluginTrigger::from_bytes(&value)?;

            if crate::db::query_index::query_id(&trigger.query)?.as_slice() == query_id {
                found.push((PluginTriggerKey::from_bytes(&key)?, trigger));
            }
        }

        Ok(found)
    }

    /// Re-registers every stored trigger's query as watched.
    ///
    /// Called at startup: watched queries live in the store, but a trigger
    /// written by a version that did not watch — or one whose watch entry was
    /// lost — would otherwise never fire again, and nothing would say so.
    pub fn watch_plugin_trigger_queries(&self) -> AtomicResult<usize> {
        let mut watched = 0;

        for entry in self.kv.iter_tree(Tree::PluginTrigger) {
            let (_, value) = entry?;
            PluginTrigger::from_bytes(&value)?.query.watch(self)?;
            watched += 1;
        }

        Ok(watched)
    }
}
