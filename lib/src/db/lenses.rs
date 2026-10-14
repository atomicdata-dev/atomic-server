//! Lens index registration and backfill for [`Db`].

use super::*;

impl Db {
    /// The active lenses. Cheap: clones an `Arc`.
    pub fn lenses(&self) -> Arc<crate::lens::LensIndex> {
        self.lenses
            .read()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }

    pub(super) fn update_lenses(&self, change: impl FnOnce(&mut crate::lens::LensIndex)) {
        if let Ok(mut guard) = self.lenses.write() {
            let mut next = (**guard).clone();
            change(&mut next);
            *guard = Arc::new(next);
        }
    }

    /// Rebuild the lens index from the stored Lens resources.
    pub(super) async fn load_lenses(&self) {
        let class = Value::AtomicUrl(urls::LENS.into());
        let subjects: Vec<Subject> = find_in_prop_val_sub_index(self, urls::IS_A, Some(&class))
            .flatten()
            .map(|atom| atom.subject)
            .collect();
        for subject in subjects {
            if let Ok(lens) = Storelike::get_resource(self, &subject).await {
                self.register_lens(&lens).await;
            }
        }
    }

    /// Make a stored Lens active. Returns the entry when it is. A lens whose
    /// target property is not in the store yet is remembered and retried when
    /// a Property is created ([`Self::retry_pending_lenses`]). Never fails a
    /// commit: an inactive lens is just not applied.
    pub async fn register_lens(&self, lens: &Resource) -> Option<crate::lens::LensEntry> {
        let subject = crate::identifiers::canonicalize_scheme(&lens.get_subject().pure_id());
        match crate::lens::build_entry(self, lens).await {
            Ok(entry) => {
                if let Ok(mut pending) = self.pending_lenses.write() {
                    pending.retain(|p| p != &subject);
                }
                self.update_lenses(|index| index.insert(entry.clone()));
                Some(entry)
            }
            Err(e) => {
                tracing::debug!(lens = %subject, error = %e, "Lens is not active");
                if let Ok(mut pending) = self.pending_lenses.write() {
                    if !pending.contains(&subject) {
                        pending.push(subject);
                    }
                }
                None
            }
        }
    }

    /// Call after a resource landed in the store. A Lens becomes active (and
    /// its resources are backfilled); a new Property may let a waiting Lens
    /// become active.
    pub(crate) async fn note_lens_related(&self, resource: &Resource) {
        let subject = resource.get_subject().pure_id();
        if crate::identifiers::is_lens_id(&subject) {
            if let Some(entry) = self.register_lens(resource).await {
                self.backfill_lens(&entry).await;
            }
        } else if crate::identifiers::is_prop_id(&subject)
            && self
                .pending_lenses
                .read()
                .map(|p| !p.is_empty())
                .unwrap_or(false)
        {
            self.retry_pending_lenses().await;
        }
    }

    /// Stop applying a lens (it was destroyed).
    pub fn unregister_lens(&self, subject: &str) {
        let subject = crate::identifiers::canonicalize_scheme(subject);
        if let Ok(mut pending) = self.pending_lenses.write() {
            pending.retain(|p| p != &subject);
        }
        self.update_lenses(|index| index.remove(&subject));
    }

    /// Try the lenses that were waiting for a property, now that one arrived.
    pub(super) async fn retry_pending_lenses(&self) {
        let pending: Vec<String> = self
            .pending_lenses
            .read()
            .map(|p| p.clone())
            .unwrap_or_default();
        for subject in pending {
            let Ok(lens) = Storelike::get_resource(self, &subject.as_str().into()).await else {
                continue;
            };
            if let Some(entry) = self.register_lens(&lens).await {
                self.backfill_lens(&entry).await;
            }
        }
    }

    /// Re-materialize the stored resources that hold a property of this lens,
    /// so the value index and search see the derived values. Reads already
    /// apply lenses; this only brings the stored projection and the indexes
    /// in line. Derived values are not commits: nothing is broadcast.
    pub async fn backfill_lens(&self, entry: &crate::lens::LensEntry) {
        let mut subjects: Vec<Subject> = Vec::new();
        let mut seen = HashSet::new();
        for prop in [&entry.from, &entry.to] {
            for atom in find_in_prop_val_sub_index(self, prop, None).flatten() {
                if seen.insert(atom.subject.to_string()) {
                    subjects.push(atom.subject);
                }
            }
        }
        for subject in subjects {
            let _guard = self.subject_locks.lock(&subject.pure_id()).await;
            let Ok(resource) = Storelike::get_resource(self, &subject).await else {
                continue;
            };
            let snapshot = self.get_loro_snapshot_bytes(&subject.pure_id());
            let mut transaction = Transaction::new();
            let built = self
                .build_projection_tx(&resource, false, true, true, snapshot, &mut transaction)
                .await;
            match built.and_then(|()| self.apply_transaction(&mut transaction)) {
                Ok(()) => {}
                Err(e) => {
                    tracing::warn!(%subject, error = %e, "Could not backfill lens");
                }
            }
        }
    }
}
