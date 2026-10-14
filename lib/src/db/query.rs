//! Query planning, watched queries and query execution for [`Db`].

use super::*;

impl Db {
    pub(super) fn get_index_iterator_for_query(&self, q: &Query) -> IndexIterator {
        match (&q.property, q.value.as_ref()) {
            (Some(prop), val) => find_in_prop_val_sub_index(self, prop, val),
            (None, None) => self.all_index_atoms(q.include_external),
            (None, Some(val)) => find_in_val_prop_sub_index(self, val, None),
        }
    }

    /// Bounded cardinality estimate for a `(property, value?)` prefix in the
    /// PropValSub index. Scans at most `cap` entries — enough to rank
    /// constraints by selectivity without paying for exact counts.
    pub(super) fn estimate_prop_val_count(
        &self,
        prop: &str,
        val: Option<&Value>,
        cap: usize,
    ) -> usize {
        let mut prefix: Vec<u8> = [
            &query_index::property_key_part(prop)[..],
            &[query_index::SEPARATION_BIT],
        ]
        .concat();
        if let Some(value) = val {
            prefix.extend(value.to_sortable_string().as_bytes());
            prefix.extend([query_index::SEPARATION_BIT]);
        }
        self.kv
            .scan_prefix(Tree::PropValSub, &prefix)
            .take(cap)
            .count()
    }

    /// Picks the candidate iterator for building a [QueryFilter]'s member
    /// index: the most selective property-bearing constraint by a scan-capped
    /// cardinality estimate. Every candidate is verified against the full
    /// filter afterwards, so any constraint's index entries are a valid
    /// starting set — the estimate only decides how few resources get row-
    /// checked. Constraints with non-equality operators can't be point-
    /// scanned; they contribute a whole-property scan as their candidate set.
    ///
    /// Also returns the position of the chosen constraint in
    /// `q_filter.filters`, so the build can cross-check its result against
    /// the constraints it did not scan (see `cross_check_first_build`).
    pub(super) fn plan_candidate_iterator(
        &self,
        q: &Query,
        q_filter: &QueryFilter,
    ) -> (IndexIterator, Option<usize>) {
        let mut best: Option<(usize, usize, &crate::storelike::PropVal)> = None;
        for (position, constraint) in q_filter.filters.iter().enumerate() {
            let Some(prop) = &constraint.property else {
                continue;
            };
            let scan_val = match (constraint.operator, &constraint.value) {
                (crate::storelike::FilterOperator::Equal, Some(v)) => Some(v),
                _ => None,
            };
            let estimate = self.estimate_prop_val_count(prop, scan_val, PLANNER_SCAN_CAP);
            if best.is_none_or(|(current, _, _)| estimate < current) {
                best = Some((estimate, position, constraint));
            }
        }

        match best {
            Some((_, position, constraint)) => {
                let prop = constraint
                    .property
                    .as_ref()
                    .expect("planner only ranks property-bearing constraints");
                let val = match constraint.operator {
                    crate::storelike::FilterOperator::Equal => constraint.value.as_ref(),
                    _ => None,
                };
                (find_in_prop_val_sub_index(self, prop, val), Some(position))
            }
            // No property-bearing constraint (value-only filters): fall back
            // to the query's own iterator (value index or full scan).
            None => (self.get_index_iterator_for_query(q), None),
        }
    }

    /// The members a first build missed, found by walking the small
    /// equality constraints the planner did *not* scan.
    ///
    /// The planner trusts that any one constraint's `PropValSub` entries are a
    /// superset of the members. That held only as long as every encoding of a
    /// value produced the same index key; when one did not, the cheapest
    /// constraint had fewer candidates than rows, the build filed a partial
    /// member list, and the filter was watched — so the partial list was
    /// trusted for good and every count it produced looked plausible
    /// (planning/silent-failures.md). This walks each other equality
    /// constraint whose entries fit under the planner's scan cap (so at most
    /// `PLANNER_SCAN_CAP` extra key reads per constraint, once per first
    /// build), and returns every matching resource that is not in `built`.
    /// Constraints beyond the cap are not walked here; the full comparison is
    /// [`Db::check_query_index`].
    pub(super) fn cross_check_first_build(
        &self,
        q_filter: &QueryFilter,
        chosen: Option<usize>,
        built: &HashSet<String>,
    ) -> Vec<Resource> {
        let mut missing = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        for (position, constraint) in q_filter.filters.iter().enumerate() {
            if Some(position) == chosen {
                continue;
            }
            let (Some(prop), Some(val)) = (&constraint.property, &constraint.value) else {
                continue;
            };
            if constraint.operator != crate::storelike::FilterOperator::Equal {
                continue;
            }
            if self.estimate_prop_val_count(prop, Some(val), PLANNER_SCAN_CAP) >= PLANNER_SCAN_CAP {
                continue;
            }
            for atom in find_in_prop_val_sub_index(self, prop, Some(val)).flatten() {
                let subject = atom.subject.as_str().to_string();
                if built.contains(&subject) || !seen.insert(subject) {
                    continue;
                }
                let Ok(resource) = self.get_resource_shallow(&atom.subject) else {
                    continue;
                };
                if query_index::resource_matches_filter(&resource, q_filter)
                    && self.filter_accepts_resource_drive(q_filter, &resource)
                {
                    missing.push(resource);
                }
            }
        }
        missing
    }

    /// Compare a query's member index with the resources it claims to index.
    ///
    /// Walks every stored resource, applies the query's filter to it the way
    /// the index maintenance does (`resource_matches_filter` plus the drive
    /// check), and reports which matching subjects the index lacks and which
    /// indexed subjects no longer match. Reading a row set out of the index
    /// is fast because it trusts the index; this is the check that trust is
    /// deserved. It is a full scan, so it is for tests, diagnostics and
    /// one-off repairs, not for the query path.
    pub fn check_query_index(&self, q: &Query) -> AtomicResult<QueryIndexReport> {
        let q_filter = QueryFilter::try_from_query(q)?;
        let id = query_index::query_id(&q_filter)?;
        // Index keys hold the subject as the writer spelled it; rows come
        // back under the store's normalized spelling. Compare one form.
        let base_domain = self.get_base_domain();
        let canonical = |s: &str| Subject::from_raw(s, base_domain.as_deref()).pure_id();

        let mut indexed: HashSet<String> = HashSet::new();
        for kv in self.kv.scan_prefix(Tree::QueryMembers, &id) {
            let (key, _) = kv?;
            let (_id, _sort, subject) = query_index::parse_members_key(&key)?;
            indexed.insert(canonical(subject));
        }

        let mut expected: HashSet<String> = HashSet::new();
        for resource in self.all_resources(true) {
            if query_index::resource_matches_filter(&resource, &q_filter)
                && self.filter_accepts_resource_drive(&q_filter, &resource)
            {
                expected.insert(canonical(resource.get_subject().as_str()));
            }
        }

        let mut missing: Vec<String> = expected.difference(&indexed).cloned().collect();
        let mut stale: Vec<String> = indexed.difference(&expected).cloned().collect();
        missing.sort();
        stale.sort();
        Ok(QueryIndexReport {
            watched: q_filter.is_watched(self),
            filter: q_filter,
            indexed: indexed.len(),
            expected: expected.len(),
            missing,
            stale,
        })
    }

    /// Register a filter to be watched. Persists to `Tree::WatchedQueries`
    /// (idempotent — same filter encodes to the same bytes) and pushes into
    /// the in-memory `watched_queries_by_drive` map. The KV `contains_key`
    /// short-circuit keeps the in-memory Vec from growing on duplicate
    /// `watch()` calls (e.g. when a client reconnects and re-watches a
    /// filter that's already persisted).
    pub(crate) fn register_watched_query(
        &self,
        filter: query_index::QueryFilter,
    ) -> AtomicResult<()> {
        // Before the persisted short-circuit: a client re-watching after the
        // queried subject arrived here gets its drive root resolved now.
        self.cache_filter_drive_root(&filter.drive);
        let filter_bytes = filter.encode()?;
        // Skip if already persisted — avoids growing the in-memory Vec on
        // re-watches. The KV is authoritative for "what filters exist"; the
        // in-memory map is just a decoded mirror.
        if self
            .kv
            .contains_key(crate::db::trees::Tree::WatchedQueries, &filter_bytes)
            .unwrap_or(false)
        {
            return Ok(());
        }
        self.kv
            .insert(crate::db::trees::Tree::WatchedQueries, &filter_bytes, b"")?;
        let drive_key = filter.drive.as_str().to_string();
        if let Ok(mut map) = self.watched_queries_by_drive.write() {
            map.entry(drive_key).or_default().insert(Arc::new(filter));
        }
        Ok(())
    }

    /// Rebuild the in-memory watched-queries map from `Tree::WatchedQueries`.
    /// Called once at Db open (after KV/migrations are ready) so the map is
    /// authoritative on first commit. Subsequent `register_watched_query`
    /// calls keep both stores in sync.
    pub(crate) fn populate_watched_queries_cache(&self) -> AtomicResult<()> {
        let mut new_map: HashMap<String, DriveFilters> = HashMap::new();
        for entry in self.kv.iter_tree(crate::db::trees::Tree::WatchedQueries) {
            let (k, _v) = match entry {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::warn!("populate_watched_queries_cache: skipping bad entry: {e}");
                    continue;
                }
            };
            let qf = match query_index::QueryFilter::from_bytes(&k) {
                Ok(qf) => qf,
                Err(e) => {
                    tracing::warn!(
                        "populate_watched_queries_cache: skipping undecodable entry ({} bytes): {e}",
                        k.len()
                    );
                    continue;
                }
            };
            self.cache_filter_drive_root(&qf.drive);
            let drive_key = qf.drive.as_str().to_string();
            new_map.entry(drive_key).or_default().insert(Arc::new(qf));
        }
        if let Ok(mut map) = self.watched_queries_by_drive.write() {
            *map = new_map;
        }
        Ok(())
    }

    /// Resolve the drive root a filter's `drive` subject lives in and remember
    /// it. A subject that is not stored here (an `https://host` prefix, a DID
    /// that has not arrived yet) records `None`; the next `watch()` retries.
    pub(super) fn cache_filter_drive_root(&self, drive: &Subject) {
        let key = drive.as_str().to_string();
        let known = self
            .filter_drive_roots
            .read()
            .ok()
            .and_then(|m| m.get(&key).cloned());
        if matches!(known, Some(Some(_))) {
            return;
        }
        let root = self
            .get_resource_shallow(drive)
            .ok()
            .and_then(|resource| resource.get_drive());
        if let Ok(mut map) = self.filter_drive_roots.write() {
            map.insert(key, root);
        }
    }

    /// The drive root a watched filter was resolved to, if known.
    pub(crate) fn filter_drive_root(&self, filter: &query_index::QueryFilter) -> Option<Subject> {
        self.filter_drive_roots
            .read()
            .ok()
            .and_then(|m| m.get(filter.drive.as_str()).cloned().flatten())
    }

    /// Whether a resource may be a member of `filter` as far as drive scope
    /// goes. HTTP and `internal:` subjects are already routed to their drive
    /// by prefix. A DID subject has no prefix, so the only evidence is its
    /// `drive` stamp: when both it and the filter's root are known, they
    /// must agree. A row without a stamp, or a filter whose root could not be
    /// resolved, is not excluded — a missing stamp is not proof of a leak,
    /// and read rights still apply at query time.
    pub(crate) fn filter_accepts_resource_drive(
        &self,
        filter: &query_index::QueryFilter,
        resource: &Resource,
    ) -> bool {
        if !crate::identifiers::is_atomic_identifier(resource.get_subject().as_str()) {
            return true;
        }
        match (resource.get_drive(), self.filter_drive_root(filter)) {
            (Some(stamp), Some(root)) => stamp.pure_id() == root.pure_id(),
            _ => true,
        }
    }

    /// The watched filters a changed atom in `drive_key` with `property` must
    /// be checked against: the drive's filters that reference that property
    /// (constraint or `sort_by`) plus its value-only filters. Returns
    /// cheap-cloned `Arc`s; iterating doesn't hold the map lock.
    pub(crate) fn watched_queries_for_atom(
        &self,
        drive_key: &str,
        property: &str,
    ) -> Vec<Arc<query_index::QueryFilter>> {
        self.watched_queries_by_drive
            .read()
            .ok()
            .and_then(|m| m.get(drive_key).map(|df| df.for_property(property)))
            .unwrap_or_default()
    }

    /// Property-routed filters across every drive. Used for DID-subject atoms
    /// whose drive prefix can't be derived (their `drive_prefix_from_subject`
    /// returns the subject itself, which won't match an HTTP-drive filter's
    /// bucket).
    pub(crate) fn all_watched_queries_for_property(
        &self,
        property: &str,
    ) -> Vec<Arc<query_index::QueryFilter>> {
        self.watched_queries_by_drive
            .read()
            .map(|m| {
                m.values()
                    .flat_map(|df| df.for_property(property))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Resolve one query-index hit against the materialized row and the
    /// requesting agent's rights, without decoding any Loro snapshot.
    ///
    /// Returns `None` when the member must be hidden (auth-denied or
    /// unresolvable), `Some(None)` when it's included subjects-only, and
    /// `Some(Some(resource))` when the query asked for nested bodies.
    ///
    /// Bodies are built from the row plus the resource's *raw* snapshot bytes
    /// attached as `loroUpdate` — byte-for-byte what the old full-decode path
    /// serialized, since the row **is** the snapshot's materialization (see
    /// planning/index-performance.md, finding 3). Subjects without a row
    /// (endpoints, never-stored externals, defensive invariant breaks) fall
    /// back to the full `get_resource_extended` path.
    pub(crate) async fn resolve_query_member(
        &self,
        subject: &Subject,
        q: &Query,
        rights_cache: &std::sync::Mutex<RightsCache>,
    ) -> Option<Option<Resource>> {
        let mut resource = match self.get_resource_shallow(subject) {
            Ok(resource) => resource,
            Err(_) => {
                // No materialized row — take the slow, complete path.
                return match self
                    .get_resource_extended(subject, true, &q.for_agent)
                    .await
                {
                    Ok(response) => {
                        if q.include_nested {
                            Some(Some(response.to_single()))
                        } else {
                            Some(None)
                        }
                    }
                    Err(_) => None,
                };
            }
        };

        if q.for_agent != ForAgent::Sudo
            && crate::hierarchy::check_rights_cached(
                self,
                &resource,
                &q.for_agent,
                crate::hierarchy::Right::Read,
                Some(rights_cache),
            )
            .await
            .is_err()
        {
            return None;
        }

        if !q.include_nested {
            return Some(None);
        }

        // Commit rows keep their `loroUpdate` payload in the row itself;
        // everything else gets the stored snapshot attached undecoded.
        if !resource.get_subject().is_commit_did() {
            let pure_id = resource.get_subject().pure_id();
            if let Some(snapshot) = self.get_loro_snapshot_bytes(&pure_id) {
                resource
                    .insert_propval_raw(crate::urls::LORO_UPDATE.into(), Value::LoroDoc(snapshot));
            }
        }

        // Same `incomplete` marking as `get_resource_extended(skip_dynamic)`:
        // tells clients the member may have dynamic properties that a direct
        // GET would compute.
        let extenders = match self.class_extenders.read() {
            Ok(guard) => guard.clone(),
            Err(_) => return None,
        };
        // An extender that cannot decide whether it applies is skipped, not
        // treated as a reason to hide the row. The row exists and the reader
        // may see it; the only thing at stake here is the `incomplete`
        // marker. Returning `None` from here used to drop every row whose
        // `isA` the built-in collection extender could not parse, silently,
        // from every collection listing and count (planning/silent-failures.md,
        // "A query index silently disagreed with the data it indexes").
        for extender in extenders.iter() {
            if !extender.can_extend(&resource) {
                continue;
            }
            match extender.resource_has_extender(&resource) {
                Ok(true) => {}
                Ok(false) => continue,
                Err(e) => {
                    tracing::warn!(
                        subject = %resource.get_subject(),
                        extender = extender.id.as_deref().unwrap_or("<unnamed>"),
                        "query member listed without its extender check: {e}"
                    );
                    continue;
                }
            }
            match extender.check_scope(&resource, self, None).await {
                Ok((true, _)) => {
                    resource
                        .insert_propval_raw(crate::urls::INCOMPLETE.into(), Value::Boolean(true));
                    break;
                }
                Ok((false, _)) => continue,
                Err(e) => {
                    tracing::warn!(
                        subject = %resource.get_subject(),
                        extender = extender.id.as_deref().unwrap_or("<unnamed>"),
                        "query member listed without its extender scope check: {e}"
                    );
                    continue;
                }
            }
        }

        Some(Some(resource))
    }

    pub(super) async fn query_basic(&self, q: &Query) -> AtomicResult<QueryResult> {
        let mut subjects: Vec<Subject> = vec![];
        let mut resources: Vec<Resource> = vec![];
        let mut total_count = 0;
        let mut seen = HashSet::new();
        let rights_cache = std::sync::Mutex::new(RightsCache::default());
        let base_domain = self.get_base_domain();

        let atoms = self.get_index_iterator_for_query(q);

        for atom_res in atoms {
            let atom = atom_res?;
            if !q.include_external && !atom.subject.is_local() {
                continue;
            }
            let identity = atom.subject.pure_id();
            if !seen.insert(identity.clone()) {
                continue;
            }
            let subject = Subject::from_raw(&identity, base_domain.as_deref());
            let index = seen.len() - 1;

            total_count += 1;

            if q.offset > index {
                continue;
            }

            // Denied members do not grow `subjects`, so we keep resolving
            // until the page is full of *authorized* hits — a private streak
            // must not hide a later readable row.
            if q.limit.is_none() || subjects.len() < q.limit.unwrap() {
                // Sudo without nested bodies needs no per-member work at all.
                if q.for_agent == ForAgent::Sudo && !q.include_nested {
                    subjects.push(subject);
                    continue;
                }

                match self.resolve_query_member(&subject, q, &rights_cache).await {
                    Some(body) => {
                        subjects.push(subject);
                        if let Some(resource) = body {
                            resources.push(resource);
                        }
                    }
                    None => {
                        // The index has an entry for this subject but the
                        // requesting agent can't resolve it — auth-filtered,
                        // destroyed-with-stale-index, or otherwise invisible.
                        // Roll back the count bump so it doesn't outrun the
                        // returned subjects and produce a
                        // `totalMembers: N, members: []` drift. We only do
                        // this for in-page hits; entries past the limit stay
                        // counted blindly (issue #286).
                        total_count -= 1;
                    }
                }
            }
        }

        Ok(QueryResult {
            subjects,
            resources,
            aggregates: Vec::new(),
            count: total_count,
        })
    }

    /// Computes a query's aggregates over every row it matches.
    ///
    /// Re-runs the same filter unpaged and reads each row's value locally: the
    /// whole point is that the numbers travel instead of the rows. Values come
    /// from the materialized row (`get_resource_shallow`) — the same source the
    /// filters are matched against, so a total can never disagree with the set
    /// it claims to summarize.
    /// Every row the query matches, unpaged and in order.
    ///
    /// Subjects, not a count: these are the rows that actually resolved for this
    /// agent. `QueryResult::count` deliberately counts raw index hits (including
    /// unauthorized and stale-index entries, see issue #286), so a `count`
    /// aggregate can legitimately come out lower than `totalMembers` — it counts
    /// what the reader can see, which is the only number a sum over the same rows
    /// can agree with.
    ///
    /// Shared by the paging path and the aggregation pass, so a total can never
    /// summarize a different set than the rows on screen.
    pub(super) async fn matching_subjects(&self, q: &Query) -> AtomicResult<Vec<Subject>> {
        // The same query, unpaged. `sort_by` is kept so this takes the exact
        // same index path as the paged query — a different path could disagree
        // about which rows match.
        let scan = Query {
            property: q.property.clone(),
            value: q.value.clone(),
            filters: q.filters.clone(),
            limit: None,
            offset: 0,
            start_val: q.start_val.clone(),
            end_val: q.end_val.clone(),
            sort_by: q.sort_by.clone(),
            sort_desc: q.sort_desc,
            include_external: q.include_external,
            // Bodies are never needed here; values are read straight off the
            // local row.
            include_nested: false,
            for_agent: q.for_agent.clone(),
            drive: q.drive.clone(),
            aggregation: None,
            expression_filters: Vec::new(),
        };

        let subjects = if requires_query_index(&scan) {
            self.query_complex(&scan).await?.subjects
        } else {
            self.query_basic(&scan).await?.subjects
        };

        if q.expression_filters.is_empty() {
            return Ok(subjects);
        }

        Ok(subjects
            .into_iter()
            .filter(|subject| {
                let Ok(resource) = self.get_resource_shallow(subject) else {
                    // Nothing to evaluate against: a row we can't read can't be
                    // shown to satisfy a constraint.
                    return false;
                };

                q.expression_filters
                    .iter()
                    .all(|filter| filter.matches(&resource))
            })
            .collect())
    }

    /// The paged answer to a query with a constraint on a computed value.
    ///
    /// The index can't narrow by such a value, so the whole matching set is
    /// evaluated and *then* paged — which also makes `count` the number of rows
    /// that really matched, rather than the index's hit count.
    pub(super) async fn query_with_expression_filters(
        &self,
        q: &Query,
    ) -> AtomicResult<QueryResult> {
        let matching = self.matching_subjects(q).await?;
        let count = matching.len();

        let page: Vec<Subject> = matching
            .into_iter()
            .skip(q.offset)
            .take(q.limit.unwrap_or(usize::MAX))
            .collect();

        let resources = if q.include_nested {
            page.iter()
                .filter_map(|subject| self.get_resource_shallow(subject).ok())
                .collect()
        } else {
            Vec::new()
        };

        Ok(QueryResult {
            subjects: page,
            resources,
            aggregates: Vec::new(),
            count,
        })
    }

    pub(super) async fn compute_aggregation(
        &self,
        q: &Query,
        aggregation: &crate::aggregate::Aggregation,
    ) -> AtomicResult<Vec<crate::aggregate::AggregateOutcome>> {
        use crate::aggregate::{
            Accumulator, AggregateGroup, AggregateOutcome, DEFAULT_GROUP_LIMIT,
        };
        use std::collections::HashMap;

        let subjects = self.matching_subjects(q).await?;

        let mut totals: Vec<Accumulator> =
            vec![Accumulator::default(); aggregation.aggregates.len()];
        let mut per_group: Vec<HashMap<String, Accumulator>> =
            vec![HashMap::new(); aggregation.aggregates.len()];

        // One instant for the whole pass: a `daysSince` evaluated per row against
        // a moving clock could put two rows of the same day in different buckets.
        let now_ms = aggregation.now_ms.unwrap_or_else(crate::utils::now);

        for subject in subjects {
            let Ok(resource) = self.get_resource_shallow(&subject) else {
                continue;
            };

            let group = aggregation.group_by.as_ref().map(|grouping| {
                crate::aggregate::group_key(&resource, grouping).unwrap_or_default()
            });

            for (index, aggregate) in aggregation.aggregates.iter().enumerate() {
                // A computed value stands in for a stored one: `Some(None)` means
                // "this row has nothing to contribute", which is exactly how a
                // missing property already reads below.
                let computed = aggregate
                    .expression
                    .as_ref()
                    .map(|expression| expression.evaluate(&resource, now_ms));

                let stored = if computed.is_some() {
                    None
                } else {
                    aggregate
                        .property
                        .as_ref()
                        .map(|property| resource.get(property).ok())
                };

                // `count` counts rows: every matching row when it names no
                // property, only the rows that HAVE the property when it does
                // (so "count of Paid date" answers "how many are paid"). The
                // other functions need a number, and a row without one simply
                // doesn't contribute — it must not land in `count` either, or a
                // sum would report a denominator it never added up.
                let accumulate = |acc: &mut Accumulator| {
                    if aggregate.function == crate::aggregate::AggregateFunction::Count {
                        if !matches!(stored, Some(None)) && !matches!(computed, Some(None)) {
                            acc.count_row();
                        }

                        return;
                    }

                    let number = match &computed {
                        Some(value) => *value,
                        None => stored.flatten().and_then(crate::aggregate::value_as_number),
                    };

                    if let Some(number) = number {
                        acc.add(number);
                    }
                };

                accumulate(&mut totals[index]);

                if let Some(group) = &group {
                    accumulate(per_group[index].entry(group.clone()).or_default());
                }
            }
        }

        let mut outcomes = Vec::with_capacity(aggregation.aggregates.len());

        for (index, aggregate) in aggregation.aggregates.iter().enumerate() {
            let mut groups: Vec<AggregateGroup> = per_group[index]
                .iter()
                .map(|(key, acc)| AggregateGroup {
                    key: key.clone(),
                    value: acc.finish(aggregate.function),
                    count: acc.count,
                })
                .collect();

            // Day and month buckets read chronologically; anything else reads
            // biggest-first, which is what a breakdown is usually scanned for.
            match aggregation.group_by.as_ref().map(|g| g.granularity) {
                Some(crate::aggregate::GroupGranularity::Exact) | None => {
                    groups.sort_by(|a, b| {
                        b.value
                            .unwrap_or(f64::MIN)
                            .partial_cmp(&a.value.unwrap_or(f64::MIN))
                            .unwrap_or(std::cmp::Ordering::Equal)
                            .then_with(|| a.key.cmp(&b.key))
                    });
                }
                _ => groups.sort_by(|a, b| a.key.cmp(&b.key)),
            }

            let limit = aggregation
                .group_by
                .as_ref()
                .and_then(|g| g.limit)
                .unwrap_or(DEFAULT_GROUP_LIMIT);
            let groups_truncated = groups.len() > limit;
            groups.truncate(limit);

            outcomes.push(AggregateOutcome {
                id: aggregate.id.clone(),
                property: aggregate.property.clone(),
                function: aggregate.function,
                value: totals[index].finish(aggregate.function),
                count: totals[index].count,
                groups,
                groups_truncated,
            });
        }

        Ok(outcomes)
    }

    pub(super) async fn query_complex(&self, q: &Query) -> AtomicResult<QueryResult> {
        let q_filter = QueryFilter::try_from_query(q)?;
        let (mut subjects, mut resources, mut total_count) =
            query_sorted_indexed(self, q, &q_filter).await?;

        // Rebuild whenever the filter is not watched, whatever the index
        // currently holds.
        //
        // This used to also require `total_count == 0`. But "not watched" means
        // nothing has been maintaining this index — so however many entries it
        // happens to hold, they are not evidence that it is complete. A partial
        // one (a build that stopped short, entries left by a filter that was
        // once watched) is non-zero, so the rebuild never fired and the query
        // kept returning a number that was wrong and entirely plausible. Empty
        // was treated as suspicious and partial as authoritative, which is
        // backwards: partial is the state that looks fine.
        if !q_filter.is_watched(self) {
            info!(filter = ?q_filter, "Building query index");
            crate::metrics::query_indexed();
            let (atoms, chosen) = self.plan_candidate_iterator(q, &q_filter);
            q_filter.watch(self)?;

            let mut transaction = Transaction::new();

            // Drop whatever was there first, so the rebuild is authoritative
            // rather than merged into a set of unknown provenance — otherwise
            // a stale member for a resource that no longer matches survives a
            // rebuild that was supposed to correct exactly that.
            let id = query_index::query_id(&q_filter)?;
            for kv in self.kv.scan_prefix(Tree::QueryMembers, &id) {
                let (key, _) = kv?;
                transaction.push(Operation {
                    tree: Tree::QueryMembers,
                    method: Method::Delete,
                    key,
                    val: None,
                });
            }
            // Every candidate is verified against ALL of the filter's
            // constraints on its materialized row (no Loro decode), so the
            // member index only holds true AND-matches — including for
            // non-equality operators, whose candidate sets are supersets.
            let mut built: HashSet<String> = HashSet::new();
            for atom in atoms.flatten() {
                let Ok(resource) = self.get_resource_shallow(&atom.subject) else {
                    // No row to verify against (external/never-stored) —
                    // don't index what we can't confirm.
                    continue;
                };
                if !query_index::resource_matches_filter(&resource, &q_filter)
                    || !self.filter_accepts_resource_drive(&q_filter, &resource)
                {
                    continue;
                }
                let prop = query_index::index_key_property(&q_filter, &atom);
                let sort_key = query_index::sort_key_for(&resource, prop);
                update_indexed_member(
                    &q_filter,
                    atom.subject.as_str(),
                    &sort_key,
                    false,
                    &mut transaction,
                )?;
                built.insert(atom.subject.as_str().to_string());
            }
            // A member the scanned constraint's index does not know about is
            // a member the filter would have listed forever without. Say so,
            // and file it.
            let missed = self.cross_check_first_build(&q_filter, chosen, &built);
            if !missed.is_empty() {
                let subjects: Vec<String> = missed
                    .iter()
                    .map(|r| r.get_subject().as_str().to_string())
                    .collect();
                tracing::warn!(
                    filter = ?q_filter,
                    missing = ?subjects,
                    "query index build missed members its candidate index did not list; added"
                );
                for resource in &missed {
                    // The cross-check only walks property-bearing
                    // constraints, so the filter always has a key property.
                    let prop = query_index::filter_key_property(&q_filter)
                        .cloned()
                        .unwrap_or_default();
                    let sort_key = query_index::sort_key_for(resource, &prop);
                    update_indexed_member(
                        &q_filter,
                        resource.get_subject().as_str(),
                        &sort_key,
                        false,
                        &mut transaction,
                    )?;
                }
            }
            self.apply_transaction(&mut transaction)?;

            // Query through the new indexes.
            (subjects, resources, total_count) = query_sorted_indexed(self, q, &q_filter).await?;
        }

        Ok(QueryResult {
            subjects,
            resources,
            aggregates: Vec::new(),
            count: total_count,
        })
    }
}
