//! KV-backed full-text search for [`crate::Db`].
//!
//! Indexes title (name / shortname / filename), description, and Loro document
//! body into the existing store trees so OPFS / redb / sled all get the same
//! engine. Queries AND tokens together, rank with BM25, and match a 1-edit
//! prefix-fuzzy bar (`avacado` finds `avocado`, `avo` typeahead works).
//! Property filters reuse the PropValSub index (exact `property:"value"`, AND).
//! Empty `q` + filters lists matching subjects (file picker, class selector).
//!
//! See `planning/local-search.md`.

use std::collections::{HashMap, HashSet};

use crate::{
    client::search::SearchOpts,
    db::{
        prop_val_sub_index::find_in_prop_val_sub_index,
        trees::{Method, Operation, Transaction, Tree},
        Db,
    },
    errors::AtomicResult,
    urls, Resource, Storelike, Subject, Value,
};

mod fuzzy;
mod keys;
mod tokenize;

pub use fuzzy::{min_prefix_levenshtein, one_edits};
pub use tokenize::tokenize;

use keys::{
    decode_doc, decode_tf, doc_id, encode_doc, encode_tf, posting_key, posting_prefix,
    posting_typeahead_prefix, search_trees, token_from_posting_key, trigram_key, trigram_prefix,
    DocId, DocToken, Field, SearchDoc, SEARCH_INDEX_VERSION_KEY,
};

/// A ranked hit from [`query`].
#[derive(Debug, Clone, PartialEq)]
pub struct SearchHit {
    pub subject: Subject,
    pub score: f32,
}

const BM25_K1: f32 = 1.2;
const BM25_B: f32 = 0.75;
/// Typical title+description length in tokens. Used as avgdl; per-doc `dl`
/// still length-normalizes. Good enough that we don't need a `SearchMeta` tree.
const AVGDL: f32 = 32.0;
const DEFAULT_LIMIT: u32 = 30;
const MAX_PARENT_WALK: usize = 64;
/// Generate the full 1-edit neighborhood (and prefix-scan it) up to this
/// token length. Longer tokens use trigrams + verify.
const EDIT_GEN_MAX_LEN: usize = 12;
const MIN_FUZZY_LEN: usize = 2;

/// Terms shorter than this are never looked up through trigrams: a query only
/// uses them for tokens longer than [`EDIT_GEN_MAX_LEN`], and a one-edit match
/// of such a token cannot be shorter than this.
const TRIGRAM_MIN_TERM_LEN: usize = EDIT_GEN_MAX_LEN;

/// Index (or re-index) a resource into the FTS trees.
/// Skips commits and documents with no searchable text. Only the postings that
/// differ from what is stored for the same subject are written.
pub fn index_resource(
    store: &Db,
    resource: &Resource,
    transaction: &mut Transaction,
) -> AtomicResult<()> {
    if skip_resource(resource) {
        return Ok(());
    }

    let subject = resource.get_subject().pure_id();
    let id = doc_id(&subject);
    let previous = load_doc_by_id(store, id, true)?;

    let fields = extract_fields(resource);
    if fields.iter().all(|(_, text)| text.is_empty()) {
        if let Some(previous) = previous {
            remove_doc(id, &previous, transaction);
        }
        return Ok(());
    }

    let drive = resource
        .get_drive()
        .map(|d| doc_id(&d.pure_id()))
        .unwrap_or_default();
    let parent = resource
        .get(urls::PARENT)
        .ok()
        .map(|v| doc_id(&Subject::from(v.to_string()).pure_id()))
        .unwrap_or_default();

    let mut tokens: Vec<DocToken> = Vec::new();
    let mut field_lens = [0u32; 3];

    for (field, text) in fields {
        if text.is_empty() {
            continue;
        }
        let list = tokenize(&text);
        field_lens[field as usize] = list.len() as u32;
        let mut tf: HashMap<String, u32> = HashMap::new();
        for token in list {
            *tf.entry(token).or_insert(0) += 1;
        }
        let mut entries: Vec<(String, u32)> = tf.into_iter().collect();
        entries.sort();
        for (token, count) in entries {
            tokens.push((field as u8, token, count));
        }
    }

    let old: HashMap<(u8, &str), u32> = previous
        .as_ref()
        .map(|p| {
            p.tokens
                .iter()
                .map(|(f, t, tf)| ((*f, t.as_str()), *tf))
                .collect()
        })
        .unwrap_or_default();
    let new_keys: HashSet<(u8, &str)> = tokens.iter().map(|(f, t, _)| (*f, t.as_str())).collect();

    for (field_id, token) in old.keys() {
        if !new_keys.contains(&(*field_id, *token)) {
            transaction.push(Operation {
                tree: Tree::SearchPostings,
                method: Method::Delete,
                key: posting_key(Field::from_u8(*field_id).unwrap_or(Field::Title), token, id),
                val: None,
            });
        }
    }

    let mut new_terms: HashSet<&str> = HashSet::new();
    for (field_id, token, tf) in &tokens {
        if old.get(&(*field_id, token.as_str())) == Some(tf) {
            continue;
        }
        transaction.push(Operation {
            tree: Tree::SearchPostings,
            method: Method::Insert,
            key: posting_key(Field::from_u8(*field_id).unwrap_or(Field::Title), token, id),
            val: Some(encode_tf(*tf)),
        });
        if token.chars().count() >= TRIGRAM_MIN_TERM_LEN {
            new_terms.insert(token.as_str());
        }
    }

    for term in new_terms {
        for gram in trigrams(term) {
            transaction.push(Operation {
                tree: Tree::SearchTrigrams,
                method: Method::Insert,
                key: trigram_key(&gram, term),
                val: Some(Vec::new()),
            });
        }
    }

    let doc = SearchDoc {
        subject,
        drive,
        parent,
        field_lens,
        tokens,
    };
    transaction.push(Operation {
        tree: Tree::SearchDocs,
        method: Method::Insert,
        key: id.to_be_bytes().to_vec(),
        val: Some(encode_doc(&doc)),
    });

    Ok(())
}

/// Index many resources, committing every `chunk` documents. Used by benches
/// and bulk rebuilds.
pub fn index_resources(store: &Db, resources: &[Resource], chunk: usize) -> AtomicResult<()> {
    let mut transaction = Transaction::new();
    let chunk = chunk.max(1);
    for (i, resource) in resources.iter().enumerate() {
        index_resource(store, resource, &mut transaction)?;
        if (i + 1) % chunk == 0 {
            store.apply_transaction(&mut transaction)?;
            transaction.clear();
        }
    }
    if !transaction.is_empty() {
        store.apply_transaction(&mut transaction)?;
    }
    Ok(())
}

/// Key prefix of the marker left for a resource whose search entries were left
/// out of a bulk write (see [`pending_marker`]).
const PENDING_PREFIX: &[u8] = b"search-pending/v1/";

/// Whether an operation writes a full-text search tree.
pub(crate) fn is_search_op(op: &Operation) -> bool {
    matches!(
        op.tree,
        Tree::SearchPostings | Tree::SearchDocs | Tree::SearchTrigrams
    )
}

/// The operation that records that `subject` still has to be indexed. A bulk
/// write of pulled resources leaves their search entries out (about three
/// quarters of everything it would write) and files one of these instead, in
/// the same transaction, so a crash loses nothing.
pub(crate) fn pending_marker(subject: &str) -> Operation {
    let mut key = PENDING_PREFIX.to_vec();
    key.extend_from_slice(subject.as_bytes());
    Operation {
        tree: Tree::PluginMeta,
        method: Method::Insert,
        key,
        val: Some(b"1".to_vec()),
    }
}

/// Index up to `limit` resources that were stored without search entries.
/// Returns how many were done; call again until it returns 0.
pub async fn index_pending(store: &Db, limit: usize) -> AtomicResult<usize> {
    let mut subjects = Vec::new();
    for pair in store.kv.scan_prefix(Tree::PluginMeta, PENDING_PREFIX) {
        let (key, _) = pair?;
        if let Ok(subject) = String::from_utf8(key[PENDING_PREFIX.len()..].to_vec()) {
            subjects.push(subject);
        }
        if subjects.len() >= limit {
            break;
        }
    }

    let mut transaction = Transaction::new();
    for subject in &subjects {
        let subj = Subject::from_raw(subject, store.get_base_domain().as_deref());
        if let Ok(resource) = store.get_resource(&subj).await {
            index_resource(store, &resource, &mut transaction)?;
        }
        let mut key = PENDING_PREFIX.to_vec();
        key.extend_from_slice(subject.as_bytes());
        transaction.push(Operation {
            tree: Tree::PluginMeta,
            method: Method::Delete,
            key,
            val: None,
        });
    }
    if !transaction.is_empty() {
        store.apply_transaction(&mut transaction)?;
    }

    Ok(subjects.len())
}

/// Drop every posting for `subject`. Idempotent if the subject is not indexed.
pub fn unindex_subject(
    store: &Db,
    subject: &str,
    transaction: &mut Transaction,
) -> AtomicResult<()> {
    let id = doc_id(subject);
    if let Some(doc) = load_doc_by_id(store, id, true)? {
        remove_doc(id, &doc, transaction);
    }
    Ok(())
}

fn remove_doc(id: DocId, doc: &SearchDoc, transaction: &mut Transaction) {
    for (field_id, token, _) in &doc.tokens {
        let field = Field::from_u8(*field_id).unwrap_or(Field::Title);
        transaction.push(Operation {
            tree: Tree::SearchPostings,
            method: Method::Delete,
            key: posting_key(field, token, id),
            val: None,
        });
    }
    transaction.push(Operation {
        tree: Tree::SearchDocs,
        method: Method::Delete,
        key: id.to_be_bytes().to_vec(),
        val: None,
    });
}

/// Wipe and rebuild the FTS trees from every stored resource.
pub fn build_search_index(store: &Db) -> AtomicResult<()> {
    tracing::info!("Building full-text search index");
    for tree in search_trees() {
        store.kv.clear_tree(tree)?;
    }
    for (count, resource) in store.all_resources(true).enumerate() {
        let mut transaction = Transaction::new();
        index_resource(store, &resource, &mut transaction)?;
        store.apply_transaction(&mut transaction)?;
        if count > 0 && count % 1000 == 0 {
            tracing::info!("Search index: {} resources", count);
        }
        if count > 0 && count % 10000 == 0 {
            store.kv.flush()?;
        }
    }
    mark_search_ready(store)?;
    tracing::info!("Full-text search index finished");
    Ok(())
}

/// Rebuild once on stores that predate this index. New stores are filled
/// incrementally by [`index_resource`]; we only scan when the FTS trees are
/// empty but resources already exist (an upgraded file).
pub fn maybe_rebuild_search_index(store: &Db) -> AtomicResult<()> {
    if store
        .kv
        .get(Tree::PluginMeta, SEARCH_INDEX_VERSION_KEY)?
        .is_some()
    {
        return Ok(());
    }
    let n_search = store.kv.len(Tree::SearchDocs).unwrap_or(0);
    let n_resources = store.kv.len(Tree::Resources).unwrap_or(0);
    if n_search == 0 && n_resources > 0 {
        tracing::info!(
            "Search index missing on a store with {} resources; rebuilding",
            n_resources
        );
        #[cfg(target_arch = "wasm32")]
        file_all_as_pending(store)?;
        #[cfg(not(target_arch = "wasm32"))]
        build_search_index(store)?;
    }
    mark_search_ready(store)
}

/// Browser upgrade: indexing every resource at open would hold the database
/// worker for a long time on a big drive, so each one is only filed as pending
/// and [`index_pending`] adds them in slices once the app is up.
#[cfg(target_arch = "wasm32")]
fn file_all_as_pending(store: &Db) -> AtomicResult<()> {
    let mut transaction = Transaction::new();
    for pair in store.kv.iter_tree(Tree::Resources) {
        let (key, _) = pair?;
        if let Ok(subject) = String::from_utf8(key.to_vec()) {
            transaction.push(pending_marker(&subject));
        }
        if transaction.len() >= 2000 {
            store.apply_transaction(&mut transaction)?;
            transaction.clear();
        }
    }
    if !transaction.is_empty() {
        store.apply_transaction(&mut transaction)?;
    }
    Ok(())
}

/// Drop the FTS trees and rebuild from every stored resource. Used after the
/// canonical-scheme key rewrite so postings are not left under `did:ad:`.
pub fn rebuild_search_index(store: &Db) -> AtomicResult<()> {
    for tree in search_trees() {
        store.kv.clear_tree(tree)?;
    }
    let _ = store.kv.remove(Tree::PluginMeta, SEARCH_INDEX_VERSION_KEY);
    build_search_index(store)
}

fn mark_search_ready(store: &Db) -> AtomicResult<()> {
    store
        .kv
        .insert(Tree::PluginMeta, SEARCH_INDEX_VERSION_KEY, b"1")
}

/// Ranked full-text search over the KV index.
///
/// Empty `query_str` with no filters returns nothing. Empty `query_str` with
/// filters lists PropValSub matches (then parent-scoped), which is what the
/// file picker and class selector send.
pub fn query(store: &Db, query_str: &str, opts: &SearchOpts) -> AtomicResult<Vec<SearchHit>> {
    query_timed(store, query_str, opts).map(|(hits, _)| hits)
}

/// Where a [`query`] spent its time, for `Server-Timing`.
#[derive(Debug, Clone, Copy, Default)]
pub struct QueryTimings {
    /// Walking the postings and BM25-scoring them, scope checks excluded.
    pub score: std::time::Duration,
    /// Loading candidate docs and checking scope / existence.
    pub scope: std::time::Duration,
    /// Combining tokens, sorting and truncating.
    pub rank: std::time::Duration,
    /// Distinct documents that matched a token (before scoping).
    pub candidates: usize,
    /// Documents that were in scope.
    pub in_scope: usize,
}

/// [`query`], also reporting where the time went.
pub fn query_timed(
    store: &Db,
    query_str: &str,
    opts: &SearchOpts,
) -> AtomicResult<(Vec<SearchHit>, QueryTimings)> {
    let mut timings = QueryTimings::default();
    let tokens: Vec<String> = tokenize(query_str);
    let filter_pairs = opts_filter_pairs(opts);
    let filter_set = if filter_pairs.is_empty() {
        None
    } else {
        Some(subjects_matching_filters(store, &filter_pairs)?)
    };

    let limit = opts.limit.unwrap_or(DEFAULT_LIMIT) as usize;
    let parents: Vec<String> = opts
        .parents
        .clone()
        .unwrap_or_default()
        .into_iter()
        .map(|p| Subject::from(p).pure_id())
        .collect();

    if tokens.is_empty() {
        let Some(allowed) = filter_set else {
            return Ok((Vec::new(), timings));
        };
        return Ok((filter_only_hits(store, allowed, &parents, limit)?, timings));
    }

    let n_docs = store.kv.len(Tree::SearchDocs).unwrap_or(0) as f32;
    if n_docs == 0.0 {
        return Ok((Vec::new(), timings));
    }

    let allowed_ids: Option<HashSet<DocId>> = filter_set
        .as_ref()
        .map(|allowed| allowed.iter().map(|s| doc_id(s)).collect());
    let mut candidates = Candidates::new(store, parents, allowed_ids);

    // Per query token: document -> best score for that token. Only documents
    // that pass the scope filter are scored (and have their length read); a
    // term's document frequency still counts every posting, so the scores of
    // surviving documents are exactly what an unscoped run would give them.
    let started = web_time::Instant::now();
    let mut per_token: Vec<HashMap<DocId, f32>> = Vec::with_capacity(tokens.len());
    for token in &tokens {
        per_token.push(score_token(store, token, n_docs, &mut candidates)?);
    }

    // AND: a doc must score on every query token.
    let ranking = web_time::Instant::now();
    let mut ids: Vec<DocId> = per_token[0].keys().copied().collect();
    for map in per_token.iter().skip(1) {
        ids.retain(|id| map.contains_key(id));
    }

    let mut hits: Vec<SearchHit> = Vec::with_capacity(ids.len());
    for id in ids {
        let Some(subject) = candidates.subject(id) else {
            continue;
        };
        let mut score = 0.0;
        for map in &per_token {
            score += map.get(&id).copied().unwrap_or(0.0);
        }
        hits.push(SearchHit {
            subject: Subject::from(subject.to_string()),
            score,
        });
    }

    hits.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.subject.as_str().cmp(b.subject.as_str()))
    });
    hits.truncate(limit);

    timings.rank = ranking.elapsed();
    timings.scope = candidates.spent;
    timings.score = started
        .elapsed()
        .saturating_sub(timings.rank + timings.scope);
    timings.candidates = candidates.seen.len();
    timings.in_scope = candidates.seen.values().filter(|c| c.is_some()).count();
    Ok((hits, timings))
}

/// A candidate document that passed scoping.
struct Candidate {
    subject: String,
    len: f32,
}

/// Decides, once per document, whether a posting hit may be returned:
/// it must pass the property filters, sit under `parents` and still exist.
/// Memoized, so the document row is read once however many terms and query
/// tokens post it, and ancestors and out-of-drive parent walks are shared.
struct Candidates<'a> {
    store: &'a Db,
    parents: Vec<String>,
    scope_ids: HashSet<DocId>,
    allowed: Option<HashSet<DocId>>,
    seen: HashMap<DocId, Option<Candidate>>,
    /// Ancestor rows read while walking parents.
    doc_cache: HashMap<DocId, SearchDoc>,
    /// Outcome of the fallback resource walk, per (drive, parent).
    walk_cache: HashMap<(DocId, DocId), bool>,
    spent: std::time::Duration,
}

impl<'a> Candidates<'a> {
    fn new(store: &'a Db, parents: Vec<String>, allowed: Option<HashSet<DocId>>) -> Self {
        let scope_ids = parents.iter().map(|p| doc_id(p)).collect();
        Self {
            store,
            parents,
            scope_ids,
            allowed,
            seen: HashMap::new(),
            doc_cache: HashMap::new(),
            walk_cache: HashMap::new(),
            spent: std::time::Duration::ZERO,
        }
    }

    /// The document length when `id` may be returned.
    fn len_of(&mut self, id: DocId) -> AtomicResult<Option<f32>> {
        if let Some(known) = self.seen.get(&id) {
            return Ok(known.as_ref().map(|c| c.len));
        }
        let started = web_time::Instant::now();
        let verdict = self.judge(id)?;
        self.spent += started.elapsed();
        let len = verdict.as_ref().map(|c| c.len);
        self.seen.insert(id, verdict);
        Ok(len)
    }

    fn subject(&self, id: DocId) -> Option<&str> {
        self.seen.get(&id)?.as_ref().map(|c| c.subject.as_str())
    }

    fn judge(&mut self, id: DocId) -> AtomicResult<Option<Candidate>> {
        if let Some(allowed) = &self.allowed {
            if !allowed.contains(&id) {
                return Ok(None);
            }
        }
        let Some(doc) = load_doc_by_id(self.store, id, false)? else {
            return Ok(None);
        };
        if doc.subject.is_empty() {
            return Ok(None);
        }
        if !self.parents.is_empty() && !self.in_parents(&doc)? {
            return Ok(None);
        }
        // An entry whose resource is gone (left behind by an interrupted
        // write, or by a store older than the unindex-on-destroy) would
        // otherwise be listed and then fail to open.
        if !self.store.has_resource_locally(&doc.subject) {
            return Ok(None);
        }
        let len = doc.field_lens.iter().sum::<u32>();
        Ok(Some(Candidate {
            len: if len == 0 { AVGDL } else { len as f32 },
            subject: doc.subject,
        }))
    }

    fn in_parents(&mut self, doc: &SearchDoc) -> AtomicResult<bool> {
        if in_scope(
            &doc.subject,
            doc,
            &self.parents,
            &self.scope_ids,
            self.store,
            &mut self.doc_cache,
        )? {
            return Ok(true);
        }
        // Not reachable through indexed ancestors (an ancestor may have no
        // searchable text): walk the resources themselves. The answer is the
        // same for every sibling, so it is kept per (drive, parent).
        if doc.drive != 0 && doc.parent != 0 {
            let key = (doc.drive, doc.parent);
            if let Some(known) = self.walk_cache.get(&key) {
                return Ok(*known);
            }
            let verdict = resource_in_parents(self.store, &doc.subject, &self.parents)?;
            self.walk_cache.insert(key, verdict);
            return Ok(verdict);
        }
        resource_in_parents(self.store, &doc.subject, &self.parents)
    }
}

fn opts_filter_pairs(opts: &SearchOpts) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Some(map) = &opts.filters {
        for (key, value) in map {
            if !value.is_empty() {
                out.push((key.clone(), value.clone()));
            }
        }
    }
    if let Some(pairs) = &opts.filter_pairs {
        for (key, value) in pairs {
            if !value.is_empty() {
                out.push((key.clone(), value.clone()));
            }
        }
    }
    out
}

/// Parse the HTTP `filters=` string: exact `property:"value"` pairs joined
/// by ` AND `. Property URLs are taken literally — there is no query
/// language and no special-character escaping.
pub fn parse_search_filters(filters: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    let mut rest = filters;
    while !rest.is_empty() {
        let (clause, next) = split_filter_clause(rest);
        rest = next;
        if let Some(pair) = parse_filter_clause(clause) {
            pairs.push(pair);
        }
    }
    pairs
}

fn split_filter_clause(input: &str) -> (&str, &str) {
    let mut in_quotes = false;
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] as char {
            '"' => in_quotes = !in_quotes,
            ' ' if !in_quotes && input[i..].starts_with(" AND ") => {
                return (&input[..i], &input[i + 5..]);
            }
            _ => {}
        }
        i += 1;
    }
    (input, "")
}

fn parse_filter_clause(clause: &str) -> Option<(String, String)> {
    let clause = clause.trim();
    if clause.is_empty() {
        return None;
    }
    // `:"` is the delimiter so property URLs (`https://…`) stay intact.
    let idx = clause.find(":\"")?;
    let key = clause[..idx].trim();
    let rest = &clause[idx + 2..];
    let end = rest.find('"').unwrap_or(rest.len());
    let value = rest[..end].trim();
    if key.is_empty() || value.is_empty() {
        return None;
    }
    Some((key.to_string(), value.to_string()))
}

fn subjects_matching_filters(
    store: &Db,
    pairs: &[(String, String)],
) -> AtomicResult<HashSet<String>> {
    let mut result: Option<HashSet<String>> = None;
    for (prop, val) in pairs {
        let value = Value::String(val.clone());
        let mut set = HashSet::new();
        for atom in find_in_prop_val_sub_index(store, prop, Some(&value)) {
            set.insert(atom?.subject.to_string());
        }
        result = Some(match result {
            None => set,
            Some(prev) => prev.intersection(&set).cloned().collect(),
        });
    }
    Ok(result.unwrap_or_default())
}

fn filter_only_hits(
    store: &Db,
    allowed: HashSet<String>,
    parents: &[String],
    limit: usize,
) -> AtomicResult<Vec<SearchHit>> {
    let mut hits = Vec::new();
    let mut doc_cache: HashMap<DocId, SearchDoc> = HashMap::new();
    let scope_ids: HashSet<DocId> = parents.iter().map(|p| doc_id(p)).collect();
    let mut subjects: Vec<String> = allowed.into_iter().collect();
    subjects.sort();
    for subject in subjects {
        if !parents.is_empty()
            && !subject_in_parents(store, &subject, parents, &scope_ids, &mut doc_cache)?
        {
            continue;
        }
        hits.push(SearchHit {
            subject: Subject::from(subject),
            score: 1.0,
        });
        if hits.len() >= limit {
            break;
        }
    }
    Ok(hits)
}

fn subject_in_parents(
    store: &Db,
    subject: &str,
    parents: &[String],
    scope_ids: &HashSet<DocId>,
    cache: &mut HashMap<DocId, SearchDoc>,
) -> AtomicResult<bool> {
    let id = doc_id(subject);
    let doc = load_doc(store, id, cache)?;
    if in_scope(subject, &doc, parents, scope_ids, store, cache)? {
        return Ok(true);
    }
    // Not in SearchDocs (no searchable text) — walk the resource itself.
    resource_in_parents(store, subject, parents)
}

fn resource_in_parents(store: &Db, subject: &str, parents: &[String]) -> AtomicResult<bool> {
    let mut current = subject.to_string();
    let mut seen = HashSet::new();
    for _ in 0..MAX_PARENT_WALK {
        if !seen.insert(current.clone()) {
            break;
        }
        if parents.iter().any(|p| p == &current) {
            return Ok(true);
        }
        let Ok(resource) = store.get_resource_shallow(&current.as_str().into()) else {
            break;
        };
        if let Some(drive) = resource.get_drive() {
            let drive_id = drive.pure_id();
            if parents
                .iter()
                .any(|p| p == &drive_id || p == drive.as_str())
            {
                return Ok(true);
            }
        }
        let parent = resource
            .get(urls::PARENT)
            .ok()
            .map(|v| Subject::from(v.to_string()).pure_id())
            .unwrap_or_default();
        if parent.is_empty() {
            break;
        }
        if parents.contains(&parent) {
            return Ok(true);
        }
        current = parent;
    }
    Ok(false)
}

fn score_token(
    store: &Db,
    q: &str,
    n_docs: f32,
    candidates: &mut Candidates,
) -> AtomicResult<HashMap<DocId, f32>> {
    let mut scores: HashMap<DocId, f32> = HashMap::new();
    let mut seen_terms: HashSet<(u8, String)> = HashSet::new();

    // Always prefix-scan the original token (typeahead).
    collect_prefix(store, q, q, &mut seen_terms)?;

    if q.chars().count() >= MIN_FUZZY_LEN && q.chars().count() <= EDIT_GEN_MAX_LEN {
        for variant in one_edits(q) {
            collect_prefix(store, &variant, q, &mut seen_terms)?;
        }
    } else if q.chars().count() > EDIT_GEN_MAX_LEN {
        collect_trigram_candidates(store, q, &mut seen_terms)?;
    }

    for (field_id, term) in seen_terms {
        let field = Field::from_u8(field_id).unwrap_or(Field::Title);
        let kind = classify_match(q, &term);
        let boost = field.boost(kind);
        let prefix = posting_prefix(field, &term);
        let mut postings: Vec<(DocId, u32)> = Vec::new();
        for pair in store.kv.scan_prefix(Tree::SearchPostings, &prefix) {
            let (key, val) = pair?;
            let Some(id) = id_from_posting(&key, &prefix) else {
                continue;
            };
            postings.push((id, decode_tf(&val)));
        }
        let df = postings.len() as u32;
        if df == 0 {
            continue;
        }
        let idf = ((n_docs - df as f32 + 0.5) / (df as f32 + 0.5) + 1.0).ln();
        for (id, tf) in postings {
            let Some(dl) = candidates.len_of(id)? else {
                continue;
            };
            let tf_norm = (tf as f32 * (BM25_K1 + 1.0))
                / (tf as f32 + BM25_K1 * (1.0 - BM25_B + BM25_B * (dl / AVGDL)));
            let add = boost * idf * tf_norm;
            scores.entry(id).and_modify(|s| *s += add).or_insert(add);
        }
    }

    Ok(scores)
}

#[derive(Clone, Copy)]
enum MatchKind {
    Exact,
    Prefix,
    Fuzzy,
}

impl Field {
    fn boost(self, kind: MatchKind) -> f32 {
        match (self, kind) {
            (Field::Title, MatchKind::Exact) => 10.0,
            (Field::Title, MatchKind::Prefix) => 6.0,
            (Field::Title, MatchKind::Fuzzy) => 4.0,
            (Field::Description | Field::Body, MatchKind::Exact) => 2.0,
            (Field::Description | Field::Body, MatchKind::Prefix) => 1.5,
            (Field::Description | Field::Body, MatchKind::Fuzzy) => 1.0,
        }
    }
}

fn classify_match(query: &str, term: &str) -> MatchKind {
    if term == query {
        MatchKind::Exact
    } else if term.starts_with(query) {
        MatchKind::Prefix
    } else {
        MatchKind::Fuzzy
    }
}

fn collect_prefix(
    store: &Db,
    prefix_token: &str,
    query: &str,
    out: &mut HashSet<(u8, String)>,
) -> AtomicResult<()> {
    if prefix_token.is_empty() {
        return Ok(());
    }
    for field in Field::ALL {
        let prefix = posting_typeahead_prefix(field, prefix_token);
        for pair in store.kv.scan_prefix(Tree::SearchPostings, &prefix) {
            let (key, _) = pair?;
            if let Some(term) = token_from_posting_key(&key, field) {
                if term.starts_with(prefix_token) || min_prefix_levenshtein(query, &term) <= 1 {
                    out.insert((field as u8, term));
                }
            }
        }
    }
    Ok(())
}

fn collect_trigram_candidates(
    store: &Db,
    q: &str,
    out: &mut HashSet<(u8, String)>,
) -> AtomicResult<()> {
    let grams = trigrams(q);
    if grams.is_empty() {
        return Ok(());
    }
    let mut counts: HashMap<String, usize> = HashMap::new();
    for gram in &grams {
        for pair in store
            .kv
            .scan_prefix(Tree::SearchTrigrams, &trigram_prefix(gram))
        {
            let (key, _) = pair?;
            if let Some(term) = term_from_trigram_key(&key, gram) {
                *counts.entry(term).or_insert(0) += 1;
            }
        }
    }
    let required = grams.len().saturating_sub(3).max(1);
    for (term, n) in counts {
        if n >= required && min_prefix_levenshtein(q, &term) <= 1 {
            for field in Field::ALL {
                out.insert((field as u8, term.clone()));
            }
        }
    }
    Ok(())
}

fn skip_resource(resource: &Resource) -> bool {
    let subject = resource.get_subject();
    if subject.is_commit_did() {
        return true;
    }
    if subject.as_str().contains("/commits/") {
        return true;
    }
    resource.is_native()
}

fn extract_fields(resource: &Resource) -> Vec<(Field, String)> {
    let title = title_text(resource);
    let description = description_text(resource);
    let body = body_text(resource);
    vec![
        (Field::Title, title),
        (Field::Description, description),
        (Field::Body, body),
    ]
}

fn title_text(resource: &Resource) -> String {
    if let Ok(v) = resource.get(urls::NAME) {
        return stringy(v);
    }
    if let Ok(v) = resource.get(urls::SHORTNAME) {
        return stringy(v);
    }
    if let Ok(v) = resource.get(urls::FILENAME) {
        return stringy(v);
    }
    String::new()
}

fn description_text(resource: &Resource) -> String {
    resource
        .get(urls::DESCRIPTION)
        .ok()
        .map(stringy)
        .unwrap_or_default()
}

fn body_text(resource: &Resource) -> String {
    if let Some(snapshot) = resource.materialized_state() {
        if let Ok(doc) = crate::loro::AtomicLoroDoc::from_snapshot(&snapshot) {
            let text = doc.extract_document_plain_text();
            if !text.is_empty() {
                return text;
            }
        }
    }
    // `set_unsafe` materializes a properties-only live doc, after which
    // `materialized_state` prefers that over the `loroUpdate` propval. A
    // snapshot stored as `LORO_UPDATE` can still carry `documentContent`.
    if let Ok(Value::LoroDoc(snapshot)) = resource.get(urls::LORO_UPDATE) {
        if let Ok(doc) = crate::loro::AtomicLoroDoc::from_snapshot(snapshot) {
            return doc.extract_document_plain_text();
        }
    }
    String::new()
}

fn stringy(value: &Value) -> String {
    match value {
        Value::String(s) | Value::Markdown(s) | Value::Slug(s) | Value::Date(s) | Value::Uri(s) => {
            s.clone()
        }
        Value::LocalizedText(map) => map.values().cloned().collect::<Vec<_>>().join(" "),
        Value::AtomicUrl(_)
        | Value::ResourceArray(_)
        | Value::NestedResource(_)
        | Value::LoroDoc(_) => String::new(),
        other => other.to_string(),
    }
}

fn trigrams(term: &str) -> Vec<String> {
    let chars: Vec<char> = term.chars().collect();
    if chars.len() < 3 {
        return if chars.is_empty() {
            Vec::new()
        } else {
            vec![term.to_string()]
        };
    }
    chars.windows(3).map(|w| w.iter().collect()).collect()
}

fn id_from_posting(key: &[u8], prefix: &[u8]) -> Option<DocId> {
    let rest = key.get(prefix.len()..)?;
    Some(u64::from_be_bytes(rest.try_into().ok()?))
}

fn term_from_trigram_key(key: &[u8], gram: &str) -> Option<String> {
    let prefix = trigram_prefix(gram);
    if key.len() <= prefix.len() {
        return None;
    }
    String::from_utf8(key[prefix.len()..].to_vec()).ok()
}

fn load_doc(
    store: &Db,
    id: DocId,
    cache: &mut HashMap<DocId, SearchDoc>,
) -> AtomicResult<SearchDoc> {
    if let Some(doc) = cache.get(&id) {
        return Ok(doc.clone());
    }
    let doc = load_doc_by_id(store, id, false)?.unwrap_or_default();
    cache.insert(id, doc.clone());
    Ok(doc)
}

fn load_doc_by_id(store: &Db, id: DocId, with_tokens: bool) -> AtomicResult<Option<SearchDoc>> {
    Ok(store
        .kv
        .get(Tree::SearchDocs, &id.to_be_bytes())?
        .map(|bytes| decode_doc(&bytes, with_tokens)))
}

fn in_scope(
    subject: &str,
    doc: &SearchDoc,
    parents: &[String],
    scope_ids: &HashSet<DocId>,
    store: &Db,
    cache: &mut HashMap<DocId, SearchDoc>,
) -> AtomicResult<bool> {
    if parents.iter().any(|p| p == subject) {
        return Ok(true);
    }
    if doc.drive != 0 && scope_ids.contains(&doc.drive) {
        return Ok(true);
    }
    let mut seen = HashSet::new();
    let mut node = doc.clone();
    for _ in 0..MAX_PARENT_WALK {
        if node.parent == 0 || !seen.insert(node.parent) {
            break;
        }
        if scope_ids.contains(&node.parent) {
            return Ok(true);
        }
        node = load_doc(store, node.parent, cache)?;
    }
    Ok(false)
}

#[cfg(test)]
mod tests;
