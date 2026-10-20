//! Stress test: a store with 1000 AI chats full of text (and 2000 documents
//! and folders), seeded and then measured through the host APIs the Flutter
//! app calls (`atomic_lib::host`). See `planning/flutter-performance.md`,
//! "Stress test: 1000 chats".
//!
//! Two steps, each in its own process so the measurement starts cold:
//!
//! ```text
//! STRESS_DIR=/path/to/scratch/stress \
//!   cargo test -p atomic_lib --features db-redb --profile e2e --test stress_chats \
//!   -- --ignored --nocapture stress_seed
//! STRESS_DIR=/path/to/scratch/stress \
//!   cargo test -p atomic_lib --features db-redb --profile e2e --test stress_chats \
//!   -- --ignored --nocapture stress_measure
//! ```
//!
//! Knobs (environment): `STRESS_CHATS` (1000), `STRESS_DOCS` (2000),
//! `STRESS_TEXT_SCALE` (1.0, scales every message's length),
//! `STRESS_APPEND_CHATS` (10: chats written one `append_chat_entry` per
//! message, as the app does while chatting; the rest go through
//! `import_ai_chat`), `STRESS_REBUILD=1` (also time a full search index
//! rebuild, the first start after an upgrade).
#![cfg(feature = "db-redb")]

use atomic_lib::{
    chat_log::Entry,
    client::search::SearchOpts,
    host::{chats, lists, profiles::AgentProfiles, recents::RecentsIndex, NoPush},
    runtime::AtomicNode,
    urls, Db, Storelike, Subject,
};
use serde_json::json;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

const AI_CHAT: &str = atomic_lib::host::rows::AI_CHAT;
/// A word that only ever appears inside chat messages, never in a title or a
/// document: a search for it shows whether chat text is searchable.
const CONTENT_ONLY: &str = "zephyrquokka";

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn stress_dir() -> PathBuf {
    PathBuf::from(std::env::var("STRESS_DIR").expect("set STRESS_DIR to a scratch directory"))
}

// ── Text ─────────────────────────────────────────────────────────────────

/// xorshift64*: deterministic, so every run seeds the same store.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
    fn range(&mut self, lo: usize, hi: usize) -> usize {
        lo + self.below(hi - lo + 1)
    }
    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }
    /// Zipf-ish: index `i` with weight about 1/(i+1).
    fn zipf(&mut self, n: usize) -> usize {
        let u = (self.next() >> 11) as f64 / (1u64 << 53) as f64;
        ((n as f64 + 1.0).powf(u) - 1.0).floor() as usize % n.max(1)
    }
}

const EN: &[&str] = &[
    "the", "of", "and", "to", "in", "is", "that", "for", "it", "as", "with", "be", "on", "not",
    "this", "but", "by", "from", "they", "we", "you", "can", "will", "which", "would", "there",
    "their", "what", "about", "when", "your", "make", "like", "time", "just", "know", "take",
    "people", "into", "year", "good", "some", "could", "them", "see", "other", "than", "then",
    "now", "look", "only", "come", "over", "think", "also", "back", "after", "use", "two", "how",
    "work", "first", "well", "way", "even", "new", "want", "because", "any", "these", "give",
    "day", "most", "budget", "recipe", "travel", "garden", "invoice", "meeting", "project",
    "server", "database", "kubernetes", "deployment", "migration", "schema", "frontend",
    "backend", "latency", "throughput", "memory", "search", "index", "query", "cache",
    "summary", "proposal", "strategy", "customer", "contract", "holiday", "bicycle", "kitchen",
    "weather", "mountain", "library", "history", "physics", "chemistry", "guitar", "marathon",
];
const NL: &[&str] = &[
    "de", "het", "een", "en", "van", "ik", "te", "dat", "die", "in", "is", "niet", "op", "aan",
    "met", "als", "voor", "maar", "om", "ook", "nog", "wel", "naar", "dan", "kan", "zijn", "bij",
    "wordt", "moet", "hebben", "gemeente", "fiets", "boodschappen", "vergadering", "begroting",
    "afspraak", "verjaardag", "huiswerk", "zomervakantie", "belasting", "verzekering",
    "aanvraag", "onderzoek", "samenvatting", "gezondheid", "werkgever", "ontwikkeling",
];
const DE: &[&str] = &[
    "der", "die", "und", "in", "den", "von", "zu", "das", "mit", "sich", "des", "auf", "für",
    "ist", "im", "nicht", "ein", "eine", "als", "auch", "werden", "Rechnung", "Wohnung",
    "Steuererklärung", "Krankenversicherung", "Bahnhof", "Wanderung", "Zusammenfassung",
    "Anleitung", "Überweisung", "Grundstück", "Straßenbahn", "Fußgängerzone",
];
const FR: &[&str] = &[
    "le", "la", "les", "de", "des", "et", "un", "une", "du", "en", "est", "que", "pour", "dans",
    "qui", "pas", "sur", "plus", "avec", "être", "réunion", "facture", "logement", "voyage",
    "recette", "déménagement", "élève", "université", "boulangerie", "randonnée", "théâtre",
];
const ES: &[&str] = &[
    "el", "la", "de", "que", "y", "en", "un", "los", "se", "del", "las", "por", "con", "una",
    "para", "como", "más", "pero", "reunión", "factura", "vivienda", "viaje", "receta",
    "mañana", "niño", "año", "español", "biblioteca", "presupuesto", "cumpleaños",
];
const CODE: &[&str] = &[
    "fn", "let", "mut", "impl", "struct", "async", "await", "return", "match", "Some", "None",
    "Ok", "Err", "const", "def", "self", "import", "from", "class", "function", "export",
    "interface", "type", "string", "number", "Vec", "HashMap", "Result", "Option", "unwrap",
];
const SYLLABLES: &[&str] = &[
    "ka", "lo", "mi", "ter", "van", "son", "rel", "dor", "pa", "ni", "que", "stra", "bel", "gon",
    "fi", "mo", "tra", "lin", "ve", "zu", "ch", "ar", "en", "ost", "um", "ix", "or", "ly", "sch",
    "ber", "gen", "hu", "ka", "ri", "do", "ne", "tal", "wey", "pre", "con",
];

/// The long tail of a real corpus: distinct, rarely repeated terms.
fn long_tail(rng: &mut Rng, n: usize) -> Vec<String> {
    (0..n)
        .map(|_| {
            let parts = rng.range(2, 4);
            (0..parts).map(|_| *rng.pick(SYLLABLES)).collect::<String>()
        })
        .collect()
}

struct Corpus {
    tail: Vec<String>,
}

impl Corpus {
    fn new() -> Self {
        Corpus {
            tail: long_tail(&mut Rng(0x5eed), 40_000),
        }
    }

    fn word(&self, rng: &mut Rng, lang: &[&'static str]) -> String {
        // 85% common words of the language, 15% the long tail.
        if rng.below(100) < 85 {
            lang[rng.zipf(lang.len())].to_string()
        } else {
            self.tail[rng.zipf(self.tail.len())].clone()
        }
    }

    fn sentence(&self, rng: &mut Rng, lang: &[&'static str]) -> String {
        let n = rng.range(6, 22);
        let mut s: Vec<String> = (0..n).map(|_| self.word(rng, lang)).collect();
        if rng.below(40) == 0 {
            s.push(CONTENT_ONLY.to_string());
        }
        if rng.below(8) == 0 {
            s.push(format!("{}", rng.range(1, 99_999)));
        }
        let mut out = s.join(" ");
        if let Some(first) = out.get(0..1) {
            out.replace_range(0..1, &first.to_uppercase());
        }
        out.push(*rng.pick(&['.', '.', '.', '?', '!']));
        out
    }

    fn code(&self, rng: &mut Rng) -> String {
        let lines = rng.range(4, 18);
        let mut out = String::from("```rust\n");
        for _ in 0..lines {
            let indent = "    ".repeat(rng.below(3));
            let ident = format!("{}_{}", self.word(rng, EN), self.word(rng, EN));
            out.push_str(&format!(
                "{indent}{} {ident} = {}({});\n",
                rng.pick(CODE),
                rng.pick(CODE),
                rng.range(0, 4096)
            ));
        }
        out.push_str("```\n");
        out
    }

    /// One message of about `len` characters: paragraphs, sometimes a heading,
    /// a list or a code block, in one language.
    fn message(&self, rng: &mut Rng, len: usize) -> String {
        let lang: &[&'static str] = match rng.below(10) {
            0..=4 => EN,
            5..=6 => NL,
            7 => DE,
            8 => FR,
            _ => ES,
        };
        let mut out = String::with_capacity(len + 200);
        while out.len() < len {
            match rng.below(10) {
                0 => out.push_str(&format!("## {}\n\n", self.sentence(rng, lang))),
                1 => {
                    for _ in 0..rng.range(2, 5) {
                        out.push_str(&format!("- {}\n", self.sentence(rng, lang)));
                    }
                    out.push('\n');
                }
                2 if lang == EN => out.push_str(&self.code(rng)),
                _ => {
                    for _ in 0..rng.range(2, 5) {
                        out.push_str(&self.sentence(rng, lang));
                        out.push(' ');
                    }
                    out.push_str("\n\n");
                }
            }
        }
        out.truncate(out.floor_char_boundary(len));
        out
    }

    fn title(&self, rng: &mut Rng) -> String {
        let lang: &[&'static str] = match rng.below(4) {
            0 | 1 => EN,
            2 => NL,
            _ => DE,
        };
        let n = rng.range(2, 5);
        let mut words: Vec<String> = (0..n).map(|_| self.word(rng, lang)).collect();
        // Titles carry the topical words, not "the of and".
        words.push(lang[rng.range(lang.len() / 2, lang.len() - 1)].to_string());
        let mut t = words.join(" ");
        if let Some(first) = t.get(0..1) {
            t.replace_range(0..1, &first.to_uppercase());
        }
        t
    }
}

// ── Timing ───────────────────────────────────────────────────────────────

struct Row {
    name: String,
    first: Duration,
    median: Duration,
    p95: Duration,
    note: String,
}

#[derive(Default)]
struct Table(Vec<Row>);

fn ms(d: Duration) -> String {
    format!("{:.2}", d.as_secs_f64() * 1000.0)
}

impl Table {
    fn push(&mut self, name: &str, mut times: Vec<Duration>, note: String) {
        let first = times[0];
        let warm = if times.len() > 1 {
            times.split_off(1)
        } else {
            times.clone()
        };
        let mut sorted = warm;
        sorted.sort();
        let median = sorted[sorted.len() / 2];
        let p95 = sorted[((sorted.len() as f64 * 0.95).ceil() as usize).saturating_sub(1)];
        println!(
            "[stress] {name}: first {} ms, median {} ms, p95 {} ms {note}",
            ms(first),
            ms(median),
            ms(p95)
        );
        self.0.push(Row {
            name: name.to_string(),
            first,
            median,
            p95,
            note,
        });
    }

    fn print(&self) {
        println!("\n| what | first (cold) ms | median ms | p95 ms | notes |");
        println!("|---|---:|---:|---:|---|");
        for r in &self.0 {
            println!(
                "| {} | {} | {} | {} | {} |",
                r.name,
                ms(r.first),
                ms(r.median),
                ms(r.p95),
                r.note
            );
        }
    }
}

/// Run `$body` (an async expression giving a note string) `$reps` times.
macro_rules! bench {
    ($table:expr, $name:expr, $reps:expr, $body:expr) => {{
        let mut times = Vec::new();
        let mut note = String::new();
        for _ in 0..$reps {
            let t = Instant::now();
            note = $body.await;
            times.push(t.elapsed());
        }
        $table.push(&$name, times, note);
    }};
}

fn rss_mb() -> f64 {
    let out = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .ok();
    out.and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse::<f64>().ok())
        .map_or(0.0, |kb| kb / 1024.0)
}

fn dir_size(path: &Path) -> u64 {
    std::fs::read_dir(path)
        .map(|entries| {
            entries
                .flatten()
                .map(|e| {
                    let meta = e.metadata().unwrap();
                    if meta.is_dir() {
                        dir_size(&e.path())
                    } else {
                        meta.len()
                    }
                })
                .sum()
        })
        .unwrap_or(0)
}

/// What the Flutter bridge's `open_db` does: open the file, make sure the
/// search index is caught up, load the recents index and start its listener.
/// The bridge runs the startup compaction check at most once a week
/// (`flutter/rust/src/api/simple/compaction_check.rs`), so a start opens
/// without it unless `STRESS_COMPACTION_CHECK` is set.
async fn open_like_the_app(dir: &Path, recents: &Arc<RecentsIndex>) -> (Db, Vec<(String, Duration)>) {
    if std::env::var("STRESS_LOG").is_ok() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .try_init();
    }
    let mut steps = Vec::new();
    let t = Instant::now();
    let policy = if std::env::var("STRESS_COMPACTION_CHECK").is_ok() {
        atomic_lib::db::compaction::CompactionPolicy::default()
    } else {
        atomic_lib::db::compaction::CompactionPolicy::disabled()
    };
    let store = Db::init_redb_file_with_policy(dir, None, &dir.join("uploads"), &policy)
        .await
        .expect("open store");
    steps.push(("init_redb_file".to_string(), t.elapsed()));
    let t = Instant::now();
    atomic_lib::search::rebuild_search_index_once(&store, "flutter-1").unwrap();
    while atomic_lib::search::index_pending(&store, 500).await.unwrap() > 0 {}
    steps.push(("search catch-up".to_string(), t.elapsed()));
    let t = Instant::now();
    recents.load(dir);
    recents.clone().spawn_listener(Arc::new(store.clone()));
    steps.push(("recents load".to_string(), t.elapsed()));
    (store, steps)
}

// ── Seed ─────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "stress seed: writes a large store to STRESS_DIR"]
async fn stress_seed() {
    let dir = stress_dir();
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let n_chats = env_usize("STRESS_CHATS", 1000);
    let n_docs = env_usize("STRESS_DOCS", 2000);
    let n_append = env_usize("STRESS_APPEND_CHATS", 10).min(n_chats);
    let scale: f64 = std::env::var("STRESS_TEXT_SCALE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1.0);

    let recents = Arc::new(RecentsIndex::new());
    let (store, _) = open_like_the_app(&dir, &recents).await;
    let (agent, home) = store.setup("Stress device").await.unwrap();
    std::fs::write(dir.join("stress-agent-secret"), agent.build_secret().unwrap()).unwrap();
    let node = AtomicNode::from_db(store.clone());
    let author = store.get_default_agent().unwrap().subject.to_string();
    let corpus = Corpus::new();
    let mut rng = Rng(42);

    // Documents and folders, in the private drive and a second drive.
    let work = store.create_drive("Work").await.unwrap();
    store.set_active_drive(&home).unwrap();
    let t = Instant::now();
    let mut doc_bytes = 0usize;
    let mut folders: Vec<String> = vec![home.clone(), work.clone()];
    for i in 0..n_docs {
        let root = if i % 2 == 0 { &home } else { &work };
        let parent = if folders.len() > 2 && rng.below(3) > 0 {
            folders[rng.below(folders.len())].clone()
        } else {
            root.clone()
        };
        let name = corpus.title(&mut rng);
        if i % 5 == 0 {
            let f = store
                .create_resource(urls::FOLDER, &parent, &name, None)
                .await
                .unwrap();
            folders.push(f);
            continue;
        }
        let subject = store
            .create_resource(urls::DOCUMENT_V2, &parent, &name, None)
            .await
            .unwrap();
        let len = ((rng.range(300, 6000) as f64) * scale) as usize;
        let body = corpus.message(&mut rng, len).replace(CONTENT_ONLY, "quokka");
        doc_bytes += body.len();
        let mut r = store.get_resource(&Subject::from(subject.as_str())).await.unwrap();
        r.live_doc()
            .unwrap()
            .doc()
            .get_text("documentContent")
            .insert(0, &body)
            .unwrap();
        node.save_locally(&mut r).await.unwrap();
        if i < 30 {
            recents.note_opened(root, &subject, 1_700_000_000_000 + i as i64);
        }
    }
    let docs_s = t.elapsed().as_secs_f64();
    println!(
        "[seed] {n_docs} documents/folders ({:.1} MB body text) in {docs_s:.1} s: {:.0}/s",
        doc_bytes as f64 / 1e6,
        n_docs as f64 / docs_s
    );

    // AI chats.
    let mut text_bytes = 0usize;
    let mut messages = 0usize;
    let mut longest = (0usize, String::new());
    let (mut append_s, mut import_s) = (0.0, 0.0);
    let (mut append_n, mut import_n) = (0usize, 0usize);
    let base_time = 1_750_000_000_000i64;
    for c in 0..n_chats {
        let n = rng.range(20, 60);
        let mut entries = Vec::with_capacity(n);
        let started = base_time + c as i64 * 3_600_000;
        for m in 0..n {
            let role = if m % 2 == 0 { "user" } else { "assistant" };
            let len = if role == "user" {
                rng.range(200, 1500)
            } else {
                rng.range(1500, 4000)
            };
            let text = corpus.message(&mut rng, ((len as f64) * scale) as usize);
            text_bytes += text.len();
            let mut entry = Entry::new(author.clone(), "", started + m as i64 * 30_000);
            entry.extra.insert("role".into(), role.into());
            let parts = json!([{ "type": "text", "text": text }]).to_string();
            entry.extra.insert("parts".into(), parts.as_str().into());
            entries.push(entry);
        }
        messages += n;
        let name = corpus.title(&mut rng);
        let t = Instant::now();
        let chat = if c < n_append {
            let chat = chats::create_ai_chat(&node, &NoPush, &name).await.unwrap();
            for e in &entries {
                chats::append_entry(&node, &NoPush, &chat, e).await.unwrap();
            }
            append_s += t.elapsed().as_secs_f64();
            append_n += n;
            chat
        } else {
            let chat = chats::import_ai_chat(&node, &NoPush, &name, &entries)
                .await
                .unwrap();
            import_s += t.elapsed().as_secs_f64();
            import_n += n;
            chat
        };
        if n > longest.0 {
            longest = (n, chat);
        }
        if c % 100 == 99 {
            println!(
                "[seed] {} chats, {messages} messages, {:.0} MB text, RSS {:.0} MB, store {:.0} MB",
                c + 1,
                text_bytes as f64 / 1e6,
                rss_mb(),
                dir_size(&dir) as f64 / 1e6
            );
        }
    }
    println!(
        "[seed] {n_chats} chats, {messages} messages, {:.1} MB message text",
        text_bytes as f64 / 1e6
    );
    if append_n > 0 {
        println!(
            "[seed] append_entry: {append_n} messages in {append_s:.1} s = {:.1} ms/message",
            append_s * 1000.0 / append_n as f64
        );
    }
    if import_n > 0 {
        println!(
            "[seed] import_ai_chat: {import_n} messages in {import_s:.1} s = {:.0} messages/s, {:.1} MB/s",
            import_n as f64 / import_s,
            text_bytes as f64 / 1e6 * (import_n as f64 / messages as f64) / import_s
        );
    }
    std::fs::write(dir.join("stress-longest-chat"), &longest.1).unwrap();
    std::fs::write(dir.join("stress-work-drive"), &work).unwrap();

    // Let the recents listener catch up and write its file.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    recents.persist();
    store.flush().unwrap();
    println!(
        "[seed] store on disk: {:.1} MB (redb {:.1} MB)",
        dir_size(&dir) as f64 / 1e6,
        std::fs::metadata(dir.join("atomic.redb")).map_or(0, |m| m.len()) as f64 / 1e6
    );
}

// ── Measure ──────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "stress measure: reads the store stress_seed wrote"]
async fn stress_measure() {
    let dir = stress_dir();
    let mut table = Table::default();
    let rss_start = rss_mb();

    let recents = Arc::new(RecentsIndex::new());
    let t = Instant::now();
    let (store, steps) = open_like_the_app(&dir, &recents).await;
    let open = t.elapsed();
    let steps: Vec<String> = steps
        .iter()
        .map(|(name, d)| format!("{name} {} ms", ms(*d)))
        .collect();
    table.push("open_db (like the bridge)", vec![open], steps.join(", "));
    let secret = std::fs::read_to_string(dir.join("stress-agent-secret")).unwrap();
    let t = Instant::now();
    store.load_agent_from_secret(&secret).await.unwrap();
    table.push("load_agent (app start)", vec![t.elapsed()], String::new());
    let store_mb = dir_size(&dir) as f64 / 1e6;
    let longest = std::fs::read_to_string(dir.join("stress-longest-chat")).unwrap();
    let work = std::fs::read_to_string(dir.join("stress-work-drive")).unwrap();
    let home = store.private_drive_subject().unwrap();

    // (a) The chat list.
    for limit in [4usize, 50, 1000] {
        bench!(table, format!("list_ai_chats({limit})"), 20, async {
            let rows = lists::list_ai_chats(&store, &recents, limit).await.unwrap();
            let bytes = serde_json::to_string(&rows).unwrap().len();
            format!("{} rows, {:.1} KB JSON", rows.len(), bytes as f64 / 1024.0)
        });
    }
    // An index that lost track (no recents.json, or a lagged event stream):
    // the first list rescans every chat.
    bench!(table, "list_ai_chats(4), index rescan", 3, async {
        let fresh = RecentsIndex::new();
        let rows = lists::list_ai_chats(&store, &fresh, 4).await.unwrap();
        format!("{} rows", rows.len())
    });

    // (b) Search: type-ahead, every drive, then scoped.
    let rss_before_search = rss_mb();
    let queries = [
        "k", "ku", "kub", "kubernetes", "b", "bu", "bud", "budget", "s", "se", "sea", "search",
        "be", "ver", "vergadering", "steuer", "rés", "budget meeting", "kubernetes dep",
        CONTENT_ONLY, "tralinka",
    ];
    for q in queries {
        bench!(table, format!("search {q:?} (all drives, 20)"), 10, async {
            let rows = lists::search(&store, None, q, 20).unwrap();
            let chats = rows
                .iter()
                .filter(|r| r["class_name"].as_str().is_some_and(|c| c.contains("hat")))
                .count();
            format!("{} hits ({chats} chats)", rows.len())
        });
    }
    for q in ["b", "bud", "budget"] {
        bench!(table, format!("search {q:?} (Work drive, 20)"), 10, async {
            let rows = lists::search(&store, Some(&work), q, 20).unwrap();
            format!("{} hits", rows.len())
        });
        bench!(table, format!("search {q:?} (all drives, 100)"), 10, async {
            let rows = lists::search(&store, None, q, 100).unwrap();
            format!("{} hits", rows.len())
        });
        bench!(table, format!("search {q:?} (AI chats only, 20)"), 10, async {
            let opts = SearchOpts {
                limit: Some(20),
                filter_pairs: Some(vec![(urls::IS_A.to_string(), AI_CHAT.to_string())]),
                ..Default::default()
            };
            let hits = atomic_lib::search::query(&store, q, &opts).unwrap();
            format!("{} hits (index filter on isA)", hits.len())
        });
    }
    let rss_after_search = rss_mb();

    // (c) The other home lists.
    bench!(table, "list_recent_resources(home, 10)", 20, async {
        format!(
            "{} rows",
            lists::list_recent_resources(&store, &recents, &home, 10).await.len()
        )
    });
    bench!(table, "list_activity(30)", 20, async {
        format!(
            "{} rows",
            lists::list_activity(&store, &recents, &AgentProfiles::none(), None, 30)
                .await
                .len()
        )
    });
    bench!(table, "list_drives + order + rows", 20, async {
        let drives = store.list_drives().await.unwrap();
        let drives = lists::order_drives_by_use(&store, &recents, drives, |d| {
            (d.subject.as_str(), d.name.as_str())
        });
        for d in &drives {
            atomic_lib::host::rows::row_resource(&store, &Subject::from(d.subject.as_str())).await;
        }
        format!("{} drives", drives.len())
    });

    // (d) Opening a chat.
    bench!(table, "read_chat(longest)", 10, async {
        let entries = chats::read_chat(&store, &longest).await.unwrap();
        let bytes = serde_json::to_string(&entries).unwrap().len();
        format!(
            "{} messages, {:.0} KB JSON over FFI",
            entries.len(),
            bytes as f64 / 1024.0
        )
    });
    let rss_end = rss_mb();

    // (e) Size and memory.
    let redb_mb = std::fs::metadata(dir.join("atomic.redb")).map_or(0, |m| m.len()) as f64 / 1e6;
    let recents_kb = std::fs::metadata(dir.join("recents.json")).map_or(0, |m| m.len()) as f64 / 1e3;
    table.print();
    println!(
        "\nstore {store_mb:.1} MB (redb {redb_mb:.1} MB, recents.json {recents_kb:.1} KB); \
         RSS start {rss_start:.0} MB, after open+lists {rss_before_search:.0} MB, \
         after search {rss_after_search:.0} MB, end {rss_end:.0} MB"
    );

    if std::env::var("STRESS_REBUILD").is_ok() {
        let t = Instant::now();
        atomic_lib::search::rebuild_search_index(&store).unwrap();
        println!(
            "full search index rebuild (first start after an upgrade): {:.1} s",
            t.elapsed().as_secs_f64()
        );
    }
}

/// Opening the seeded store three times in one process, each closed cleanly
/// before the next: what `Database::create` costs on a clean file, apart
/// from repair after an unclean exit.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "stress: reopens the store stress_seed wrote"]
async fn stress_reopen() {
    let dir = stress_dir();
    if std::env::var("STRESS_LOG").is_ok() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .try_init();
    }
    println!("[reopen] RSS before {:.0} MB", rss_mb());
    for i in 0..3 {
        let check = atomic_lib::db::recovery::inspect(&dir.join("atomic.redb"));
        println!("[reopen] before open {i}: {check:?}");
        let t = Instant::now();
        let policy = if std::env::var("STRESS_NO_COMPACTION").is_ok() {
            atomic_lib::db::compaction::CompactionPolicy::disabled()
        } else {
            Default::default()
        };
        let store = Db::init_redb_file_with_policy(&dir, None, &dir.join("uploads"), &policy)
            .await
            .expect("open store");
        let open = t.elapsed();
        let t = Instant::now();
        store.flush().unwrap();
        drop(store);
        println!(
            "[reopen] open {i}: {} ms (close {} ms), RSS {:.0} MB",
            ms(open),
            ms(t.elapsed()),
            rss_mb()
        );
    }
}
