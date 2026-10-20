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
    "the",
    "of",
    "and",
    "to",
    "in",
    "is",
    "that",
    "for",
    "it",
    "as",
    "with",
    "be",
    "on",
    "not",
    "this",
    "but",
    "by",
    "from",
    "they",
    "we",
    "you",
    "can",
    "will",
    "which",
    "would",
    "there",
    "their",
    "what",
    "about",
    "when",
    "your",
    "make",
    "like",
    "time",
    "just",
    "know",
    "take",
    "people",
    "into",
    "year",
    "good",
    "some",
    "could",
    "them",
    "see",
    "other",
    "than",
    "then",
    "now",
    "look",
    "only",
    "come",
    "over",
    "think",
    "also",
    "back",
    "after",
    "use",
    "two",
    "how",
    "work",
    "first",
    "well",
    "way",
    "even",
    "new",
    "want",
    "because",
    "any",
    "these",
    "give",
    "day",
    "most",
    "budget",
    "recipe",
    "travel",
    "garden",
    "invoice",
    "meeting",
    "project",
    "server",
    "database",
    "kubernetes",
    "deployment",
    "migration",
    "schema",
    "frontend",
    "backend",
    "latency",
    "throughput",
    "memory",
    "search",
    "index",
    "query",
    "cache",
    "summary",
    "proposal",
    "strategy",
    "customer",
    "contract",
    "holiday",
    "bicycle",
    "kitchen",
    "weather",
    "mountain",
    "library",
    "history",
    "physics",
    "chemistry",
    "guitar",
    "marathon",
];
const NL: &[&str] = &[
    "de",
    "het",
    "een",
    "en",
    "van",
    "ik",
    "te",
    "dat",
    "die",
    "in",
    "is",
    "niet",
    "op",
    "aan",
    "met",
    "als",
    "voor",
    "maar",
    "om",
    "ook",
    "nog",
    "wel",
    "naar",
    "dan",
    "kan",
    "zijn",
    "bij",
    "wordt",
    "moet",
    "hebben",
    "gemeente",
    "fiets",
    "boodschappen",
    "vergadering",
    "begroting",
    "afspraak",
    "verjaardag",
    "huiswerk",
    "zomervakantie",
    "belasting",
    "verzekering",
    "aanvraag",
    "onderzoek",
    "samenvatting",
    "gezondheid",
    "werkgever",
    "ontwikkeling",
];
const DE: &[&str] = &[
    "der",
    "die",
    "und",
    "in",
    "den",
    "von",
    "zu",
    "das",
    "mit",
    "sich",
    "des",
    "auf",
    "für",
    "ist",
    "im",
    "nicht",
    "ein",
    "eine",
    "als",
    "auch",
    "werden",
    "Rechnung",
    "Wohnung",
    "Steuererklärung",
    "Krankenversicherung",
    "Bahnhof",
    "Wanderung",
    "Zusammenfassung",
    "Anleitung",
    "Überweisung",
    "Grundstück",
    "Straßenbahn",
    "Fußgängerzone",
];
const FR: &[&str] = &[
    "le",
    "la",
    "les",
    "de",
    "des",
    "et",
    "un",
    "une",
    "du",
    "en",
    "est",
    "que",
    "pour",
    "dans",
    "qui",
    "pas",
    "sur",
    "plus",
    "avec",
    "être",
    "réunion",
    "facture",
    "logement",
    "voyage",
    "recette",
    "déménagement",
    "élève",
    "université",
    "boulangerie",
    "randonnée",
    "théâtre",
];
const ES: &[&str] = &[
    "el",
    "la",
    "de",
    "que",
    "y",
    "en",
    "un",
    "los",
    "se",
    "del",
    "las",
    "por",
    "con",
    "una",
    "para",
    "como",
    "más",
    "pero",
    "reunión",
    "factura",
    "vivienda",
    "viaje",
    "receta",
    "mañana",
    "niño",
    "año",
    "español",
    "biblioteca",
    "presupuesto",
    "cumpleaños",
];
const CODE: &[&str] = &[
    "fn",
    "let",
    "mut",
    "impl",
    "struct",
    "async",
    "await",
    "return",
    "match",
    "Some",
    "None",
    "Ok",
    "Err",
    "const",
    "def",
    "self",
    "import",
    "from",
    "class",
    "function",
    "export",
    "interface",
    "type",
    "string",
    "number",
    "Vec",
    "HashMap",
    "Result",
    "Option",
    "unwrap",
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
        if times.is_empty() {
            return;
        }
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
async fn open_like_the_app(
    dir: &Path,
    recents: &Arc<RecentsIndex>,
) -> (Db, Vec<(String, Duration)>) {
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
    while atomic_lib::search::index_pending(&store, 500)
        .await
        .unwrap()
        > 0
    {}
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
    std::fs::write(
        dir.join("stress-agent-secret"),
        agent.build_secret().unwrap(),
    )
    .unwrap();
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
        let body = corpus
            .message(&mut rng, len)
            .replace(CONTENT_ONLY, "quokka");
        doc_bytes += body.len();
        let mut r = store
            .get_resource(&Subject::from(subject.as_str()))
            .await
            .unwrap();
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
        "k",
        "ku",
        "kub",
        "kubernetes",
        "b",
        "bu",
        "bud",
        "budget",
        "s",
        "se",
        "sea",
        "search",
        "be",
        "ver",
        "vergadering",
        "steuer",
        "rés",
        "budget meeting",
        "kubernetes dep",
        CONTENT_ONLY,
        "tralinka",
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
        bench!(
            table,
            format!("search {q:?} (all drives, 100)"),
            10,
            async {
                let rows = lists::search(&store, None, q, 100).unwrap();
                format!("{} hits", rows.len())
            }
        );
        bench!(
            table,
            format!("search {q:?} (AI chats only, 20)"),
            10,
            async {
                let opts = SearchOpts {
                    limit: Some(20),
                    filter_pairs: Some(vec![(urls::IS_A.to_string(), AI_CHAT.to_string())]),
                    ..Default::default()
                };
                let hits = atomic_lib::search::query(&store, q, &opts).unwrap();
                format!("{} hits (index filter on isA)", hits.len())
            }
        );
    }
    let rss_after_search = rss_mb();

    // (c) The other home lists.
    bench!(table, "list_recent_resources(home, 10)", 20, async {
        format!(
            "{} rows",
            lists::list_recent_resources(&store, &recents, &home, 10)
                .await
                .len()
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
    let recents_kb =
        std::fs::metadata(dir.join("recents.json")).map_or(0, |m| m.len()) as f64 / 1e3;
    table.print();
    println!(
        "\nstore {store_mb:.1} MB (redb {redb_mb:.1} MB, recents.json {recents_kb:.1} KB); \
         RSS start {rss_start:.0} MB, after open+lists {rss_before_search:.0} MB, \
         after search {rss_after_search:.0} MB, end {rss_end:.0} MB"
    );

    if std::env::var("STRESS_TREES").is_ok() {
        use atomic_lib::db::trees::Tree;
        println!("\n| tree | entries | keys MB | values MB (uncompressed) |\n|---|---:|---:|---:|");
        for tree in [
            Tree::Resources,
            Tree::LoroSnapshots,
            Tree::Envelopes,
            Tree::Outbox,
            Tree::PropValSub,
            Tree::ValPropSub,
            Tree::QueryMembers,
            Tree::SearchPostings,
            Tree::SearchDocs,
            Tree::SearchTrigrams,
            Tree::DidMapping,
            Tree::PluginMeta,
        ] {
            let (mut n, mut keys, mut values) = (0usize, 0usize, 0usize);
            for pair in store.kv.iter_tree(tree) {
                let (k, v) = pair.unwrap();
                n += 1;
                keys += k.len();
                values += v.len();
            }
            println!(
                "| {tree:?} | {n} | {:.1} | {:.1} |",
                keys as f64 / 1e6,
                values as f64 / 1e6
            );
        }
    }

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

// ── One very long chat ───────────────────────────────────────────────────

/// A short chat line, about 120 characters on average: mostly a sentence or
/// two, one in twenty a few paragraphs.
fn short_message(corpus: &Corpus, rng: &mut Rng) -> String {
    let len = if rng.below(20) == 0 {
        rng.range(300, 1000)
    } else {
        rng.range(20, 160)
    };
    corpus.message(rng, len)
}

/// The free space of the volume that holds `dir`, in MB.
fn free_mb(dir: &Path) -> u64 {
    let out = std::process::Command::new("df")
        .args(["-k", &dir.to_string_lossy()])
        .output()
        .ok();
    out.and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| {
            s.lines()
                .nth(1)?
                .split_whitespace()
                .nth(3)?
                .parse::<u64>()
                .ok()
        })
        .map_or(u64::MAX, |kb| kb / 1024)
}

/// Seed one AI chat and one chat room with `STRESS_LONG` (200 000) messages
/// each through the bulk import (one commit per 256-entry page), and one
/// end-to-end encrypted conversation with `STRESS_LONG_CONV` (20 000)
/// messages, sent one by one as the app does. Writes `long-chat-ids`.
async fn seed_long_chats(dir: &Path) {
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir).unwrap();
    assert!(free_mb(dir) > 3000, "less than 3 GB free: not seeding");
    let n = env_usize("STRESS_LONG", 200_000);
    let n_conv = env_usize("STRESS_LONG_CONV", 20_000);
    let recents = Arc::new(RecentsIndex::new());
    let (store, _) = open_like_the_app(dir, &recents).await;
    let (agent, home) = store.setup("Stress device").await.unwrap();
    std::fs::write(
        dir.join("stress-agent-secret"),
        agent.build_secret().unwrap(),
    )
    .unwrap();
    let node = AtomicNode::from_db(store.clone());
    let author = agent.subject.to_string();
    let other = atomic_lib::agents::Agent::new(Some("Other")).unwrap();
    store
        .add_resource(&other.to_resource().unwrap())
        .await
        .unwrap();
    let corpus = Corpus::new();
    let mut rng = Rng(7);
    let base = 1_700_000_000_000i64;

    let make = |rng: &mut Rng, ai: bool| -> (Vec<Entry>, usize) {
        let mut bytes = 0;
        let entries = (0..n)
            .map(|i| {
                let text = short_message(&corpus, rng);
                bytes += text.len();
                // Every other line from someone else, in a room.
                let who = if !ai && i % 2 == 1 {
                    other.subject.to_string()
                } else {
                    author.clone()
                };
                let mut e = Entry::new(who, "", base + i as i64 * 20_000);
                if ai {
                    let role = if i % 2 == 0 { "user" } else { "assistant" };
                    e.extra.insert("role".into(), role.into());
                    let parts = json!([{ "type": "text", "text": text }]).to_string();
                    e.extra.insert("parts".into(), parts.as_str().into());
                } else {
                    e.text = text;
                }
                e
            })
            .collect();
        (entries, bytes)
    };

    let t = Instant::now();
    let (entries, bytes) = make(&mut rng, true);
    let ai_chat = chats::import_ai_chat(&node, &NoPush, "Very long AI chat", &entries)
        .await
        .unwrap();
    println!(
        "[seed] AI chat: {n} messages, {:.1} MB text, {:.1} s, store {:.0} MB",
        bytes as f64 / 1e6,
        t.elapsed().as_secs_f64(),
        dir_size(dir) as f64 / 1e6
    );
    drop(entries);

    let t = Instant::now();
    let room = store
        .create_resource(urls::CHATROOM, &home, "Very long room", None)
        .await
        .unwrap();
    let (entries, bytes) = make(&mut rng, false);
    chats::import_entries(&node, &NoPush, &room, &entries)
        .await
        .unwrap();
    println!(
        "[seed] chat room: {n} messages, {:.1} MB text, {:.1} s, store {:.0} MB",
        bytes as f64 / 1e6,
        t.elapsed().as_secs_f64(),
        dir_size(dir) as f64 / 1e6
    );
    drop(entries);

    // An encrypted conversation between this agent and `other`.
    use atomic_lib::conversation::{encryption_public_key, Keyring, Member};
    use atomic_lib::host::conversations::vault_proof;
    let (my_proof, other_proof) = (vault_proof(&agent).unwrap(), vault_proof(&other).unwrap());
    let mut keyring = Keyring::default();
    keyring
        .add_epoch(&[
            Member {
                agent: agent.subject.to_string(),
                encryption_key: encryption_public_key(&my_proof),
            },
            Member {
                agent: other.subject.to_string(),
                encryption_key: encryption_public_key(&other_proof),
            },
        ])
        .unwrap();
    let mut builder = atomic_lib::commit::CommitBuilder::new("placeholder".into());
    builder.set(
        urls::IS_A.into(),
        atomic_lib::Value::ResourceArray(vec![urls::CONVERSATION.into(), urls::DRIVE.into()]),
    );
    builder.set(
        urls::NAME.into(),
        atomic_lib::Value::String("Conversation".into()),
    );
    builder.set(
        urls::READ.into(),
        atomic_lib::Value::ResourceArray(vec![
            agent.subject.to_string().into(),
            other.subject.to_string().into(),
        ]),
    );
    builder.set(
        urls::CONVERSATION_KEYS.into(),
        atomic_lib::Value::String(keyring.to_json().unwrap()),
    );
    let commit = atomic_lib::Commit::create_did(builder, &agent, &store)
        .await
        .unwrap();
    let conversation = commit.subject.to_string();
    node.apply_local_commit(commit, &atomic_lib::host::own_commit_opts())
        .await
        .unwrap();
    let mut drive = store
        .get_resource(&Subject::from(home.as_str()))
        .await
        .unwrap();
    drive
        .set_unsafe(
            urls::CONVERSATIONS.into(),
            atomic_lib::Value::ResourceArray(vec![conversation.as_str().into()]),
        )
        .unwrap();
    node.save_locally(&mut drive).await.unwrap();
    let t = Instant::now();
    for i in 0..n_conv {
        let text = short_message(&corpus, &mut rng);
        atomic_lib::host::conversations::send_message(&node, &NoPush, &conversation, &text)
            .await
            .unwrap();
        if i % 5000 == 4999 {
            println!(
                "[seed] conversation: {} messages, {:.1} ms/message",
                i + 1,
                t.elapsed().as_secs_f64() * 1000.0 / (i + 1) as f64
            );
        }
    }
    println!(
        "[seed] conversation: {n_conv} messages in {:.1} s, store {:.0} MB",
        t.elapsed().as_secs_f64(),
        dir_size(dir) as f64 / 1e6
    );
    std::fs::write(
        dir.join("long-chat-ids"),
        format!("{ai_chat}\n{room}\n{conversation}\n"),
    )
    .unwrap();
    tokio::time::sleep(Duration::from_millis(1500)).await;
    recents.persist();
    store.flush().unwrap();
}

/// One chat of each kind with 200 000 messages (a conversation with 20 000):
/// opening, appending, the recents rescan, search and the store size.
///
/// ```text
/// STRESS_DIR=<scratch>/long cargo test -p atomic_lib --features db-redb --profile e2e \
///   --test stress_chats -- --ignored --nocapture stress_long_chat
/// ```
///
/// Seeds the store the first time (when `long-chat-ids` is missing; knobs
/// `STRESS_LONG`, `STRESS_LONG_CONV`), then measures it in a fresh open.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "stress: seeds and measures one very long chat of each kind"]
async fn stress_long_chat() {
    let dir = stress_dir();
    if !dir.join("long-chat-ids").exists() {
        seed_long_chats(&dir).await;
    }
    let ids = std::fs::read_to_string(dir.join("long-chat-ids")).unwrap();
    let mut ids = ids.lines();
    let (ai_chat, room, conversation) = (
        ids.next().unwrap().to_string(),
        ids.next().unwrap().to_string(),
        ids.next().unwrap().to_string(),
    );
    let mut table = Table::default();
    let recents = Arc::new(RecentsIndex::new());
    let rss_start = rss_mb();
    let (store, _) = open_like_the_app(&dir, &recents).await;
    let secret = std::fs::read_to_string(dir.join("stress-agent-secret")).unwrap();
    store.load_agent_from_secret(&secret).await.unwrap();
    let node = AtomicNode::from_db(store.clone());
    let rooms = atomic_lib::host::chat_rooms::ChatRooms::new(AgentProfiles::none());
    let convos = atomic_lib::host::conversations::Conversations::new(AgentProfiles::none());
    let rss_open = rss_mb();
    let json_kb =
        |rows: &Vec<serde_json::Value>| serde_json::to_string(rows).unwrap().len() as f64 / 1024.0;

    // Opening in windows: the newest 50, then 20 windows back, then a poll.
    let window_kb = |w: &serde_json::Value, field: &str| {
        let n = w[field].as_array().map_or(0, Vec::len);
        (n, serde_json::to_string(w).unwrap().len() as f64 / 1024.0)
    };
    let rss = rss_mb();
    let decodes = chats::page_decodes();
    bench!(
        table,
        "open AI chat: read_chat_page(newest 50)",
        10,
        async {
            let w = chats::read_chat_page(&store, &ai_chat, None, 50)
                .await
                .unwrap();
            let (n, kb) = window_kb(&w, "entries");
            format!("{n} messages, {kb:.0} KB JSON")
        }
    );
    println!(
        "[long] read_chat_page: {:.1} page decodes per window",
        (chats::page_decodes() - decodes) as f64 / 10.0
    );
    let first = chats::read_chat_page(&store, &ai_chat, None, 50)
        .await
        .unwrap();
    let mut cursor = first["older"].as_str().unwrap().to_string();
    let newest = first["newest"].as_str().unwrap().to_string();
    bench!(
        table,
        "scroll up AI chat: next older window of 50",
        20,
        async {
            let w = chats::read_chat_page(&store, &ai_chat, Some(&cursor), 50)
                .await
                .unwrap();
            cursor = w["older"].as_str().unwrap().to_string();
            format!("{} messages", w["entries"].as_array().unwrap().len())
        }
    );
    bench!(table, "poll AI chat: read_chat_after(newest)", 10, async {
        let w = chats::read_chat_after(&store, &ai_chat, &newest, 100)
            .await
            .unwrap();
        format!("{} new", w["entries"].as_array().unwrap().len())
    });
    let rss_ai_window = rss_mb() - rss;
    let rss = rss_mb();
    bench!(
        table,
        "open room: ChatRooms::read_page(newest 50)",
        10,
        async {
            let w = rooms.read_page(&store, &room, None, 50).await.unwrap();
            let (n, kb) = window_kb(&w, "messages");
            format!("{n} messages, {kb:.0} KB JSON")
        }
    );
    let first = rooms.read_page(&store, &room, None, 50).await.unwrap();
    let mut cursor = first["older"].as_str().unwrap().to_string();
    bench!(
        table,
        "scroll up room: next older window of 50",
        20,
        async {
            let w = rooms
                .read_page(&store, &room, Some(&cursor), 50)
                .await
                .unwrap();
            cursor = w["older"].as_str().unwrap().to_string();
            format!("{} messages", w["messages"].as_array().unwrap().len())
        }
    );
    let rss_room_window = rss_mb() - rss;
    let rss = rss_mb();
    let fresh = atomic_lib::host::conversations::Conversations::new(AgentProfiles::none());
    bench!(
        table,
        "open conversation: read_page(newest 50)",
        10,
        async {
            let w = fresh
                .read_page(&store, &conversation, None, 50)
                .await
                .unwrap();
            let (n, kb) = window_kb(&w, "messages");
            format!("{n} messages, {kb:.0} KB JSON")
        }
    );
    let first = fresh
        .read_page(&store, &conversation, None, 50)
        .await
        .unwrap();
    let mut cursor = first["older"].as_str().unwrap().to_string();
    bench!(
        table,
        "scroll up conversation: next older window of 50",
        20,
        async {
            let w = fresh
                .read_page(&store, &conversation, Some(&cursor), 50)
                .await
                .unwrap();
            cursor = w["older"].as_str().unwrap().to_string();
            format!("{} messages", w["messages"].as_array().unwrap().len())
        }
    );
    let rss_conv_window = rss_mb() - rss;
    println!(
        "[long] RSS growth in windows: AI chat {rss_ai_window:.0} MB, room \
         {rss_room_window:.0} MB, conversation {rss_conv_window:.0} MB"
    );

    // Opening the old way, every message at once (STRESS_LONG_FULL=0 skips).
    let reps = env_usize("STRESS_LONG_REPS", 3);
    let full = std::env::var("STRESS_LONG_FULL").map_or(true, |v| v != "0");
    let rss = rss_mb();
    bench!(
        table,
        "open AI chat: read_chat (all)",
        if full { reps } else { 0 },
        async {
            let rows = chats::read_chat(&store, &ai_chat).await.unwrap();
            format!("{} messages, {:.0} KB JSON", rows.len(), json_kb(&rows))
        }
    );
    let rss_ai = rss_mb() - rss;
    let rss = rss_mb();
    bench!(
        table,
        "open room: ChatRooms::read (all)",
        if full { reps } else { 0 },
        async {
            let rows = rooms.read(&store, &room).await.unwrap();
            format!("{} messages, {:.0} KB JSON", rows.len(), json_kb(&rows))
        }
    );
    let rss_room = rss_mb() - rss;
    let rss = rss_mb();
    bench!(
        table,
        "open conversation: Conversations::read (all)",
        if full { reps } else { 0 },
        async {
            let rows = convos.read(&store, &conversation).await.unwrap();
            format!("{} messages, {:.0} KB JSON", rows.len(), json_kb(&rows))
        }
    );
    let rss_conv = rss_mb() - rss;
    bench!(table, "conversations list(10) (newest message)", 5, async {
        let rows = convos.list(&store, 10).await.unwrap();
        format!("{} rows", rows.len())
    });

    // Appending one message at the end.
    for (name, chat) in [("AI chat", &ai_chat), ("room", &room)] {
        let decodes = chats::page_decodes();
        store.reset_fetch_counters();
        let appends = 10;
        bench!(
            table,
            format!("append one message ({name})"),
            appends,
            async {
                let e = Entry::new(
                    store.get_default_agent().unwrap().subject.to_string(),
                    "One more line",
                    atomic_lib::utils::now(),
                );
                chats::append_entry(&node, &NoPush, chat, &e).await.unwrap();
                String::new()
            }
        );
        println!(
            "[long] append ({name}): {:.1} page decodes and {:.1} full get_resource per message",
            (chats::page_decodes() - decodes) as f64 / appends as f64,
            store.get_resource_call_count() as f64 / appends as f64
        );
    }
    bench!(table, "send one conversation message", 10, async {
        atomic_lib::host::conversations::send_message(&node, &NoPush, &conversation, "One more")
            .await
            .unwrap();
        String::new()
    });

    // The recents index: a rescan reads each chat's last activity.
    bench!(
        table,
        "chat_last_activity (recents rescan, per chat)",
        3,
        async {
            let at = chats::chat_last_activity(&store, &ai_chat).await.unwrap();
            format!("last {at}")
        }
    );
    bench!(table, "search \"b\" (all drives, 20)", 10, async {
        format!(
            "{} hits",
            lists::search(&store, None, "b", 20).unwrap().len()
        )
    });

    table.print();
    let redb_mb = std::fs::metadata(dir.join("atomic.redb")).map_or(0, |m| m.len()) as f64 / 1e6;
    println!(
        "\nstore {:.0} MB (redb {redb_mb:.0} MB); RSS start {rss_start:.0} MB, after open \
         {rss_open:.0} MB, end {:.0} MB; RSS growth reading all: AI chat {rss_ai:.0} MB, room \
         {rss_room:.0} MB, conversation {rss_conv:.0} MB",
        dir_size(&dir) as f64 / 1e6,
        rss_mb()
    );
}
