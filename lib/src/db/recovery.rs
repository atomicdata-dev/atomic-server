//! Opening a redb file that may be damaged, without losing it.
//!
//! redb is crash-safe as long as one handle writes the file. A second handle
//! on a file that is still open (the Flutter app re-ran `open_db` in the same
//! process when Android recreated its activity, and the file lock did not
//! keep it out) trims the file to what it believes is free when dropped,
//! while the first handle later writes its own, longer, layout into the
//! header. After the next kill the header describes more file than there is
//! and redb's open *panics* (`raw_file_len >= header.layout().len()`).
//!
//! This module holds the pieces a host needs to come back from that: a
//! process-wide guard so one process never opens a file twice, a look at the
//! header without redb, setting a broken file aside (never deleting it), and
//! repairing a copy of it.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use redb::{Database, ReadableDatabase, ReadableTable, TableHandle};

use crate::errors::AtomicResult;

/// What a damaged store's open error says. `is_damaged_store_error` looks
/// for it, and for redb's own "corrupt" wording.
pub const DAMAGED_STORE: &str = "store file is damaged";

/// Whether an open error means the file itself is damaged, as opposed to a
/// lock held by someone else, a permission problem or a missing directory,
/// which are no reason to set the user's data aside.
pub fn is_damaged_store_error(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains(DAMAGED_STORE) || lower.contains("corrupt")
}

static OPEN_FILES: Mutex<Option<HashSet<PathBuf>>> = Mutex::new(None);

/// One process, one handle per store file. redb's own `flock` is not there
/// on every platform: Rust 1.95's standard library has no file lock on
/// Android (1.98's has), and redb then opens a second handle silently, which
/// is how the Flutter app damaged its store. Dropping the guard frees the path.
#[derive(Debug)]
pub struct OpenFileGuard(PathBuf);

impl OpenFileGuard {
    pub fn acquire(path: &Path) -> AtomicResult<Self> {
        let key = canonical(path);
        let mut open = OPEN_FILES.lock().unwrap_or_else(|e| e.into_inner());
        let set = open.get_or_insert_with(HashSet::new);
        if !set.insert(key.clone()) {
            return Err(format!(
                "The store {} is already open in this process; a second handle would damage it",
                path.display()
            )
            .into());
        }
        Ok(OpenFileGuard(key))
    }
}

impl Drop for OpenFileGuard {
    fn drop(&mut self) {
        let mut open = OPEN_FILES.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(set) = open.as_mut() {
            set.remove(&self.0);
        }
    }
}

/// The path with its directory resolved, so two spellings of one file meet.
/// The file itself may not exist yet.
fn canonical(path: &Path) -> PathBuf {
    if let Ok(p) = path.canonicalize() {
        return p;
    }
    match (path.parent(), path.file_name()) {
        (Some(dir), Some(name)) => dir
            .canonicalize()
            .map(|d| d.join(name))
            .unwrap_or_else(|_| path.to_path_buf()),
        _ => path.to_path_buf(),
    }
}

/// `Database::create`, with redb's panics on a damaged file turned into an
/// error that says so.
pub fn create_database(path: &Path) -> AtomicResult<Database> {
    create_database_with_cache(path, None)
}

/// redb's own read cache default (`Builder::new`): 1 GiB.
pub const DEFAULT_CACHE_BYTES: usize = 1024 * 1024 * 1024;

/// The builder [`create_database_with_cache`] opens with: redb's defaults,
/// with the read cache at `cache_bytes` when given. A server wants the
/// default (the whole working set stays cached); a phone wants tens of MiB,
/// or whatever it reads stays in memory up to the store's size.
pub fn database_builder(cache_bytes: Option<usize>) -> (redb::Builder, usize) {
    let mut builder = Database::builder();
    let bytes = cache_bytes.unwrap_or(DEFAULT_CACHE_BYTES);
    if cache_bytes.is_some() {
        builder.set_cache_size(bytes);
    }
    (builder, bytes)
}

/// [`create_database`] with the read cache at `cache_bytes` (redb's 1 GiB
/// default when `None`).
pub fn create_database_with_cache(
    path: &Path,
    cache_bytes: Option<usize>,
) -> AtomicResult<Database> {
    let (builder, _) = database_builder(cache_bytes);
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| builder.create(path))) {
        Ok(Ok(db)) => Ok(db),
        Ok(Err(e)) if is_damage(&e) => Err(format!(
            "The {DAMAGED_STORE}: redb could not read {}: {e}",
            path.display()
        )
        .into()),
        Ok(Err(e)) => Err(format!("Failed to create redb at {}: {e}", path.display()).into()),
        Err(panic) => Err(format!(
            "The {DAMAGED_STORE}: redb panicked opening {}: {}",
            path.display(),
            panic_message(&panic)
        )
        .into()),
    }
}

/// redb's errors for a file that is not (or no longer) a readable store:
/// a checksum or format failure, a wrong magic number (`InvalidData`) or a
/// file that ends early. A lock or a permission problem is not damage.
fn is_damage(e: &redb::DatabaseError) -> bool {
    match e {
        redb::DatabaseError::Storage(redb::StorageError::Corrupted(_)) => true,
        redb::DatabaseError::Storage(redb::StorageError::Io(io)) => matches!(
            io.kind(),
            std::io::ErrorKind::InvalidData | std::io::ErrorKind::UnexpectedEof
        ),
        _ => false,
    }
}

pub fn panic_message(panic: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = panic.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = panic.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic".to_string()
    }
}

/// The redb file header, read without redb (which panics on the damage this
/// is for).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileCheck {
    pub file_len: u64,
    /// The length the header's layout describes.
    pub layout_len: u64,
    pub page_size: u32,
    /// Set while a handle has the file open; still set after a kill.
    pub recovery_required: bool,
}

impl FileCheck {
    /// The header describes more file than there is: the damage above.
    pub fn is_short(&self) -> bool {
        self.file_len < self.layout_len
    }
}

const MAGIC: [u8; 9] = [b'r', b'e', b'd', b'b', 0x1A, 0x0A, 0xA9, 0x0D, 0x0A];

/// `None` when the file is missing, empty or not a redb file.
pub fn inspect(path: &Path) -> std::io::Result<Option<FileCheck>> {
    use std::io::Read;
    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let file_len = file.metadata()?.len();
    let mut header = [0u8; 32];
    if file_len < header.len() as u64 {
        return Ok(None);
    }
    file.read_exact(&mut header)?;
    if header[..MAGIC.len()] != MAGIC {
        return Ok(None);
    }
    let u32_at = |o: usize| u32::from_le_bytes(header[o..o + 4].try_into().unwrap());
    let page_size = u32_at(12);
    let region_header_pages = u64::from(u32_at(16));
    let region_max_data_pages = u64::from(u32_at(20));
    let full_regions = u64::from(u32_at(24));
    let trailing_pages = u64::from(u32_at(28));
    let ps = u64::from(page_size);
    let trailing = if trailing_pages > 0 {
        (region_header_pages + trailing_pages) * ps
    } else {
        0
    };
    let layout_len =
        ps + full_regions * (region_header_pages + region_max_data_pages) * ps + trailing;
    Ok(Some(FileCheck {
        file_len,
        layout_len,
        page_size,
        recovery_required: header[9] & 2 != 0,
    }))
}

/// Rename a store that cannot be opened to `<name>.corrupt-<unix ms>` next
/// to it, and return the new path. Never deletes: the file is the user's
/// data and the only evidence of what went wrong.
pub fn set_aside(path: &Path) -> std::io::Result<PathBuf> {
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "store".into());
    let mut kept = path.with_file_name(format!("{name}.corrupt-{ms}"));
    let mut n = 1;
    while kept.exists() {
        kept = path.with_file_name(format!("{name}.corrupt-{ms}-{n}"));
        n += 1;
    }
    std::fs::rename(path, &kept)?;
    Ok(kept)
}

/// Try to bring a damaged store back as `dest`, working on a copy so
/// `broken` stays as it is. A file shorter than its header is extended
/// with zeroes to the length the header describes; redb then repairs it,
/// falling back to the previous commit when the newest one's pages are
/// gone. Every table is read through to check the result. On failure
/// `dest` is removed (it is only the copy) and the error says why.
pub fn repair_copy(broken: &Path, dest: &Path) -> AtomicResult<()> {
    let result = (|| -> AtomicResult<()> {
        std::fs::copy(broken, dest)
            .map_err(|e| format!("Could not copy {}: {e}", broken.display()))?;
        if let Some(check) = inspect(dest)? {
            if check.is_short() {
                let f = std::fs::OpenOptions::new().write(true).open(dest)?;
                f.set_len(check.layout_len)?;
                f.sync_all()?;
            }
        }
        let db = create_database(dest)?;
        verify_readable(&db)?;
        drop(db);
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(dest);
    }
    result
}

/// Read every row of every table (all of ours are `&[u8] -> &[u8]`); a
/// damaged page fails or panics here rather than later in the app.
pub fn verify_readable(db: &Database) -> AtomicResult<()> {
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let tx = db.begin_read().map_err(|e| e.to_string())?;
        for handle in tx.list_tables().map_err(|e| e.to_string())? {
            let def = redb::TableDefinition::<&[u8], &[u8]>::new(handle.name());
            let table = tx.open_table(def).map_err(|e| e.to_string())?;
            for row in table.iter().map_err(|e| e.to_string())? {
                let (k, v) = row.map_err(|e| e.to_string())?;
                std::hint::black_box((k.value().len(), v.value().len()));
            }
        }
        Ok::<(), String>(())
    }));
    match outcome {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(format!("The {DAMAGED_STORE}: {e}").into()),
        Err(panic) => Err(format!("The {DAMAGED_STORE}: {}", panic_message(&panic)).into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "atomic-recovery-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_second_open_of_one_file_in_one_process_is_refused() {
        let dir = temp_dir("guard");
        let path = dir.join("atomic.redb");
        let first = OpenFileGuard::acquire(&path).unwrap();
        // Another spelling of the same file.
        let other = dir.join(".").join("atomic.redb");
        assert!(OpenFileGuard::acquire(&other).is_err());
        drop(first);
        OpenFileGuard::acquire(&other).unwrap();
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn inspect_reads_the_layout_of_a_healthy_store() {
        let dir = temp_dir("inspect");
        let path = dir.join("atomic.redb");
        drop(Database::create(&path).unwrap());
        let check = inspect(&path).unwrap().unwrap();
        assert_eq!(check.layout_len, check.file_len, "{check:?}");
        assert!(!check.is_short());
        assert!(!check.recovery_required, "a clean close clears the flag");
        assert_eq!(inspect(&dir.join("missing.redb")).unwrap(), None);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn the_cache_size_option_is_applied_and_the_default_kept() {
        assert_eq!(database_builder(None).1, DEFAULT_CACHE_BYTES);
        assert_eq!(database_builder(Some(48 << 20)).1, 48 << 20);
    }

    #[test]
    fn a_store_far_bigger_than_its_cache_still_reads_back() {
        let dir = temp_dir("small-cache");
        let path = dir.join("atomic.redb");
        let table = redb::TableDefinition::<&[u8], &[u8]>::new("t");
        // 1 MiB of cache for 16 MiB of data: reads must go to the file.
        let db = create_database_with_cache(&path, Some(1 << 20)).unwrap();
        let tx = db.begin_write().unwrap();
        {
            let mut t = tx.open_table(table).unwrap();
            for k in 0..64u32 {
                t.insert(
                    k.to_be_bytes().as_slice(),
                    vec![k as u8; 256 * 1024].as_slice(),
                )
                .unwrap();
            }
        }
        tx.commit().unwrap();
        let tx = db.begin_read().unwrap();
        let t = tx.open_table(table).unwrap();
        for k in 0..64u32 {
            let v = t.get(k.to_be_bytes().as_slice()).unwrap().unwrap();
            assert!(v.value().iter().all(|b| *b == k as u8));
        }
        drop(t);
        drop(tx);
        drop(db);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn set_aside_keeps_the_file_under_a_new_name() {
        let dir = temp_dir("aside");
        let path = dir.join("atomic.redb");
        std::fs::write(&path, b"broken").unwrap();
        let kept = set_aside(&path).unwrap();
        assert!(!path.exists());
        assert_eq!(std::fs::read(&kept).unwrap(), b"broken");
        assert!(kept
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("atomic.redb.corrupt-"));
        std::fs::write(&path, b"again").unwrap();
        let kept2 = set_aside(&path).unwrap();
        assert_ne!(kept, kept2);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn create_database_turns_the_short_file_panic_into_a_damaged_error() {
        let dir = temp_dir("short");
        let path = dir.join("atomic.redb");
        {
            let db = Database::create(&path).unwrap();
            let tx = db.begin_write().unwrap();
            {
                let mut t = tx
                    .open_table(redb::TableDefinition::<&[u8], &[u8]>::new("t"))
                    .unwrap();
                for k in 0..50u32 {
                    t.insert(k.to_be_bytes().as_slice(), vec![7u8; 20_000].as_slice())
                        .unwrap();
                }
            }
            tx.commit().unwrap();
        }
        let check = inspect(&path).unwrap().unwrap();
        let f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        f.set_len(check.file_len - 2 * u64::from(check.page_size))
            .unwrap();
        drop(f);
        assert!(inspect(&path).unwrap().unwrap().is_short());

        let Err(err) = create_database(&path) else {
            panic!("a short file must not open");
        };
        assert!(is_damaged_store_error(&err.to_string()), "{err}");

        let kept = set_aside(&path).unwrap();
        repair_copy(&kept, &path).unwrap();
        let db = create_database(&path).unwrap();
        verify_readable(&db).unwrap();
        drop(db);
        assert!(kept.exists(), "the broken file is kept");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_file_that_is_not_a_store_is_damage() {
        let dir = temp_dir("garbage");
        let path = dir.join("atomic.redb");
        std::fs::write(&path, vec![0x42u8; 9000]).unwrap();
        let Err(err) = create_database(&path) else {
            panic!("garbage must not open");
        };
        assert!(is_damaged_store_error(&err.to_string()), "{err}");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn only_damage_counts_as_damage() {
        assert!(is_damaged_store_error("DB corrupted: bad checksum"));
        assert!(is_damaged_store_error(&format!("The {DAMAGED_STORE}: x")));
        assert!(!is_damaged_store_error(
            "Database already open. Cannot acquire lock."
        ));
        assert!(!is_damaged_store_error("Permission denied (os error 13)"));
    }

    /// The stores the Android app could not open (`ATOMIC_BROKEN_STORES`, a
    /// list of paths): each is diagnosed as short and repaired on a copy.
    #[test]
    #[ignore = "needs ATOMIC_BROKEN_STORES"]
    fn repair_the_broken_stores_from_the_field() {
        let Ok(paths) = std::env::var("ATOMIC_BROKEN_STORES") else {
            return;
        };
        let dir = temp_dir("field");
        for (i, p) in paths.split(':').enumerate() {
            let p = Path::new(p);
            let check = inspect(p).unwrap().unwrap();
            let dest = dir.join(format!("repaired-{i}.redb"));
            let result = repair_copy(p, &dest);
            eprintln!(
                "{}: {check:?} short={} repair={result:?}",
                p.display(),
                check.is_short()
            );
        }
        std::fs::remove_dir_all(dir).ok();
    }
}
