/**
 * Resources the user opened recently, per drive, most recent first. Kept in
 * localStorage so the `@` mention menu can offer them before anything is
 * typed, when full-text search has no query to rank on.
 */

const STORAGE_KEY = 'recentResources';
const MAX_PER_DRIVE = 20;

type RecentResources = Record<string, string[]>;

function read(): RecentResources {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    const parsed: unknown = raw ? JSON.parse(raw) : {};

    return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
      ? (parsed as RecentResources)
      : {};
  } catch {
    return {};
  }
}

export function getRecentResources(drive: string): string[] {
  const list = read()[drive];

  return Array.isArray(list) ? list : [];
}

function write(all: RecentResources): void {
  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(all));
  } catch {
    // Storage full or blocked: recents are a convenience, not state.
  }
}

export function addRecentResource(drive: string, subject: string): void {
  // The drive itself is always one click away in the sidebar.
  if (subject === drive) return;

  const all = read();
  const current = Array.isArray(all[drive]) ? all[drive] : [];

  if (current[0] === subject) return;

  all[drive] = [subject, ...current.filter(s => s !== subject)].slice(
    0,
    MAX_PER_DRIVE,
  );

  write(all);
}

/** Forgets `subject`, e.g. because it was deleted, trashed or went missing. */
export function removeRecentResource(drive: string, subject: string): void {
  const all = read();
  const current = Array.isArray(all[drive]) ? all[drive] : [];

  if (!current.includes(subject)) return;

  all[drive] = current.filter(s => s !== subject);
  write(all);
}
