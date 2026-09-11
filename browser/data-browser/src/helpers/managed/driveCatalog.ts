// @wc-ignore-file
/** Account pointers are discovery hints, never resource access grants. */
export type CatalogEntry = {
  drive_subject: string;
  drive_name?: string | null;
  drive_emoji?: string | null;
};
export type DriveCatalog = { drives: CatalogEntry[]; removed: string[] };
export type CatalogIdentity = { email: string; agent: string };
export type CatalogSnapshot = DriveCatalog & CatalogIdentity;

export function catalogSubjects(
  local: string[],
  catalog: DriveCatalog | null,
): string[] {
  const removed = new Set(catalog?.removed ?? []);

  return [
    ...new Set([
      ...local,
      ...(catalog?.drives.map(d => d.drive_subject) ?? []),
    ]),
  ].filter(s => !removed.has(s));
}

export function parseCatalog(value: unknown): DriveCatalog {
  const c = value as DriveCatalog;

  if (
    !c ||
    !Array.isArray(c.drives) ||
    !Array.isArray(c.removed) ||
    c.drives.some(d => typeof d?.drive_subject !== 'string') ||
    c.removed.some(d => typeof d !== 'string')
  ) {
    throw new Error('Invalid drive catalog');
  }

  return c;
}

export class DriveCatalogSync {
  private generation = 0;
  snapshot: CatalogSnapshot | null = null;
  constructor(
    private deps: {
      identity: () => Promise<CatalogIdentity | null>;
      send: (entries: CatalogEntry[]) => Promise<unknown>;
      changed: (snapshot: CatalogSnapshot | null) => void;
    },
  ) {}

  reset() {
    this.generation++;
    this.snapshot = null;
    this.deps.changed(null);
  }

  async refresh(entries: CatalogEntry[]) {
    const request = ++this.generation;
    const identity = await this.deps.identity();
    if (request !== this.generation) return;

    if (!identity) {
      this.reset();

      return;
    }

    if (
      this.snapshot &&
      (this.snapshot.email !== identity.email ||
        this.snapshot.agent !== identity.agent)
    ) {
      this.snapshot = null;
      this.deps.changed(null);
    }

    const result = parseCatalog(await this.deps.send(entries));
    if (request !== this.generation) return;
    const after = await this.deps.identity();
    if (request !== this.generation) return;

    if (
      !after ||
      after.email !== identity.email ||
      after.agent !== identity.agent
    ) {
      this.reset();

      return;
    }

    this.snapshot = { ...result, ...identity };
    this.deps.changed(this.snapshot);
  }
}

export function catalogCacheKey(identity: CatalogIdentity): string {
  return `atomic-drive-catalog:${JSON.stringify([identity.email, identity.agent])}`;
}

export function readCatalogCache(
  identity: CatalogIdentity,
  storage: Pick<Storage, 'getItem'>,
): CatalogSnapshot | null {
  try {
    const raw = storage.getItem(catalogCacheKey(identity));
    if (!raw) return null;

    return { ...parseCatalog(JSON.parse(raw)), ...identity };
  } catch {
    return null;
  }
}
