import { dataBrowser, server, type NativeChannel } from '@tomic/lib';
import baseModels from '@repo-lib-defaults/default_base_models.json';
import defaultStore from '@repo-lib-defaults/default_store.json';

type JsonAd = Record<string, unknown> & { '@id': string };

const NAME = 'https://atomicdata.dev/properties/name';
const PARENT = 'https://atomicdata.dev/properties/parent';
const IS_A = 'https://atomicdata.dev/properties/isA';
const DRIVE = server.classes.drive;
const FOLDER = dataBrowser.classes.folder;
const DESCRIPTION = 'https://atomicdata.dev/properties/description';

/**
 * A host for trying the embed in a desktop browser: the web app's default
 * ontology plus a few resources, all in memory. It stands in for the Rust
 * side until that exists, and answers the same calls.
 */
export function createMockHost(): NativeChannel & {
  resources: Map<string, JsonAd>;
} {
  const resources = new Map<string, JsonAd>();
  /** Every call the page made, newest last: for looking at in a console. */
  const calls: Array<[string, unknown[]]> = [];
  // `did:ad:X` and `atomic:X` are one resource.
  const key = (subject: string) => subject.replace(/^(did:ad:|atomic:)/, '');

  for (const r of [
    ...(baseModels as JsonAd[]),
    ...(defaultStore as JsonAd[]),
  ]) {
    resources.set(r['@id'], r);
  }

  // DID subjects, like real resources: the store resolves them locally.
  const drive = '';
  const folder =
    'did:ad:-HBYtYHShjXaA3WwCO5ytOeI0xAVRSeMpDPo_G2GTlCCBH5hnLCZPNEGfgkZ6lbwegdTpH3sRazAT8vtLnkSJA';
  const add = (r: JsonAd) => resources.set(r['@id'], r);

  add({
    '@id': drive,
    [IS_A]: [DRIVE],
    [NAME]: 'Mock drive',
    [DESCRIPTION]: 'A drive that only exists in this page.',
  });
  add({
    '@id': folder,
    [IS_A]: [FOLDER],
    [NAME]: 'A folder',
    [PARENT]: drive,
  });
  add({
    '@id':
      'did:ad:mECIr9XPNTZUU7ISoThaSOEpEdDEu-TSpdMYeKqu9E42s-RLiGbb_n8vSv_AZBXRKqPgumWOxvhAQfPZYuV1OA',
    [IS_A]: ['https://atomicdata.dev/classes/Class'],
    [NAME]: 'A resource inside the folder',
    [PARENT]: folder,
    [DESCRIPTION]: 'Rendered by ResourcePage, with nothing around it.',
  });

  const find = (id: string) =>
    resources.get(id) ??
    [...resources.values()].find(r => key(r['@id']) === key(id));

  const text = (id: string) => {
    const r = find(id);

    // Answered under the name it was asked by.
    return r ? JSON.stringify({ ...r, '@id': id }) : null;
  };

  const methods: Record<string, (args: unknown[]) => unknown> = {
    init: () => true,
    getResource: ([s]) => text(s as string),
    getResourcesWithSnapshots: ([subjects]) =>
      (subjects as string[]).map(s => ({
        jsonAd: text(s),
        snapshot: null,
      })),
    getLoroSnapshot: () => null,
    allSubjects: () => [...resources.keys()],
    getDriveSubjects: () => [...resources.keys()],
    getAllVersionVectors: () => ({}),
    getVersionVectorsForDrive: () => ({}),
    getVersionVectorsForSubjects: () => ({}),
    historyAttribution: () => null,
    getBlob: () => null,
    flush: () => undefined,
    outboxEntries: () => [],
    outboxWrite: () => undefined,
    putResource: ([j]) => {
      const r = JSON.parse(j as string) as JsonAd;
      resources.set(r['@id'], r);
    },
    putResources: ([js]) => {
      for (const j of js as string[]) {
        const r = JSON.parse(j) as JsonAd;
        resources.set(r['@id'], r);
      }
    },
    putResourceWithSnapshot: ([, j]) => {
      const r = JSON.parse(j as string) as JsonAd;
      resources.set(r['@id'], r);
    },
    applyCommit: () => undefined,
    applyPeerCommit: () => undefined,
    removeResource: ([s]) => {
      resources.delete(s as string);
    },
    query: ([opts]) => {
      const o = opts as { property?: string; value?: string; limit?: number };
      const subjects = [...resources.values()]
        .filter(r => {
          if (!o.property) return true;
          const v = r[o.property];

          return Array.isArray(v) ? v.includes(o.value) : v === o.value;
        })
        .map(r => r['@id'])
        .slice(0, o.limit ?? 1000);

      return { subjects, count: subjects.length, resources: [] };
    },
    search: ([q]) =>
      [...resources.values()]
        .filter(r =>
          String(r[NAME] ?? '')
            .toLowerCase()
            .includes(String(q).toLowerCase()),
        )
        .map(r => r['@id'])
        .slice(0, 20),
  };

  Object.assign(window, { mockHostCalls: calls });

  return {
    resources,
    async call(method, args) {
      calls.push([method, args]);
      const m = methods[method];

      if (!m) throw new Error(`mock host: no ${method}`);

      return m(args);
    },
  };
}
