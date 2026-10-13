import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it, vi } from 'vitest';
import {
  parseAppPackage,
  prepareAppPackageImport,
  readAppPackage,
  appPackageSchema,
} from './app-package.js';
import { core } from './ontologies/core.js';
import { IMPORT_BASELINE, IMPORT_LOCAL_ID } from './import-records.js';
import { planVerdict } from './plugin-plan.js';
import { applyPlan } from './plugin-apply.js';
import { Datatype } from './datatypes.js';
import type { JSONValue } from './value.js';

const json = readFileSync(
  new URL('./fixtures/app-package.json', import.meta.url),
  'utf8',
);
const parent = 'https://test/drive/packages';
const content = 'https://test/schema/package-content';
const klass = 'https://test/schema/package';
const schema = {
  classes: { 'app-package': klass },
  properties: { 'app-package-content': content },
};

function host(saved: Record<string, Record<string, JSONValue>> = {}) {
  return {
    query: vi.fn((property: string, value: string) =>
      Object.keys(saved).filter(key => saved[key][property] === value),
    ),
    read: vi.fn((subject: string) => saved[subject]),
  };
}

describe('portable app package resources', () => {
  it('uses the existing importer, planner and apply path without executing code', async () => {
    const saved: Record<string, Record<string, JSONValue>> = {};
    const importer = host(saved);
    const verdict = prepareAppPackageImport(importer, json, parent, schema);
    expect(verdict.summary.created).toBe(1);
    const plan = await planVerdict(verdict, {
      createSubject: () => 'https://test/temporary',
      readResource: async subject => saved[subject],
      getProperty: async subject => ({
        subject,
        shortname: subject,
        description: '',
        datatype: subject === IMPORT_BASELINE ? Datatype.JSON : Datatype.STRING,
      }),
    });
    expect(plan.blocked).toBe(false);
    const create = vi.fn(async request => {
      saved['https://test/imported'] = {
        ...request.propVals,
        [core.properties.parent]: request.parent,
        [core.properties.isA]: request.isA,
      };

      return 'https://test/imported';
    });
    const report = await applyPlan(plan, {
      create,
      set: vi.fn(),
      remove: vi.fn(),
      destroy: vi.fn(),
    });
    expect(report.failed).toBe(0);
    expect(create).toHaveBeenCalledTimes(1);
    const resource = saved['https://test/imported'];
    expect(resource[core.properties.parent]).toBe(parent);
    expect(resource[core.properties.isA]).toEqual([klass]);
    expect(resource[IMPORT_LOCAL_ID]).toBe(parseAppPackage(json).id);
    expect(readAppPackage(resource, schema)).toEqual(parseAppPackage(json));
    expect(
      prepareAppPackageImport(importer, json, parent, schema).summary.unchanged,
    ).toBe(1);
    expect(
      prepareAppPackageImport(
        importer,
        json,
        'https://test/another-parent',
        schema,
      ).summary.created,
    ).toBe(1);

    const changed = JSON.parse(json);
    changed.release.source += '\n// changed revision';
    const conflict = prepareAppPackageImport(
      importer,
      JSON.stringify(changed),
      parent,
      schema,
    );
    expect(conflict.problems.some(p => p.severity === 'error')).toBe(true);
    expect(conflict.intents).toEqual([]);
  });

  it('preserves literal local references and canonicalizes document formatting', () => {
    const original = prepareAppPackageImport(host(), json, parent, schema);
    const pkg = JSON.parse(json);
    const reordered = Object.fromEntries(Object.entries(pkg).reverse());
    expect(
      prepareAppPackageImport(
        host(),
        JSON.stringify(reordered),
        parent,
        schema,
      ),
    ).toEqual(original);
    const intent = original.intents[0];
    if (intent.op !== 'create') throw new Error('Expected package create');
    expect(parseAppPackage(intent.set[content] as string)).toEqual(pkg);
    expect(appPackageSchema().classes.map(c => c.shortname)).toEqual([
      'app-package',
    ]);
  });

  it.each([
    'credentials',
    'grants',
    'agent',
    'schedule',
    'connection',
    'parent',
  ])('rejects installation field %s before consulting the store', field => {
    const importer = host();
    expect(() =>
      prepareAppPackageImport(
        importer,
        JSON.stringify({ ...JSON.parse(json), [field]: 'private' }),
        parent,
        schema,
      ),
    ).toThrow();
    expect(importer.query).not.toHaveBeenCalled();
  });

  it('carries single- and multi-table destinations without changing package content', () => {
    const manifest = (name: string) =>
      JSON.parse(
        readFileSync(
          new URL(`../../../testdata/plugin-manifest/${name}`, import.meta.url),
          'utf8',
        ),
      );

    const stored = (release: Record<string, unknown>) => {
      const pkg = JSON.parse(json);
      pkg.release.manifest = release;
      const verdict = prepareAppPackageImport(
        host(),
        JSON.stringify(pkg),
        parent,
        schema,
      );
      const intent = verdict.intents[0];
      if (intent.op !== 'create') throw new Error('Expected package create');

      return intent.set[content] as string;
    };

    const sha = (text: string) =>
      createHash('sha256').update(text).digest('hex');

    // Pinned: these bytes are what an imported package resource holds.
    expect(sha(stored(JSON.parse(json).release.manifest))).toBe(
      '1cca98e4ad15c9d3b75a175301bf582cc835859350372f61745e76a119c24fe6',
    );
    expect(sha(stored(manifest('v2-accepts-destination.json')))).toBe(
      'd779cbeb7976f6b356269951b3dd3e808b57e5aa0f29681d0e73734cf8e347f9',
    );
    const multi = manifest('v2-destination-tables.json');
    expect(JSON.parse(stored(multi)).release.manifest).toEqual(multi);

    const broken = structuredClone(multi);
    broken.destination.tables.statements.rowClass = 'bank-account';
    expect(() => stored(broken)).toThrow('table rowClass must name a class');
  });

  it('rejects ambiguous resource labels instead of rewriting them as links', () => {
    const pkg = JSON.parse(json);
    pkg.name = 'local:package';
    expect(() => parseAppPackage(JSON.stringify(pkg))).toThrow(
      'reserved local:',
    );
  });

  it('rejects malformed releases and unsupported setup instead of weakening declarations', () => {
    for (const patch of [
      { runtime: 'other/1' },
      { source: '' },
      { token: 'secret' },
      { manifest: { schemaVersion: 3 } },
      { manifest: { schemaVersion: 2, capabilities: ['teleport'] } },
      { schemas: { item: 'local:item' } },
    ]) {
      const pkg = JSON.parse(json);
      Object.assign(pkg.release, patch);
      expect(() => parseAppPackage(JSON.stringify(pkg))).toThrow();
    }

    const pkg = JSON.parse(json);
    pkg.setup.inputSchema.properties.name.pattern = '.*';
    expect(() => parseAppPackage(JSON.stringify(pkg))).toThrow();
    expect(() => parseAppPackage(' '.repeat(4 * 1024 * 1024 + 1))).toThrow(
      '4 MiB',
    );
    expect(() => readAppPackage({}, schema)).toThrow();
    expect(() =>
      prepareAppPackageImport(host(), json, parent, {
        classes: {},
        properties: {},
      }),
    ).toThrow();
  });
});
