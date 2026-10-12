import { describe, it, expect } from 'vitest';
import { Resource } from './resource.js';
import { core } from './ontologies/core.js';

describe('rights lists', () => {
  it('setting an unchanged rights list twice does not repeat agents', () => {
    const resource = new Resource('did:ad:testdrive');
    const agents = ['did:ad:agent:a', 'did:ad:agent:b'];

    resource.set(core.properties.read, agents);
    resource.set(core.properties.read, [...agents]);
    resource.push(core.properties.read, ['did:ad:agent:a'], true);

    expect(resource.get(core.properties.read)).toEqual(agents);
  });
});
