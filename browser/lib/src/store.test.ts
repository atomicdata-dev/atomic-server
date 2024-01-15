import { expect } from 'chai';
import { jest } from '@jest/globals';
import { Resource, urls, Store, core, Core } from './index.js';

describe('Store', () => {
  it('renders the populate value', async () => {
    const store = new Store();
    const subject = 'https://atomicdata.dev/test';
    const testval = 'Hi world';
    const newResource = new Resource(subject);
    newResource.setUnsafe(urls.properties.description, testval);
    store.addResources(newResource);
    const gotResource = store.getResourceLoading(subject);
    const atomString = gotResource!
      .get(urls.properties.description)!
      .toString();
    expect(atomString).to.equal(testval);
  });

  it('fetches a resource', async () => {
    const store = new Store({ serverUrl: 'https://atomicdata.dev' });
    const resource = await store.getResourceAsync(
      'https://atomicdata.dev/properties/createdAt',
    );

    if (resource.error) {
      throw resource.error;
    }

    const atomString = resource.get(urls.properties.shortname)!.toString();
    expect(atomString).to.equal('created-at');
  });

  it('accepts a custom fetch implementation', async () => {
    const testResourceSubject = 'https://atomicdata.dev';

    const customFetch = jest.fn(
      async (url: RequestInfo | URL, options: RequestInit | undefined) => {
        return fetch(url, options);
      },
    );

    const store = new Store();

    await store.fetchResourceFromServer(testResourceSubject, {
      noWebSocket: true,
    });

    expect(customFetch.mock.calls).to.have.length(0);

    store.injectFetch(customFetch);

    await store.fetchResourceFromServer(testResourceSubject, {
      noWebSocket: true,
    });

    expect(customFetch.mock.calls).to.have.length(1);
  });

  it('creates new resources using store.newResource()', async () => {
    const store = new Store({ serverUrl: 'https://myserver.dev' });

    const resource1 = await store.newResource<Core.Property>({
      subject: 'https://myserver.dev/testthing',
      parent: 'https://myserver.dev/properties',
      isA: core.classes.property,
      propVals: {
        [core.properties.datatype]: urls.datatypes.slug,
        [core.properties.shortname]: 'testthing',
      },
    });

    expect(resource1.props.parent).to.equal('https://myserver.dev/properties');
    expect(resource1.props.datatype).to.equal(urls.datatypes.slug);
    expect(resource1.props.shortname).to.equal('testthing');
    expect(resource1.hasClasses(core.classes.property)).to.equal(true);

    const resource2 = await store.newResource();

    expect(resource2.props.parent).to.equal(store.getServerUrl());
    expect(resource2.get(core.properties.isA)).to.equal(undefined);
  });
});
