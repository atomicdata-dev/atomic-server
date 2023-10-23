import { Resource } from './resource.js';
import { urls } from './urls.js';

describe('resource.ts', () => {
  it('push propvals', () => {
    const resource = new Resource('test');
    const testsubject = 'https://example.com/testsubject';
    resource.pushPropVal(urls.properties.subResources, [testsubject], true);
    resource.pushPropVal(urls.properties.subResources, [testsubject], true);

    expect(resource.get(urls.properties.subResources)).toStrictEqual([
      testsubject,
    ]);

    const testsubject2 = 'https://example.com/testsubject2';

    resource.pushPropVal(
      urls.properties.subResources,
      [testsubject2, testsubject2],
      true,
    );

    expect(resource.get(urls.properties.subResources)).toStrictEqual([
      testsubject,
      testsubject2,
    ]);

    resource.pushPropVal(urls.properties.subResources, [
      testsubject,
      testsubject,
    ]);

    expect(resource.get(urls.properties.subResources)).toStrictEqual([
      testsubject,
      testsubject2,
      testsubject,
      testsubject,
    ]);
  });
});
