import { describe, it } from 'vitest';

import { Datatype, urls, validateDatatype } from './index.js';

describe('Datatypes', () => {
  it('throws errors when datatypes dont match values', async ({ expect }) => {
    const string = 'valid string';
    const int = 5;
    const float = 1.13;
    const slug = 'sl-ug';
    const atomicUrl = urls.classes.class;
    const resourceArray = [urls.classes.class, urls.classes.property];
    const resourceArrayInvalid = [urls.classes.class, 'urls.classes.property'];
    expect(
      () => validateDatatype(string, Datatype.STRING),
      'Valid string',
    ).to.not.throw();
    expect(
      () => validateDatatype(int, Datatype.STRING),
      'Invalid string, number',
    ).to.throw();
    expect(
      () => validateDatatype(float, Datatype.STRING),
      'Invalid string, number',
    ).to.throw();

    expect(
      () => validateDatatype(atomicUrl, Datatype.ATOMIC_URL),
      'Valid AtomicUrl',
    ).to.not.throw();
    expect(
      () => validateDatatype(string, Datatype.ATOMIC_URL),
      'Invalid AtomicUrl, string',
    ).to.throw();

    expect(
      () => validateDatatype(int, Datatype.INTEGER),
      'Valid Integer',
    ).to.not.throw();
    expect(
      () => validateDatatype(float, Datatype.INTEGER),
      'Invalid Integer, string',
    ).to.throw();
    expect(
      () => validateDatatype(string, Datatype.INTEGER),
      'Invalid Integer, float',
    ).to.throw();

    expect(
      () => validateDatatype(slug, Datatype.SLUG),
      'Valid slug',
    ).to.not.throw();
    expect(() => validateDatatype(float, Datatype.SLUG)).to.throw();
    expect(() => validateDatatype(string, Datatype.SLUG)).to.throw();
    expect(() => validateDatatype(int, Datatype.SLUG)).to.throw();

    expect(() =>
      validateDatatype(resourceArray, Datatype.RESOURCEARRAY),
    ).to.not.throw();
    expect(() =>
      validateDatatype(resourceArrayInvalid, Datatype.RESOURCEARRAY),
    ).to.throw();
    expect(() => validateDatatype(float, Datatype.RESOURCEARRAY)).to.throw();
    expect(() => validateDatatype(string, Datatype.RESOURCEARRAY)).to.throw();
    expect(() => validateDatatype(int, Datatype.RESOURCEARRAY)).to.throw();
  });
});
