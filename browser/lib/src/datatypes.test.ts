import { describe, it } from 'vitest';

import {
  Datatype,
  datatypeTag,
  localizeText,
  urls,
  validateDatatype,
} from './index.js';

describe('Datatypes', () => {
  it('throws errors when datatypes dont match values', async ({ expect }) => {
    const string = 'valid string';
    const int = 5;
    const float = 1.13;
    const slug = 'sl-ug';
    const atomicUrl = urls.classes.class;
    const resourceArray = [urls.classes.class, urls.classes.property];
    const resourceArrayInvalid = [urls.classes.class, 'not a URL'];
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

  it('validates URI values and refuses script schemes', ({ expect }) => {
    expect(() =>
      validateDatatype('https://example.com/a?b=c', Datatype.URI),
    ).to.not.throw();
    expect(() =>
      validateDatatype('mailto:someone@example.com', Datatype.URI),
    ).to.not.throw();

    expect(() => validateDatatype('', Datatype.URI), 'empty').to.throw();
    expect(() => validateDatatype(5, Datatype.URI), 'number').to.throw();
    expect(
      () => validateDatatype('not a url', Datatype.URI),
      'relative',
    ).to.throw();
    expect(
      () => validateDatatype('javascript:alert(1)', Datatype.URI),
      'javascript:',
    ).to.throw();
    expect(
      () => validateDatatype('  JavaScript:alert(1)', Datatype.URI),
      'javascript: with case and whitespace',
    ).to.throw();
    expect(
      () => validateDatatype('data:text/html,<b>x</b>', Datatype.URI),
      'data:',
    ).to.throw();
    expect(
      () => validateDatatype('vbscript:MsgBox(1)', Datatype.URI),
      'vbscript:',
    ).to.throw();
  });

  it('validates LocalizedText values', ({ expect }) => {
    expect(() =>
      validateDatatype(
        { en: 'Fast sync', 'nl-BE': 'Snelle synchronisatie' },
        Datatype.LOCALIZEDTEXT,
      ),
    ).to.not.throw();
    // Empty map is a valid (if useless) LocalizedText.
    expect(() => validateDatatype({}, Datatype.LOCALIZEDTEXT)).to.not.throw();

    expect(() =>
      validateDatatype('just a string', Datatype.LOCALIZEDTEXT),
    ).to.throw();
    expect(() => validateDatatype(['en'], Datatype.LOCALIZEDTEXT)).to.throw();
    expect(() =>
      validateDatatype({ 'not a tag!': 'x' }, Datatype.LOCALIZEDTEXT),
    ).to.throw();
    expect(() =>
      validateDatatype({ en: 5 }, Datatype.LOCALIZEDTEXT),
    ).to.throw();
  });
});

describe('localizeText', () => {
  it('resolves exact → primary subtag → default → en → first', ({ expect }) => {
    const value = {
      en: 'Fast sync',
      'en-US': 'Fast sync (US)',
      nl: 'Snelle synchronisatie',
    };
    expect(localizeText(value, 'en-US')).toBe('Fast sync (US)');
    expect(localizeText(value, 'nl-BE')).toBe('Snelle synchronisatie');
    expect(localizeText(value, 'de', 'nl')).toBe('Snelle synchronisatie');
    expect(localizeText(value, 'de')).toBe('Fast sync');
    expect(localizeText({ fr: 'Bonjour' }, 'de')).toBe('Bonjour');
    expect(localizeText(undefined, 'en')).toBeUndefined();
  });
});

describe('datatypeTag', () => {
  it('tags load-bearing datatypes and collapses the rest', ({ expect }) => {
    // Load-bearing: references and arrays get a tag.
    expect(datatypeTag(Datatype.ATOMIC_URL, 'https://example.com/x')).toBe(
      'atomicUrl',
    );
    expect(datatypeTag(Datatype.RESOURCEARRAY, [])).toBe('resourceArray');
    expect(datatypeTag(Datatype.RESOURCEARRAY, ['https://example.com/x'])).toBe(
      'resourceArray',
    );
    expect(datatypeTag(Datatype.JSON, '{"a":1}')).toBe('json');
    expect(datatypeTag(Datatype.JSON, [300, 214])).toBe('json');

    // A nested resource (object stored as a JSON string under an atomicURL
    // property) stays untagged — the server heuristic handles `{...}`.
    expect(datatypeTag(Datatype.ATOMIC_URL, '{"a":1}')).toBeUndefined();

    // Cosmetic string-likes are tagged so the server can recover
    // the exact variant — at least vector/search text extraction branches on
    // `Value::Markdown`.
    expect(datatypeTag(Datatype.MARKDOWN, '# heading')).toBe('markdown');
    expect(datatypeTag(Datatype.SLUG, 'a-slug')).toBe('slug');
    expect(datatypeTag(Datatype.URI, 'mailto:a@b.c')).toBe('uri');
    expect(datatypeTag(Datatype.DATE, '2026-05-21')).toBe('date');
    expect(datatypeTag(Datatype.TIMESTAMP, 1700000000000)).toBe('timestamp');

    // LocalizedText: a map that must not materialize as plain Json.
    expect(datatypeTag(Datatype.LOCALIZEDTEXT, { en: 'hi' })).toBe(
      'localizedText',
    );

    // Plain string and scalars stay untagged (the default).
    expect(datatypeTag(Datatype.STRING, 'hello')).toBeUndefined();
    expect(datatypeTag(Datatype.INTEGER, 5)).toBeUndefined();
    expect(datatypeTag(Datatype.BOOLEAN, true)).toBeUndefined();
  });
});
