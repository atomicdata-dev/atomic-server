import { describe, expect, it } from 'vitest';
import {
  asSubject,
  blobSubjectFromDownloadUrl,
  extractDidSubject,
  InvalidSubjectError,
  isDidSubject,
  isHttpSubject,
  isIdentifierHttpEndpoint,
  isIdentifierPathForm,
  isIdentifierResolutionPath,
  isValidSubject,
  identifierKind,
  isPropertySubject,
  isResourceSubject,
  canonicalIdentifier,
  isAtomicIdentifier,
  isLegacyAtomicLink,
  subjectsReferToSameResource,
  emitSubjectForCaps,
  CAP_CANONICAL_SCHEME,
  tryAsSubject,
  type Subject,
} from './subject.js';

describe('subject', () => {
  describe('isValidSubject', () => {
    it('accepts Atomic identifier subjects', () => {
      expect(isValidSubject('did:ad:abc')).toBe(true);
      expect(isValidSubject('atomic:abc')).toBe(true);
      expect(isValidSubject('atomic:agent:pk')).toBe(true);
      expect(isAtomicIdentifier('atomic://pair?v=1')).toBe(false);
      expect(isLegacyAtomicLink('atomic://pair?v=1')).toBe(true);
    });

    it('accepts http(s) URL subjects', () => {
      expect(isValidSubject('https://atomicdata.dev/things/1')).toBe(true);
      expect(isValidSubject('http://localhost:9883/foo')).toBe(true);
    });

    it('rejects empty strings, relative paths, and other prefixes', () => {
      expect(isValidSubject('')).toBe(false);
      expect(isValidSubject('/things/1')).toBe(false);
      expect(isValidSubject('did:web:example.com')).toBe(false);
      expect(isValidSubject('ftp://example.com')).toBe(false);
    });
  });

  describe('asSubject', () => {
    it('brands a valid subject and round-trips its string value', () => {
      const s: Subject = asSubject('did:ad:abc');
      expect(s).toBe('did:ad:abc');
    });

    it('throws InvalidSubjectError on a malformed input', () => {
      expect(() => asSubject('nope')).toThrow(InvalidSubjectError);
    });
  });

  describe('tryAsSubject', () => {
    it('returns the branded subject when valid', () => {
      expect(tryAsSubject('https://atomicdata.dev/x')).toBe(
        'https://atomicdata.dev/x',
      );
    });

    it('returns undefined when invalid', () => {
      expect(tryAsSubject('nope')).toBeUndefined();
    });
  });

  describe('isDidSubject / isHttpSubject', () => {
    it('discriminates DIDs from HTTP URLs', () => {
      const did = asSubject('did:ad:abc');
      const http = asSubject('https://atomicdata.dev/things/1');

      expect(isDidSubject(did)).toBe(true);
      expect(isHttpSubject(did)).toBe(false);
      expect(isDidSubject(http)).toBe(false);
      expect(isHttpSubject(http)).toBe(true);
    });
  });

  describe('extractDidSubject / subjectsReferToSameResource', () => {
    it('returns a DID unchanged, stripping query and fragment', () => {
      expect(extractDidSubject('did:ad:abc')).toBe('atomic:abc');
      expect(extractDidSubject('atomic:abc')).toBe('atomic:abc');
      expect(extractDidSubject('did:ad:abc?drive=did:ad:drive')).toBe(
        'atomic:abc',
      );
    });

    it('extracts an identifier from the HTTP path form and resolver endpoints', () => {
      expect(extractDidSubject('https://example.com/did:ad:abc')).toBe(
        'atomic:abc',
      );
      expect(extractDidSubject('https://example.com/atomic:abc')).toBe(
        'atomic:abc',
      );
      expect(
        extractDidSubject(
          'https://example.com/did?subject=' + encodeURIComponent('did:ad:abc'),
        ),
      ).toBe('atomic:abc');
      expect(
        extractDidSubject(
          'https://example.com/resource?subject=' +
            encodeURIComponent('atomic:abc'),
        ),
      ).toBe('atomic:abc');
      expect(
        extractDidSubject(
          'https://example.com/atomic?subject=' +
            encodeURIComponent('atomic:abc'),
        ),
      ).toBe('atomic:abc');
    });

    it('classifies identifier resolution paths without treating did:key as Atomic', () => {
      expect(isIdentifierHttpEndpoint('/did')).toBe(true);
      expect(isIdentifierHttpEndpoint('/resource')).toBe(true);
      expect(isIdentifierHttpEndpoint('/atomic')).toBe(true);
      expect(isIdentifierHttpEndpoint('/diddle')).toBe(false);
      expect(isIdentifierPathForm('/atomic:abc')).toBe(true);
      expect(isIdentifierPathForm('/did:ad:abc')).toBe(true);
      expect(isIdentifierPathForm('/did:ad:ab/c+d==')).toBe(true);
      expect(isIdentifierPathForm('/did:key:abc')).toBe(false);
      expect(isIdentifierPathForm('/atomic://pair')).toBe(false);
      expect(isIdentifierPathForm('/foo/atomic:abc')).toBe(false);
      expect(isIdentifierResolutionPath('/did?subject=atomic:abc')).toBe(true);
      expect(isIdentifierResolutionPath('/search')).toBe(false);
    });

    it('does not treat ordinary HTTP resources as DIDs', () => {
      expect(
        extractDidSubject('https://atomicdata.dev/ontology/core'),
      ).toBeUndefined();
      expect(extractDidSubject('/relative')).toBeUndefined();
    });

    it('treats atomic:x and did:ad:x as the same resource', () => {
      expect(subjectsReferToSameResource('atomic:abc', 'did:ad:abc')).toBe(
        true,
      );
    });

    it('treats https://host/did:ad:x and did:ad:x as the same resource', () => {
      expect(
        subjectsReferToSameResource(
          'https://example.com/did:ad:abc',
          'did:ad:abc',
        ),
      ).toBe(true);
      expect(
        subjectsReferToSameResource(
          'did:ad:abc',
          'https://example.com/did:ad:abc',
        ),
      ).toBe(true);
    });

    it('still rejects a genuine subject mismatch', () => {
      expect(
        subjectsReferToSameResource(
          'https://example.com/did:ad:aaa',
          'did:ad:bbb',
        ),
      ).toBe(false);
      expect(
        subjectsReferToSameResource(
          'https://example.com/foo',
          'https://example.com/bar',
        ),
      ).toBe(false);
    });

    it('emits atomic: only when the peer listed canonical-scheme', () => {
      expect(emitSubjectForCaps('atomic:abc', [CAP_CANONICAL_SCHEME])).toBe(
        'atomic:abc',
      );
      expect(emitSubjectForCaps('did:ad:abc', [CAP_CANONICAL_SCHEME])).toBe(
        'atomic:abc',
      );
      expect(emitSubjectForCaps('atomic:abc', [])).toBe('did:ad:abc');
      expect(emitSubjectForCaps('did:ad:abc', ['commit-ok-slim'])).toBe(
        'did:ad:abc',
      );
    });
  });
});

describe('blobSubjectFromDownloadUrl', () => {
  const hash = 'ab'.repeat(32);

  it('finds the blob behind a content-addressed download URL', () => {
    expect(
      blobSubjectFromDownloadUrl(`https://example.com/download/files/${hash}`),
    ).toBe(`atomic:blob:${hash}`);
    expect(
      blobSubjectFromDownloadUrl(
        `http://localhost:9883/download/files/${hash.toUpperCase()}?w=400`,
      ),
    ).toBe(`atomic:blob:${hash}`);
    expect(blobSubjectFromDownloadUrl(`/download/files/${hash}`)).toBe(
      `atomic:blob:${hash}`,
    );
  });

  it('ignores every other URL', () => {
    expect(
      blobSubjectFromDownloadUrl(
        'https://atomicdata.dev/download/files/1726139217600-photo.jpg',
      ),
    ).toBeUndefined();
    expect(
      blobSubjectFromDownloadUrl(`https://example.com/files/${hash}`),
    ).toBeUndefined();
    expect(
      blobSubjectFromDownloadUrl(`https://example.com/download/files/${hash}0`),
    ).toBeUndefined();
    expect(blobSubjectFromDownloadUrl('blob:https://example.com/abc')).toBe(
      undefined,
    );
    expect(blobSubjectFromDownloadUrl('')).toBeUndefined();
  });
});

describe('property subjects', () => {
  const hex = 'a'.repeat(64);

  it('recognises atomic:prop: and legacy did:ad:prop:', () => {
    expect(identifierKind(`atomic:prop:${hex}`)).toBe('property');
    expect(identifierKind(`did:ad:prop:${hex}`)).toBe('property');
    expect(identifierKind('atomic:prop:')).toBe('other');
    expect(isPropertySubject(`did:ad:prop:${hex}`)).toBe(true);
  });

  it('is not a resource subject', () => {
    expect(isResourceSubject(`atomic:prop:${hex}`)).toBe(false);
  });

  it('canonicalizes the legacy scheme', () => {
    expect(canonicalIdentifier(`did:ad:prop:${hex}`)).toBe(
      `atomic:prop:${hex}`,
    );
  });
});
