import { describe, expect, it } from 'vitest';
import {
  asSubject,
  extractDidSubject,
  InvalidSubjectError,
  isDidSubject,
  isHttpSubject,
  isValidSubject,
  subjectsReferToSameResource,
  tryAsSubject,
  type Subject,
} from './subject.js';

describe('subject', () => {
  describe('isValidSubject', () => {
    it('accepts DID subjects', () => {
      expect(isValidSubject('did:ad:abc')).toBe(true);
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
      expect(extractDidSubject('did:ad:abc')).toBe('did:ad:abc');
      expect(extractDidSubject('did:ad:abc?drive=did:ad:drive')).toBe(
        'did:ad:abc',
      );
    });

    it('extracts a DID from the HTTP path form and the /did endpoint', () => {
      expect(extractDidSubject('https://example.com/did:ad:abc')).toBe(
        'did:ad:abc',
      );
      expect(
        extractDidSubject(
          'https://example.com/did?subject=' + encodeURIComponent('did:ad:abc'),
        ),
      ).toBe('did:ad:abc');
    });

    it('does not treat ordinary HTTP resources as DIDs', () => {
      expect(
        extractDidSubject('https://atomicdata.dev/ontology/core'),
      ).toBeUndefined();
      expect(extractDidSubject('/relative')).toBeUndefined();
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
  });
});
