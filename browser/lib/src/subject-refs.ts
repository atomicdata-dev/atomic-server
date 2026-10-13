/**
 * Short refs for `did:ad:` subjects in LLM tool I/O (see
 * planning/json-ad-compact.md). A full DID is ~90 chars of high-entropy
 * base64 (~30–40 tokens); the model only needs a token it can reliably hand
 * back, so tool results shorten subjects to `#<first 8 DID chars>` and tool
 * inputs expand them again.
 *
 * Refs are DERIVED (a prefix of the DID), not allocated — no counter state to
 * persist. Expansion still needs this tab registry (filled by every
 * shorten call, re-seeded each turn by the drive tree in the system prompt);
 * the registry survives refresh in sessionStorage; an unknown ref fails loudly and
 * the model recovers by searching. Refs never reach storage: they are
 * expanded at the tool boundary and in link rendering only.
 */

import { identifierBody } from './subject.js';

/** Plain resource subjects only, in either scheme; agent / commit / blob /
 *  node subjects stay untouched. */
const SHORTENABLE = /^(atomic:|did:ad:)[A-Za-z0-9_-]{16,}$/;

/** The identifier body after the scheme; the input already matched SHORTENABLE. */
function bodyOf(subject: string): string {
  return identifierBody(subject) ?? subject;
}

const REF_PATTERN = /^#([A-Za-z0-9_-]{8,})$/;

/** ref body → full subject */
const registry = new Map<string, string>();
const STORAGE_KEY = 'atomic.ai.subject-refs.v1';

// Retain emitted refs when a chunk reloads or the conversation is reopened in
// this tab. They identify resources only; normal Store permissions still apply.
try {
  const saved: unknown = JSON.parse(
    sessionStorage.getItem(STORAGE_KEY) ?? '[]',
  );

  if (Array.isArray(saved)) {
    for (const entry of saved) {
      if (
        Array.isArray(entry) &&
        entry.length === 2 &&
        typeof entry[0] === 'string' &&
        typeof entry[1] === 'string' &&
        REF_PATTERN.test(`#${entry[0]}`) &&
        SHORTENABLE.test(entry[1]) &&
        bodyOf(entry[1]).startsWith(entry[0])
      )
        registry.set(entry[0], entry[1]);
    }
  }
} catch {
  /* Storage may be disabled. In-memory refs still work. */
}

/**
 * Returns the short ref for a subject, registering it for later expansion.
 * Non-shortenable values (global URLs, commit subjects) pass through. On the
 * (practically impossible) prefix collision the ref extends until unique.
 */
export const shortenSubject = (subject: string): string => {
  if (!SHORTENABLE.test(subject)) {
    return subject;
  }

  const body = bodyOf(subject);
  let length = 8;
  let key = body.slice(0, length);

  while (registry.has(key) && registry.get(key) !== subject) {
    length += 4;
    key = body.slice(0, length);
  }

  if (registry.get(key) !== subject) {
    registry.set(key, subject);

    try {
      sessionStorage.setItem(STORAGE_KEY, JSON.stringify([...registry]));
    } catch {
      /* Storage may be disabled or full. */
    }
  }

  return `#${key}`;
};

/** Expands a ref if it is one AND is known; otherwise returns undefined. */
export const tryExpandRef = (value: string): string | undefined => {
  const match = REF_PATTERN.exec(value);

  return match ? registry.get(match[1]) : undefined;
};

/**
 * Expands a value that must denote a resource. Non-refs pass through
 * (full subjects); unknown refs throw with a recovery hint for the model.
 */
export const expandSubject = (value: string): string => {
  const match = REF_PATTERN.exec(value);

  if (!match) {
    return value;
  }

  const subject = registry.get(match[1]);

  if (!subject) {
    throw new Error(
      `Unknown ref "${value}" — it may come from an older session. Find the resource again (search or drive tree) and use the ref or subject from that result.`,
    );
  }

  return subject;
};

/**
 * Walks a tool result and shortens every full did:ad subject it finds —
 * string values, array members, and object keys. Only exact full-string
 * matches are touched, so prose containing a DID mid-sentence is left alone.
 */
export const shortenRefsDeep = <T>(value: T): T => {
  if (typeof value === 'string') {
    return shortenSubject(value) as T;
  }

  if (Array.isArray(value)) {
    return value.map(shortenRefsDeep) as T;
  }

  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([key, val]) => [
        shortenSubject(key),
        shortenRefsDeep(val),
      ]),
    ) as T;
  }

  return value;
};
