import { blake3 } from '@noble/hashes/blake3.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';
import { Datatype } from './datatypes.js';
import {
  canonicalizeScheme,
  isPropertySubject,
  propertySubject,
} from './subject.js';

/** Domain separation: a property ID can never equal a blob hash. */
export const PROPERTY_IDENTITY_CONTEXT = 'atomic property identity v1';

const SLUG_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

const knownDatatypes = new Set<string>(
  Object.values(Datatype).filter(d => d !== Datatype.UNKNOWN),
);

/**
 * The content-addressed ID of a Property: `atomic:prop:{blake3-hex}`.
 *
 * `ontology` is the Property's `parent`. See
 * `docs/src/schema/property-identity.md`. Throws on an invalid shortname or an
 * unknown datatype.
 */
export function propertyId(
  ontology: string,
  shortname: string,
  datatype: string,
): string {
  if (!SLUG_RE.test(shortname)) {
    throw new Error(`Invalid property shortname: '${shortname}'`);
  }

  if (!knownDatatypes.has(datatype)) {
    throw new Error(`Unknown datatype: '${datatype}'`);
  }

  // JCS of an object of three strings: keys sorted, no whitespace.
  const jcs = JSON.stringify({
    datatype,
    ontology: canonicalizeScheme(ontology),
    shortname,
  });

  const hash = blake3(utf8ToBytes(jcs), {
    context: utf8ToBytes(PROPERTY_IDENTITY_CONTEXT),
  });

  return propertySubject(bytesToHex(hash));
}

/** True for `atomic:prop:{hex}` and legacy `did:ad:prop:{hex}`. */
export function isPropertyId(subject: string): boolean {
  return isPropertySubject(subject);
}

/** Does `subject` equal the ID derived from the given ontology, shortname and datatype? */
export function verifyPropertyId(
  subject: string,
  ontology: string,
  shortname: string,
  datatype: string,
): boolean {
  if (!isPropertyId(subject)) {
    return false;
  }

  try {
    return (
      canonicalizeScheme(subject) === propertyId(ontology, shortname, datatype)
    );
  } catch {
    return false;
  }
}
