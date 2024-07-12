/* -----------------------------------
 * GENERATED WITH @tomic/cli
 * -------------------------------- */

import { registerOntologies } from '@tomic/lib';

import { ontology } from './ontology.js';

export function initOntologies(): void {
  registerOntologies(ontology);
}
