/* -----------------------------------
 * GENERATED WITH @tomic/cli
 * -------------------------------- */

import { registerOntologies } from '../ontology.js';

import { core } from './core.js';
import { commits } from './commits.js';
import { collections } from './collections.js';
import { dataBrowser } from './dataBrowser.js';
import { server } from './server.js';
import { ai } from './ai.js';
import { forks } from './forks.js';
import { i18n } from './i18n.js';
import { forms } from './forms.js';

export function initOntologies(): void {
  registerOntologies(
    core,
    commits,
    collections,
    dataBrowser,
    server,
    ai,
    forks,
    i18n,
    forms,
  );
}
