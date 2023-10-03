
/* -----------------------------------
* GENERATED WITH ATOMIC-GENERATE
* -------------------------------- */

import { registerOntologies } from '../index.js';

import { core } from './core.js';
import { commits } from './commits.js';
import { collections } from './collections.js';
import { dataBrowser } from './dataBrowser.js';
import { server } from './server.js';

export function initOntologies(): void {
  registerOntologies(core, commits, collections, dataBrowser, server);
}
