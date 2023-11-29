import * as fs from 'fs';
import * as path from 'path';

export interface AtomicConfig {
  /**
   * Path relative to this file where the generated files should be written to.
   */
  outputFolder: string;
  /**
   * [OPTIONAL] The @tomic/lib module identifier.
   * The default should be sufficient in most but if you have given the module an alias you should change this value
   */
  moduleAlias?: string;
  /**
   * [OPTIONAL] By default we generate class types for ease of use (e.g: export type Property = typeof core.classes.property;). But these names can clash with other interfaces or classes in your project. When 'useNameSpaces' is set to true the types will be wrapped in a namespace.
   */
  useNamespaces?: boolean;
  /**
   * [OPTIONAL] The secret of the agent that is used to access your atomic data server. This can also be provided as a command line argument if you don't want to store it in the config file.
   * If left empty the public agent is used.
   */
  agentSecret?: string;
  /** The list of subjects of your ontologies */

  ontologies: string[];
  _ISLIB_: boolean;
}

export const atomicConfig: AtomicConfig = JSON.parse(
  fs
    .readFileSync(path.resolve(process.cwd(), './atomic.config.json'))
    .toString(),
);
