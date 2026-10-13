/* eslint-disable no-console */
import * as fs from 'fs';
import * as path from 'path';
import chalk from 'chalk';
import {
  assertLockfileMatches,
  lockfileFromEnsured,
  lockfileFromInput,
  ontologyFromSchemaFile,
  parseLockfile,
  serializeLockfile,
  type Lockfile,
  type OntologyInput,
} from '@tomic/lib';

const USAGE = `
ad-generate ontology <command> <file> [options]

Commands:
  push <file>   Make the schema a real ontology on the server and write the lockfile.
  lock <file>   Offline. Write the lockfile for an ontology whose subject you know.
  check <file>  Offline. Fail if the lockfile no longer matches the schema.

<file> is a JSON Schema or an ontology JSON ({ shortname, classes }).
The lockfile is written next to it as <file>.lock.json.

Options:
  --parent <subject>    push: the resource (usually a drive) that holds the ontology. Required.
  --ontology <subject>  lock: the subject of the Ontology resource. Required.
  --shortname <slug>    The ontology's shortname. Defaults to the one in the file.
  --lockfile <path>     Lockfile path. Defaults to <file>.lock.json
  --accept-changes      push: push even if the lockfile no longer matches (new properties are made).
  --types               push: also generate typescript types (adds the ontology to atomic.config.json).
  --agent, -a <secret>  push: the agent that signs. Defaults to agentSecret in atomic.config.json.
`;

const VALUE_FLAGS = [
  '--parent',
  '--ontology',
  '--shortname',
  '--lockfile',
  '--agent',
  '-a',
];

interface Args {
  command?: string;
  file?: string;
  flags: Map<string, string>;
  switches: Set<string>;
}

const parseArgs = (args: string[]): Args => {
  const positional: string[] = [];
  const flags = new Map<string, string>();
  const switches = new Set<string>();

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];

    if (VALUE_FLAGS.includes(arg)) {
      flags.set(arg, args[++i] ?? '');
    } else if (arg.startsWith('-')) {
      switches.add(arg);
    } else {
      positional.push(arg);
    }
  }

  return { command: positional[0], file: positional[1], flags, switches };
};

const fail = (message: string): void => {
  console.error(chalk.red('ERROR:'), message);
  process.exitCode = 1;
};

const readInput = (file: string, shortname?: string): OntologyInput => {
  let text: string;

  try {
    text = fs.readFileSync(file, 'utf8');
  } catch (error) {
    throw new Error(`Could not read ${file}: ${(error as Error).message}`);
  }

  try {
    return ontologyFromSchemaFile(text, { shortname });
  } catch (error) {
    throw new Error(`${file}: ${(error as Error).message}`);
  }
};

const readLockfile = (lockfilePath: string): Lockfile | undefined => {
  if (!fs.existsSync(lockfilePath)) return undefined;

  try {
    return parseLockfile(fs.readFileSync(lockfilePath, 'utf8'));
  } catch (error) {
    throw new Error(`${lockfilePath}: ${(error as Error).message}`);
  }
};

const writeLockfile = (lockfilePath: string, lock: Lockfile): void => {
  fs.writeFileSync(lockfilePath, serializeLockfile(lock));
  console.log(chalk.blue('Lockfile written to'), chalk.cyan(lockfilePath));
};

export const ontologyCommand = async (rawArgs: string[]) => {
  const { command, file, flags, switches } = parseArgs(rawArgs);

  if (!command || !['push', 'lock', 'check'].includes(command)) {
    console.log(USAGE);
    process.exitCode = command ? 1 : 0;

    return;
  }

  if (!file) {
    return fail(
      `Missing <file>. Usage: ad-generate ontology ${command} <file>`,
    );
  }

  const lockfilePath = flags.get('--lockfile') ?? `${file}.lock.json`;

  try {
    const input = readInput(file, flags.get('--shortname'));
    const previous = readLockfile(lockfilePath);

    if (command === 'lock') {
      const ontology = flags.get('--ontology');

      if (!ontology) return fail('lock needs --ontology <subject>');

      // Keep the class subjects of an earlier push of the same ontology.
      const classes = previous?.ontology === ontology ? previous.classes : {};

      return writeLockfile(
        lockfilePath,
        lockfileFromInput(input, ontology, classes),
      );
    }

    if (command === 'check') {
      if (!previous) {
        return fail(
          `No lockfile at ${lockfilePath}. Run \`ontology push\` or \`ontology lock\` first`,
        );
      }

      assertLockfileMatches(previous, input);
      console.log(chalk.green('Lockfile matches the schema'));

      return;
    }

    await push(input, previous, lockfilePath, flags, switches);
  } catch (error) {
    fail((error as Error).message);
  }
};

const push = async (
  input: OntologyInput,
  previous: Lockfile | undefined,
  lockfilePath: string,
  flags: Map<string, string>,
  switches: Set<string>,
) => {
  const parent = flags.get('--parent');

  if (!parent) throw new Error('push needs --parent <subject>');

  // A pinned lockfile must still match, or the push would quietly make new
  // properties next to the old ones.
  if (previous && !switches.has('--accept-changes')) {
    try {
      assertLockfileMatches(previous, input);
    } catch (error) {
      throw new Error(
        `${lockfilePath}: ${(error as Error).message}\nPass --accept-changes to push anyway`,
      );
    }
  }

  // Needs atomic.config.json (server and agent), so load it only now.
  const { ensureOntology } = await import('@tomic/lib');
  const { store, ready, ensureServerUrlForSubject } =
    await import('../store.js');

  await ready;
  ensureServerUrlForSubject(parent);

  if (!store.getAgent()) {
    throw new Error(
      'push needs an agent to sign with: set agentSecret in atomic.config.json or pass --agent <secret>',
    );
  }

  const ensured = await ensureOntology(store, parent, input);
  const lock = lockfileFromEnsured(ensured);

  console.log(
    chalk.green('Ontology'),
    chalk.cyan(ensured.ontology),
    `(${Object.keys(ensured.classes).length} classes, ${Object.keys(ensured.properties).length} properties)`,
  );
  writeLockfile(lockfilePath, lock);

  if (switches.has('--types')) {
    await generate(ensured.ontology);
  }
};

/** Adds the ontology to atomic.config.json when it is not listed, then generates all types. */
const generate = async (ontology: string) => {
  const { atomicConfig } = await import('../config.js');
  const { generateTypes } = await import('./ontologies.js');
  const ontologies = [...atomicConfig.ontologies];

  if (!ontologies.includes(ontology)) {
    ontologies.push(ontology);

    const configPath = path.resolve(process.cwd(), './atomic.config.json');
    const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));

    config.ontologies = ontologies;
    fs.writeFileSync(configPath, `${JSON.stringify(config, null, 2)}\n`);
    console.log(chalk.blue('Added the ontology to'), chalk.cyan(configPath));
  }

  await generateTypes(ontologies);
};
