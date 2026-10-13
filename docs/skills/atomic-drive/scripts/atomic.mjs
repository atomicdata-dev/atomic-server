#!/usr/bin/env node
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';

export const CONFIG_PATH =
  process.env.ATOMIC_BOOTSTRAP_CONFIG ??
  `${homedir()}/.config/atomic-drive/bootstrap.json`;
const SELF = fileURLToPath(import.meta.url);
const help = `Atomic drive bootstrap (signed HTTP; configurable credentials)
  identity                         Public identity and connection metadata
  catalog                          Enabled skill metadata from Atomic
  load <skill-name>                 Instructions and reference/script metadata
  read <subject>                    Compact JSON-AD, including document text
  text <subject>                    Document body only
  search <query>                    Search the default drive
  create <json-file>                Compact JSON-AD with @class and @parent
  write-document <subject> <file>   Replace a document body from Markdown/text
  edit <subject> <property> <file>  Set one property from a JSON value file
  load-script <skill> <path>        Read and verify a pinned script
  run <skill> <path> [args...]      Explicitly run that verified script
All subjects are full atomic:/did:ad: IDs or property URLs, never session #refs.
Create failures after allocation report the subject: inspect it before retrying.`;

const sameSubject = (a, b) =>
  typeof a === 'string' &&
  typeof b === 'string' &&
  a.replace(/^did:ad:/, 'atomic:') === b.replace(/^did:ad:/, 'atomic:');
const hash = text => createHash('sha256').update(text).digest('hex');

/** Public connection metadata only. Paths resolve beside the configuration file. */
export async function readConfig(configPath = CONFIG_PATH) {
  const absolute = resolve(configPath);
  let config;
  try {
    config = JSON.parse(await readFile(absolute, 'utf8'));
  } catch {
    throw new Error(
      'Cannot read bootstrap configuration. Set ATOMIC_BOOTSTRAP_CONFIG or see references/setup.md.',
    );
  }
  if (!config || typeof config !== 'object' || Array.isArray(config))
    throw new Error('Expected a configuration object.');
  const url = new URL(process.env.ATOMIC_SERVER_URL ?? config.serverUrl);
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if (
    !['http:', 'https:'].includes(url.protocol) ||
    (url.protocol === 'http:' && !loopback) ||
    url.username ||
    url.password ||
    url.pathname !== '/' ||
    url.search ||
    url.hash
  ) {
    throw new Error(
      'Use an HTTPS server origin, or loopback HTTP, without credentials, path, query or fragment.',
    );
  }
  config.serverUrl = url.origin;
  for (const name of ['agent', 'drive'])
    if (
      typeof config[name] !== 'string' ||
      !/^(atomic:|did:ad:|https?:\/\/)/.test(config[name])
    )
      throw new Error(`Expected a public ${name} subject.`);
  for (const name of ['library', 'documentReader', 'documentWriter']) {
    if (typeof config[name] !== 'string' || !config[name])
      throw new Error(`Missing ${name} path.`);
    config[name] = resolve(dirname(absolute), config[name]);
  }
  if (
    config.credentialEnv &&
    (typeof config.credentialEnv !== 'string' ||
      !/^[A-Za-z_][A-Za-z0-9_]*$/.test(config.credentialEnv))
  )
    throw new Error('Invalid credential environment variable name.');
  const command = config.credentialCommand;
  if (
    command &&
    (typeof command !== 'object' ||
      typeof command.command !== 'string' ||
      !command.command ||
      !Array.isArray(command.args) ||
      !command.args.every(arg => typeof arg === 'string'))
  )
    throw new Error(
      'Expected credentialCommand with an executable and string arguments.',
    );
  if (
    [command, config.credentialEnv, config.keychainHelper].filter(Boolean)
      .length > 1
  )
    throw new Error('Select one credential source.');
  if (!command && !config.credentialEnv && !config.keychainHelper)
    throw new Error('Configure a credentialCommand or credentialEnv.');
  if (config.keychainHelper)
    config.keychainHelper = resolve(dirname(absolute), config.keychainHelper);
  return config;
}

/** The executable is trusted local configuration. Its stderr and stdout never
 * enter diagnostics, and the secret is never passed as a command argument. */
export function credentialFor(config) {
  if (config.credentialEnv) {
    const secret = process.env[config.credentialEnv];
    if (!secret)
      throw new Error('Configured credential environment variable is empty.');
    return { secret };
  }
  const command = config.credentialCommand ?? {
    command: config.keychainHelper,
    args: ['get'],
  };
  const result = spawnSync(command.command, [...command.args, config.agent], {
    encoding: 'utf8',
    timeout: 30000,
    maxBuffer: 16384,
    shell: false,
  });
  if (result.status !== 0 || !result.stdout?.trim())
    throw new Error('Credential command failed or returned no credential.');
  return { secret: result.stdout.trim() };
}

export async function openAtomic(configPath = CONFIG_PATH) {
  const config = await readConfig(configPath);
  const lib = await import(pathToFileURL(config.library).href);
  const required = [
    'enableLoro',
    'readResourceCompact',
    'createResourceFromCompact',
    'setResourceProperty',
  ];
  if (
    !lib.Agent?.fromSecret ||
    !lib.Store ||
    required.some(name => typeof lib[name] !== 'function')
  ) {
    throw new Error(
      'Incompatible Atomic library. See references/setup.md for the tested runtime revision.',
    );
  }
  const credential = credentialFor(config);
  let agent;
  try {
    agent = await lib.Agent.fromSecret(credential.secret);
  } catch {
    throw new Error('The saved Atomic credential is invalid.');
  } finally {
    credential.secret = '';
  }
  if (!sameSubject(agent.subject, config.agent))
    throw new Error(
      'Keychain identity does not match bootstrap configuration.',
    );
  await lib.enableLoro();
  const { documentText } = await import(
    pathToFileURL(config.documentReader).href
  );
  const { writeDocumentText } = await import(
    pathToFileURL(config.documentWriter).href
  );
  const store = new lib.Store({
    serverUrl: config.serverUrl,
    agent,
    connect: false,
    requireOnlineWrites: true,
  });
  // Mark the HTTP server available without opening a WebSocket or local client DB.
  store.setServerConnected(true);
  store.injectFetch((input, opts) =>
    fetch(input, {
      ...opts,
      redirect: 'error',
      signal: AbortSignal.timeout(20000),
    }),
  );

  async function resource(subject) {
    const result = await store.fetchResourceFromServer(subject, {
      noWebSocket: true,
    });
    if (result.error) throw result.error;
    return result;
  }
  async function inDrive(subject) {
    const item = await resource(subject);
    if (
      !sameSubject(item.subject, config.drive) &&
      !sameSubject(
        item.get('https://atomicdata.dev/properties/drive'),
        config.drive,
      )
    ) {
      throw new Error('Registry content must belong to the configured drive.');
    }
    return item;
  }
  async function text(subject, scoped = false) {
    const item = await (scoped ? inDrive(subject) : resource(subject));
    if (
      !item.hasClasses(lib.dataBrowser.classes.documentV2) &&
      !item.hasClasses(lib.dataBrowser.classes.meeting)
    )
      throw new Error('This resource has no document body.');
    const doc = item.getLoroDoc();
    if (!doc) throw new Error('Document snapshot unavailable.');
    return documentText(doc);
  }
  async function read(subject) {
    const item = await resource(subject);
    const result = await lib.readResourceCompact(store, item.subject, {
      includeCommitData: true,
    });
    if (
      item.hasClasses(lib.dataBrowser.classes.documentV2) ||
      item.hasClasses(lib.dataBrowser.classes.meeting)
    )
      result._documentText = await text(item.subject);
    return result;
  }
  async function writeDocument(subject, body) {
    const item = await resource(subject);
    if (
      !item.hasClasses(lib.dataBrowser.classes.documentV2) &&
      !item.hasClasses(lib.dataBrowser.classes.meeting)
    )
      throw new Error('This resource has no document body.');
    const doc = item.getLoroDoc();
    if (!doc) throw new Error('Document snapshot unavailable.');
    writeDocumentText(doc, body);
    item.markDirty();
    const saved = await item.save();
    if (saved === 'offline')
      throw new Error(
        'The write was queued rather than acknowledged by the server.',
      );
    return { subject: item.subject };
  }
  async function create(data) {
    const body = data._documentText;
    const ordinary = { ...data };
    delete ordinary._documentText;
    if (body !== undefined && typeof body !== 'string')
      throw new Error('_documentText must be text.');
    if (
      body !== undefined &&
      ![
        'document',
        lib.dataBrowser.classes.documentV2,
        'meeting',
        lib.dataBrowser.classes.meeting,
      ].includes(data['@class'])
    )
      throw new Error('_documentText requires a document or meeting class.');
    const result = await lib.createResourceFromCompact(
      store,
      config.drive,
      ordinary,
    );
    acknowledged('Create', result.subject);
    if (body !== undefined) {
      try {
        await writeDocument(result.subject, body);
      } catch {
        throw new Error(
          `Resource created at ${result.subject}, but its body was not saved. Inspect that subject before retrying.`,
        );
      }
    }
    return result;
  }
  function acknowledged(operation, subject) {
    const status = store.getSyncStatus();
    if (status.pendingDirtyCount || status.blockedCount)
      throw new Error(
        `${operation} was not acknowledged by the server for ${subject}. Inspect that subject before retrying; this command has no persistent outbox.`,
      );
  }
  async function edit(subject, property, value) {
    const result = await lib.setResourceProperty(
      store,
      subject,
      property,
      value,
    );
    acknowledged('Edit', result.subject);
    return result;
  }
  async function registry() {
    if (!config.registry) throw new Error('No registry resource configured.');
    let value;
    try {
      value = JSON.parse(await text(config.registry, true));
    } catch (error) {
      throw new Error(
        `Unable to read the Atomic skill registry: ${error.message}`,
      );
    }
    if (value.version !== 1 || !Array.isArray(value.skills))
      throw new Error('Unsupported registry format.');
    const names = new Set();
    for (const entry of value.skills) {
      if (
        !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(entry.name) ||
        names.has(entry.name) ||
        typeof entry.description !== 'string' ||
        typeof entry.subject !== 'string' ||
        typeof entry.enabled !== 'boolean'
      )
        throw new Error('Invalid or duplicate skill entry in registry.');
      names.add(entry.name);
    }
    return value;
  }
  async function skill(name) {
    const entry = (await registry()).skills.find(s => s.name === name);
    if (!entry || entry.enabled !== true)
      throw new Error('Skill is absent or disabled in the Atomic registry.');
    return entry;
  }
  async function load(name) {
    const entry = await skill(name);
    return { ...entry, instructions: await text(entry.subject, true) };
  }
  async function script(name, path) {
    const entry = await skill(name);
    const item = (entry.scripts ?? []).find(s => s.path === path);
    if (
      !item ||
      item.enabled !== true ||
      !/^[a-f0-9]{64}$/.test(item.sha256 ?? '')
    )
      throw new Error('Script is absent, disabled, or missing a SHA-256 pin.');
    // Scripts are ordinary editable Atomic documents with one fenced code block.
    const content = await text(item.subject, true);
    const match = /^```(?:javascript|js|mjs)?\n([\s\S]*?)\n```$/.exec(content);
    if (!match)
      throw new Error(
        'Script document must contain exactly one JavaScript code block.',
      );
    const source = match[1] + '\n';
    if (hash(source) !== item.sha256)
      throw new Error(
        'Script SHA-256 mismatch. Review the changed contents before updating its pin.',
      );
    return { ...item, source };
  }
  return {
    config,
    store,
    lib,
    read,
    text,
    create,
    edit,
    writeDocument,
    registry,
    skill,
    load,
    script,
  };
}

async function main() {
  const [command = 'help', ...args] = process.argv.slice(2);
  if (command === 'help' || command === '--help') {
    process.stdout.write(help + '\n');
    return;
  }
  const counts = {
    identity: 0,
    catalog: 0,
    load: 1,
    read: 1,
    text: 1,
    search: 1,
    create: 1,
    'write-document': 2,
    edit: 3,
    'load-script': 2,
  };
  if (!(command in counts) && command !== 'run')
    throw new Error('Unknown command; use help.');
  if (command === 'run' ? args.length < 2 : args.length !== counts[command])
    throw new Error('Wrong number of arguments; use help.');
  // Keep library diagnostics off stdout, which is reserved for command results.
  console.log = console.info = console.debug = () => {};
  const a = await openAtomic();
  let result;
  try {
    switch (command) {
      case 'identity':
        result = {
          agent: a.config.agent,
          serverUrl: a.config.serverUrl,
          drive: a.config.drive,
          registry: a.config.registry,
          transport: 'http',
          credential: a.config.credentialEnv
            ? 'environment'
            : 'credential command',
        };
        break;
      case 'catalog':
        result = {
          version: 1,
          registry: a.config.registry,
          skills: (await a.registry()).skills
            .filter(s => s.enabled)
            .map(({ name, description, subject }) => ({
              name,
              description,
              subject,
            })),
        };
        break;
      case 'load':
        result = await a.load(args[0]);
        break;
      case 'read':
        result = await a.read(args[0]);
        break;
      case 'text':
        process.stdout.write((await a.text(args[0])) + '\n');
        return;
      case 'search':
        result = await Promise.all(
          (
            await a.store.search(args[0], {
              parents: [a.config.drive],
              limit: 20,
              serverOnly: true,
            })
          ).map(subject => a.read(subject)),
        );
        break;
      case 'create':
        result = await a.create(JSON.parse(await readFile(args[0], 'utf8')));
        break;
      case 'write-document':
        result = await a.writeDocument(
          args[0],
          await readFile(args[1], 'utf8'),
        );
        break;
      case 'edit':
        result = await a.edit(
          args[0],
          args[1],
          JSON.parse(await readFile(args[2], 'utf8')),
        );
        break;
      case 'load-script':
        result = await a.script(args[0], args[1]);
        break;
      case 'run': {
        if (a.config.credentialEnv)
          throw new Error(
            'Registry scripts require a credential command; environment credentials are not forwarded.',
          );
        const entry = await a.script(args[0], args[1]);
        const cache = resolve(dirname(CONFIG_PATH), 'script-cache');
        await mkdir(cache, { recursive: true, mode: 0o700 });
        const path = resolve(cache, entry.sha256 + '.mjs');
        await writeFile(path, entry.source, { mode: 0o600 });
        const env = {
          ...process.env,
          ATOMIC_BOOTSTRAP_CLI: SELF,
          ATOMIC_BOOTSTRAP_CONFIG: CONFIG_PATH,
        };
        delete env.ATOMIC_AGENT_SECRET;
        const child = spawnSync(process.execPath, [path, ...args.slice(2)], {
          stdio: 'inherit',
          env,
          timeout: 120000,
        });
        if (child.error)
          throw new Error(
            'Script did not complete within its time limit or could not start.',
          );
        process.exitCode = child.status ?? 1;
        return;
      }
    }
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  } finally {
    a.store.disconnect();
  }
}

if (process.argv[1] && resolve(process.argv[1]) === SELF) {
  main()
    .catch(error => {
      process.stderr.write(`Atomic bootstrap: ${error.message}\n`);
      process.exitCode = 1;
    })
    .finally(() =>
      process.stdout.write('', () => process.exit(process.exitCode ?? 0)),
    );
}
