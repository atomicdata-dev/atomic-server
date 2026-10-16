/**
 * Typed bindings for the exports of an app, generated from its manifest.
 *
 * The manifest's `inputSchema` / `outputSchema` (the bounded JSON Schema subset
 * of `server/src/plugins/actions.rs`) are the source: one `interface` per
 * schema and one function per export that calls `store.callExport` with those
 * types. The output imports nothing, so an app can check it in beside its
 * manifest. No WASM: a frame calls the server's `/host/call`, whatever the app
 * is written in.
 *
 * Regenerate with `pnpm generate-bindings <manifest.json> <out.ts>`.
 */

interface Field {
  type: string;
  description?: string;
  items?: Schema;
}

interface Schema {
  type: string;
  properties?: Record<string, Field>;
  required?: string[];
}

interface ManifestExport {
  interface: string;
  function: string;
  description?: string;
  inputSchema: Schema;
  outputSchema: Schema;
}

export interface BindingsManifest {
  exports?: ManifestExport[];
}

const pascal = (text: string) =>
  text
    .split(/[^a-zA-Z0-9]+/)
    .filter(Boolean)
    .map(part => part[0].toUpperCase() + part.slice(1))
    .join('');

const camel = (text: string) => {
  const name = pascal(text);

  return name[0].toLowerCase() + name.slice(1);
};

const doc = (text: string | undefined, indent: string) =>
  text ? `${indent}/** ${text.replace(/\*\//g, '* /')} */\n` : '';

function scalar(field: Field, name: string): string {
  switch (field.type) {
    case 'string':
      return 'string';
    case 'integer':
      return 'number';
    case 'boolean':
      return 'boolean';
    default:
      throw new Error(`${name}: unsupported field type '${field.type}'`);
  }
}

/** Emits `schema` as `export interface name`, and the interfaces it needs first. */
function declare(schema: Schema, name: string, out: string[]): void {
  const required = new Set(schema.required ?? []);
  const lines: string[] = [];

  for (const [key, field] of Object.entries(schema.properties ?? {})) {
    let type: string;

    if (field.type === 'array') {
      if (!field.items) throw new Error(`${name}.${key}: array without items`);
      const item = `${name}${pascal(key)}Item`;
      declare(field.items, item, out);
      type = `${item}[]`;
    } else {
      type = scalar(field, `${name}.${key}`);
    }

    lines.push(
      `${doc(field.description, '  ')}  ${key}${required.has(key) ? '' : '?'}: ${type};`,
    );
  }

  out.push(`export interface ${name} {\n${lines.join('\n')}\n}\n`);
}

/** The TypeScript source of the bindings for every export in `manifest`. */
export function generateExportBindings(manifest: BindingsManifest): string {
  const out: string[] = [
    '// Generated from the manifest by @tomic/plugin (generateExportBindings). Do not edit.\n',
    `/** What \`store.callExport\` of a frame or packaged view offers. */
export interface ExportCaller {
  callExport<T = unknown>(
    iface: string,
    fn: string,
    args?: Record<string, unknown>,
  ): Promise<T>;
}
`,
  ];

  for (const exp of manifest.exports ?? []) {
    const segment = exp.interface.split('/')[1]?.split('@')[0] ?? exp.interface;
    const base = `${pascal(segment)}${pascal(exp.function)}`;
    const args = `${base}Args`;
    const result = `${base}Result`;

    declare(exp.inputSchema, args, out);
    declare(exp.outputSchema, result, out);
    out.push(
      `${doc(exp.description, '')}export function ${camel(segment)}${pascal(exp.function)}(
  store: ExportCaller,
  args: ${args},
): Promise<${result}> {
  return store.callExport<${result}>(
    ${JSON.stringify(exp.interface)},
    ${JSON.stringify(exp.function)},
    { ...args },
  );
}
`,
    );
  }

  return out.join('\n');
}
