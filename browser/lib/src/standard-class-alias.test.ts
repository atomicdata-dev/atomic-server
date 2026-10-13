import { expect, it } from 'vitest';
import { core } from './ontologies/core.js';
import { dataBrowser } from './ontologies/dataBrowser.js';
import { server } from './ontologies/server.js';
import { standardClassAlias } from './standard-class-alias.js';
it('resolves standard class names using canonical ontology identifiers', () => {
  expect(standardClassAlias('File')).toBe(server.classes.file);
  expect(standardClassAlias('file')).toBe(server.classes.file);
  expect(standardClassAlias('folder')).toBe(dataBrowser.classes.folder);
  expect(standardClassAlias('document')).toBe(dataBrowser.classes.documentV2);
  expect(standardClassAlias('document-v2')).toBe(
    dataBrowser.classes.documentV2,
  );
  expect(standardClassAlias('Class')).toBe(core.classes.class);
  expect(standardClassAlias('property')).toBe(core.classes.property);
  expect(standardClassAlias('products')).toBeUndefined();
  expect(standardClassAlias('__proto__')).toBeUndefined();
});
