/** Helper function related the Atomic Classes */

import {
  Datatype,
  JSONValue,
  properties,
  Property,
  Resource,
  Store,
} from './index.js';

/** Returns the Typescript interface string based on the Class */
export async function classToTypescriptDefinition(
  klass: Resource,
  store: Store,
): Promise<string> {
  function renderProperty(property: Property, required: boolean) {
    const description = `/** ${property.description}*/`;
    const shortname = `"${property.shortname}"${required ? '' : '?'}`;
    const datatype = dataTypeToJSONType(property.datatype);

    return `  ${description}\n  ${shortname}: ${datatype};\n`;
  }

  const requires = await Promise.all(
    klass.getSubjects(properties.requires).map(s => store.getProperty(s)),
  );
  const recommends = await Promise.all(
    klass.getSubjects(properties.recommends).map(s => store.getProperty(s)),
  );
  const className = klass.get(properties.shortname);
  let returnString = `interface ${className} {\n`;
  requires.forEach(prop => {
    returnString = returnString.concat(renderProperty(prop, true));
  });
  recommends.forEach(prop => {
    returnString = returnString.concat(renderProperty(prop, false));
  });
  returnString = returnString.concat('}');

  return returnString;
}

/** Returns the typescript type string for a Datatype */
function dataTypeToJSONType(datatype: Datatype): JSONValue {
  switch (datatype) {
    case Datatype.ATOMIC_URL:
      return 'string | Resource';
    case Datatype.BOOLEAN:
      return 'boolean';
    case Datatype.DATE:
      return 'string';
    case Datatype.FLOAT:
      return 'number';
    case Datatype.INTEGER:
      return 'number';
    case Datatype.MARKDOWN:
      return 'string';
    case Datatype.RESOURCEARRAY:
      return 'string[] | Resource[]';
    case Datatype.SLUG:
      return 'string';
    case Datatype.STRING:
      return 'string';
    case Datatype.TIMESTAMP:
      return 'number';
    case Datatype.UNKNOWN:
      return 'unknown';
  }
}
