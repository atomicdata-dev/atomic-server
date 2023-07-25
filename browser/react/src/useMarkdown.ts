import {
  Datatype,
  JSONValue,
  properties,
  Resource,
  Store,
  urls,
  valToArray,
  valToDate,
} from '@tomic/lib';
import { useEffect, useState } from 'react';
import { useStore, useString, useTitle } from './index.js';

/** Properties not relevant to show in PropValLines */
const hiddenProps = [
  // Shown as title
  properties.name,
  properties.shortname,
  properties.file.filename,
  // Shown separately
  properties.description,
  // Shown in rights / share menu
  properties.write,
  properties.read,
];

/**
 * Returns a Markdown string representing the entire Resource, e.g.:
 *
 * ```md
 * # Some Title
 *
 * author: [joe](https://example.com/joe)
 *
 * published-at: 2020-01-01
 *
 * And here a description! Hello world!
 * ```
 */
export function useMarkdown(resource: Resource): string {
  const [title] = useTitle(resource);
  const [description] = useString(resource, urls.properties.description);
  const [md, setMd] = useState(`# ${title}`);
  const store = useStore();

  useEffect(() => {
    async function getPropValTexts() {
      let propValLines = '';

      for await (const [prop, val] of resource.getPropVals()) {
        if (!hiddenProps.includes(prop)) {
          propValLines = propValLines + (await propertyLine(prop, val, store));
        }
      }

      setMd(`# ${title}` + propValLines + '\n\n' + description);
    }

    getPropValTexts();
  }, [resource]);

  if (resource.error) {
    return resource.error.message;
  }

  return md;
}

/** Renders a single Atomic Property + Value as a single Markdown line */
async function propertyLine(
  propertySubject: string,
  value: JSONValue,
  store: Store,
): Promise<string> {
  const property = await store.getProperty(propertySubject);
  let valString = value?.toString();

  switch (property.datatype) {
    case Datatype.ATOMIC_URL:
      valString = `[${value}](${value})`;
      break;
    case Datatype.RESOURCEARRAY:
      {
        valString = '';
        valToArray(value).map(item => {
          valString = valString + `[${item}](${item}),`;
        });
      }

      break;
    case Datatype.TIMESTAMP:
      valString = valToDate(value).toLocaleString();
      break;
  }

  return `\n\n**${property.shortname}**: ${valString}`;
}
