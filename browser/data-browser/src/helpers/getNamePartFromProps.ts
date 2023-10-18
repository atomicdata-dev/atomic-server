import { core, JSONValue } from '@tomic/react';
import { randomString } from './randomString';

const normalizeName = (name: string) =>
  encodeURIComponent(name.replace(/\s/g, '-'));

export const getNamePartFromProps = (
  props: Record<string, JSONValue>,
): string =>
  normalizeName(
    (props?.[core.properties.shortname] as string) ??
      (props?.[core.properties.name] as string) ??
      randomString(8),
  );
