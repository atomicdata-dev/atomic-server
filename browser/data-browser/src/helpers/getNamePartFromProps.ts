import { JSONValue, properties } from '@tomic/react';
import { randomString } from './randomString';

const normalizeName = (name: string) =>
  encodeURIComponent(name.replaceAll('/t', '-'));

export const getNamePartFromProps = (
  props: Record<string, JSONValue>,
): string =>
  normalizeName(
    (props?.[properties.shortname] as string) ??
      (props?.[properties.name] as string) ??
      randomString(8),
  );
