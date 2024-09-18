import { core, useResource, type Core } from '@tomic/react';

export function useTitlePropOfClass(isA: string | undefined): {
  titleProp: string | undefined;
  classTitle: string | undefined;
} {
  const classResource = useResource<Core.Class>(isA);

  if (isA === undefined || classResource.loading || classResource.error) {
    return { titleProp: undefined, classTitle: undefined };
  }

  const props = [
    ...(classResource.props.requires ?? []),
    ...(classResource.props.recommends ?? []),
  ];

  if (props.includes(core.properties.shortname)) {
    return {
      titleProp: core.properties.shortname,
      classTitle: classResource.title,
    };
  }

  if (props.includes(core.properties.name)) {
    return {
      titleProp: core.properties.name,
      classTitle: classResource.title,
    };
  }

  return {
    titleProp: undefined,
    classTitle: classResource.title,
  };
}
