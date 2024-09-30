import { core, useStore, type Core, type Store } from '@tomic/react';
import { useState, useEffect } from 'react';

type TitlePropResult = {
  titleProp: string | undefined;
  classTitle: string | undefined;
};

export async function getTitlePropOfClass(
  isA: string | undefined,
  store: Store,
): Promise<TitlePropResult> {
  if (isA === undefined) {
    return {
      titleProp: undefined,
      classTitle: undefined,
    };
  }

  const classResource = await store.getResource<Core.Class>(isA);

  if (classResource.error) {
    return {
      titleProp: undefined,
      classTitle: undefined,
    };
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

export function useTitlePropOfClass(isA: string | undefined): TitlePropResult {
  const store = useStore();
  const [result, setResult] = useState<TitlePropResult>({
    titleProp: undefined,
    classTitle: undefined,
  });

  useEffect(() => {
    if (isA === undefined) {
      return;
    }

    getTitlePropOfClass(isA, store).then(setResult);
  }, [isA, store]);

  return result;
}
