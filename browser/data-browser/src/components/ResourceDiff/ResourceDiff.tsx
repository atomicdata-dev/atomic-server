import { lazy, Suspense, type FC } from 'react';
import { Spinner } from '@components/Spinner';
import type {
  ChangeSwitcherProps,
  ResourceDiffProps,
} from '@chunks/ResourceDiff/ResourceDiff';

export {
  useResourceDiff,
  isPropEqual,
  type AtomicDiff,
} from './resourceDiffUtils';

const ResourceDiffChunk = lazy(() =>
  import('@chunks/ResourceDiff/ResourceDiff').then(m => ({
    default: m.ResourceDiff,
  })),
);

const ChangeSwitcherChunk = lazy(() =>
  import('@chunks/ResourceDiff/ResourceDiff').then(m => ({
    default: m.ChangeSwitcher,
  })),
);

export const ResourceDiff: FC<ResourceDiffProps> = props => (
  <Suspense fallback={<Spinner centered />}>
    <ResourceDiffChunk {...props} />
  </Suspense>
);

export const ChangeSwitcher: FC<ChangeSwitcherProps> = props => (
  <Suspense fallback={<Spinner centered />}>
    <ChangeSwitcherChunk {...props} />
  </Suspense>
);
