import { useMemo } from 'react';
import { styled } from 'styled-components';
import toast from 'react-hot-toast';
import {
  commits,
  diffFork,
  forks,
  useResource,
  useValue,
  type Resource,
} from '@tomic/react';
import { FaCodeBranch, FaCodeMerge } from 'react-icons/fa6';
import { useNavigateWithTransition } from '../hooks/useNavigateWithTransition';
import { constructOpenURL } from '../helpers/navigation';
import { ResourceInline } from '../views/ResourceInline/ResourceInline';
import { Button } from './Button';
import { Row } from './Row';

interface ForkBarProps {
  resource: Resource;
}

/**
 * Shown above a Fork's normal view. A fork renders through the same view as
 * the resource it forked — it carries that resource's classes — so without this
 * bar there is nothing on screen to say you are not looking at the original.
 */
export function ForkBar({ resource }: ForkBarProps): React.JSX.Element | null {
  const navigate = useNavigateWithTransition();
  const original = resource.get(forks.properties.originalSubject) as
    | string
    | undefined;
  const originalResource = useResource(original ?? '');

  // Subscribe to each resource's latest commit so the component re-renders when
  // either changes — and so `diffFork` is recomputed then, rather than being
  // memoized on the (stable) resource proxy references, which never change when
  // a resource mutates internally. See the React-Compiler / Resource-proxy note.
  const [forkCommit] = useValue(resource, commits.properties.lastCommit);
  const [originalCommit] = useValue(
    originalResource,
    commits.properties.lastCommit,
  );

  const changes = useMemo(
    () => diffFork(resource, originalResource),
    // The commit ids are deliberate invalidation keys, not syntactic inputs:
    // `diffFork` reads the resources' internals, which mutate without changing
    // the proxy reference. Re-run when either resource commits.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [resource, originalResource, forkCommit, originalCommit],
  );

  if (!resource.isFork || !original) {
    return null;
  }

  const conflicts = changes.filter(c => c.conflict);
  // A document/canvas fork carries its edits in a Loro body, not in propvals,
  // so `diffFork` (propvals only) can't see them. Presence of a fork version
  // marks such a fork; treat it as always mergeable rather than showing "no
  // changes" and disabling merge. The body itself is CRDT-merged.
  const hasBody = !!resource.get(forks.properties.forkVersion);
  const mergeable = changes.length > 0 || hasBody;

  const merge = async () => {
    // Never let a merge silently overwrite a property that was also edited on
    // the original since the fork — make the reviewer choose.
    if (
      conflicts.length > 0 &&
      !window.confirm(
        `${conflicts.length} propert${
          conflicts.length === 1 ? 'y was' : 'ies were'
        } also changed on the original since this fork was made (${conflicts
          .map(c => c.property.split('/').pop())
          .join(', ')}). Merging will overwrite ${
          conflicts.length === 1 ? 'it' : 'them'
        } with this fork's version. Continue?`,
      )
    ) {
      return;
    }

    try {
      const merged = await resource.mergeIntoOriginal();
      toast.success('Fork merged');
      navigate(constructOpenURL(merged.subject));
    } catch (error) {
      toast.error((error as Error).message);
    }
  };

  const discard = async () => {
    try {
      await resource.destroy();
      toast.success('Fork discarded');
      navigate(constructOpenURL(original));
    } catch (error) {
      toast.error((error as Error).message);
    }
  };

  return (
    <Wrapper>
      <Row justify='space-between' center gap='1ch'>
        {/* Each translatable string stays whole and separate from the resource
            link: wuchale turns a sentence with a component spliced into it into
            an array of children, which React then wants keys for. */}
        <Row center gap='1ch'>
          <FaCodeBranch />
          <span>Fork of</span>
          <ResourceInline subject={original} />
          <Subtle>
            {changes.length === 0
              ? hasBody
                ? 'Edit the body, then merge.'
                : 'No changes yet.'
              : `${changes.length} changed propert${
                  changes.length === 1 ? 'y' : 'ies'
                }.`}
          </Subtle>
          {conflicts.length > 0 && (
            <Conflict>
              {conflicts.length} conflict{conflicts.length === 1 ? '' : 's'}
            </Conflict>
          )}
        </Row>
        <Row center gap='1ch'>
          <Button subtle onClick={discard}>
            Discard
          </Button>
          <Button onClick={merge} disabled={!mergeable}>
            <FaCodeMerge /> <span>Merge</span>
          </Button>
        </Row>
      </Row>
    </Wrapper>
  );
}

const Subtle = styled.span`
  color: ${p => p.theme.colors.textLight};
`;

const Conflict = styled.span`
  color: ${p => p.theme.colors.alert};
  font-weight: bold;
`;

/** A bar, not a card: it spans the view it sits above rather than floating in it. */
const Wrapper = styled.aside`
  background-color: ${p => p.theme.colors.bg1};
  border-bottom: 1px solid ${p => p.theme.colors.bg2};
  padding: ${p => p.theme.size(2)} 0;
  margin-bottom: ${p => p.theme.size(2)};
`;
