import { useMemo, useState } from 'react';
import { styled } from 'styled-components';
import toast from 'react-hot-toast';
import {
  commits,
  diffFork,
  forks,
  unknownSubject,
  useResource,
  useValue,
  type Resource,
} from '@tomic/react';
import { FaCodeBranch, FaCodeMerge, FaListCheck } from 'react-icons/fa6';
import { useNavigateWithTransition } from '../hooks/useNavigateWithTransition';
import { constructOpenURL } from '../helpers/navigation';
import { ResourceInline } from '../views/ResourceInline/ResourceInline';
import { Button } from './Button';
import { Row } from './Row';
import { ResourceDiff, type AtomicDiff } from './ResourceDiff/ResourceDiff';

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
  // `unknownSubject` rather than `''`: an empty subject resolves against the
  // page origin, so every non-fork resource (the bar renders above all of them
  // and only returns null below, after the hooks have run) fetched the server
  // root and got a 404 — nothing serves a resource there, since no Drive is
  // created at `/`. The store answers `unknownSubject` from memory and never
  // reaches for the network.
  const originalResource = useResource(original ?? unknownSubject);

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

  // The review panel: every changed property, the original's current value
  // against the fork's. Off by default so the bar stays one line; a reviewer
  // opens it before merging instead of trusting a count.
  const [reviewing, setReviewing] = useState(false);
  const diff = useMemo(
    (): AtomicDiff => ({
      oldResource: originalResource,
      newResource: resource,
      changedProps: changes.map(c => c.property),
    }),
    [originalResource, resource, changes],
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
      navigate(constructOpenURL(merged.subject));
    } catch (error) {
      toast.error((error as Error).message);
    }
  };

  const discard = async () => {
    try {
      await resource.destroy();
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
          {changes.length > 0 && (
            <Button
              subtle
              onClick={() => setReviewing(r => !r)}
              data-testid='fork-review'
              aria-expanded={reviewing}
            >
              <FaListCheck />{' '}
              <span>{reviewing ? 'Hide changes' : 'Review changes'}</span>
            </Button>
          )}
          <Button subtle onClick={discard}>
            Discard
          </Button>
          <Button onClick={merge} disabled={!mergeable}>
            <FaCodeMerge /> <span>Merge</span>
          </Button>
        </Row>
      </Row>
      {reviewing && changes.length > 0 && (
        <ReviewPanel data-testid='fork-review-panel'>
          {/* Old is the original as it is now, new is the fork: what a merge
              would write over what. */}
          <ResourceDiff diff={diff} />
          {conflicts.length > 0 && (
            <ConflictNote>
              <span>
                Also changed on the original since this fork was made:
              </span>
              {conflicts.map(c => (
                <ConflictProp key={c.property}>
                  <ResourceInline subject={c.property} />
                </ConflictProp>
              ))}
              <span>Merging keeps the fork's version.</span>
            </ConflictNote>
          )}
        </ReviewPanel>
      )}
    </Wrapper>
  );
}

const ReviewPanel = styled.div`
  margin-top: ${p => p.theme.size(2)};
  padding: ${p => p.theme.size(2)};
  border-radius: ${p => p.theme.radius};
  background-color: ${p => p.theme.colors.bg};
`;

const ConflictNote = styled.div`
  display: flex;
  flex-wrap: wrap;
  gap: 1ch;
  align-items: center;
  margin-top: ${p => p.theme.size(2)};
  color: ${p => p.theme.colors.alert};
`;

const ConflictProp = styled.span`
  font-weight: bold;
`;

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
