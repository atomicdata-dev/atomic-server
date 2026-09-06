import {
  attributionForVersion,
  type Attribution,
  type HistoryAttribution,
  type Version,
} from '@tomic/react';
import { styled } from 'styled-components';

import type { JSX } from 'react';
import { ResourceInline } from '../../views/ResourceInline/ResourceInline';

const formatter = new Intl.DateTimeFormat('default', {
  month: 'long',
  year: 'numeric',
  day: 'numeric',
  hour: 'numeric',
  minute: 'numeric',
  second: 'numeric',
});

export interface VersionTitleProps {
  version: Version;
  /** Signed-envelope attribution for the resource, when any is retained. */
  attribution?: HistoryAttribution | null;
}

/**
 * "Edited <when> by <whom>". The signer comes from a signed envelope whose
 * Loro change token matches this version, and is labelled Verified when the
 * answering node checked the signature. A version no envelope claims falls
 * back to the Loro peer id: that is who typed, not a proof of who signed.
 *
 * Kept as small, flat pieces of JSX text: the i18n extractor (wuchale) turns
 * each text run into a catalogue entry, and a ternary spanning elements
 * extracts as one placeholder-heavy message that renders as `[i18n-404:…]`
 * until translated.
 */
export function VersionTitle({
  version,
  attribution,
}: VersionTitleProps): JSX.Element {
  const date = new Date(version.timestamp);
  const formattedDate = formatter.format(date);
  const signed = attributionForVersion(version, attribution);

  return (
    <span>
      Edited <time dateTime={date.toISOString()}>{formattedDate}</time>{' '}
      {signed ? (
        <SignedBy attribution={signed} />
      ) : (
        <UnattributedBy peer={version.peer} />
      )}
      {version.message && !signed && <> — {version.message}</>}
    </span>
  );
}

function SignedBy({ attribution }: { attribution: Attribution }): JSX.Element {
  const label = attribution.verified ? 'Verified' : 'Unverified';
  const title = attribution.verified
    ? "Signature checked against the signer's key"
    : 'Envelope present, but its signature did not verify';

  return (
    <>
      by <ResourceInline subject={attribution.signer} />{' '}
      <Badge
        $verified={attribution.verified}
        title={title}
        data-testid='version-attribution'
      >
        {label}
      </Badge>
    </>
  );
}

function UnattributedBy({ peer }: { peer?: string }): JSX.Element | null {
  if (!peer) return null;

  const shortPeer = `${peer.slice(0, 8)}...`;

  return (
    <>
      by peer {shortPeer}{' '}
      <Badge
        $verified={false}
        title='No signed envelope covers this change on this node'
        data-testid='version-attribution'
      >
        Unattributed
      </Badge>
    </>
  );
}

const Badge = styled.span<{ $verified: boolean }>`
  display: inline-block;
  padding: 0 0.4em;
  border-radius: ${p => p.theme.radius};
  font-size: 0.8em;
  line-height: 1.6;
  color: ${p => (p.$verified ? 'white' : p.theme.colors.textLight)};
  background-color: ${p =>
    p.$verified ? p.theme.colors.main : p.theme.colors.bg1};
`;
