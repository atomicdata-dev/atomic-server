import {
  core,
  dataBrowser,
  server,
  useArray,
  useFileObjectUrl,
  useResource,
  useString,
  useSubject,
  type Resource,
} from '@tomic/react';
import type { IconType } from 'react-icons';
import { styled } from 'styled-components';
import { getIconForClass } from '../helpers/iconMap';
import { AvatarImg } from './AvatarImg';

import type { JSX } from 'react';

export interface ResourceGlyphProps {
  resource: Resource;
  /** Render nothing instead of falling back to the class icon. */
  requireCustom?: boolean;
  /** Overrides the class-icon fallback (e.g. datatype icons for Properties). */
  fallbackIcon?: IconType;
  className?: string;
}

/**
 * The resource's glyph, one precedence rule for every surface:
 * icon image > emoji > class icon. Sized in `em` so it scales with its
 * context (sidebar row, inline link, page title).
 */
export function ResourceGlyph({
  resource,
  requireCustom,
  fallbackIcon,
  className,
}: ResourceGlyphProps): JSX.Element | null {
  const [iconImage] = useSubject(resource, dataBrowser.properties.icon);
  const [emoji] = useString(resource, dataBrowser.properties.emoji);
  const [isA] = useArray(resource, core.properties.isA);
  // Per-drive schema classes are recognised by shortname, so load the class.
  const classResource = useResource(isA[0]);
  const [classShortname] = useString(classResource, core.properties.shortname);

  if (iconImage) {
    return (
      <GlyphImage
        subject={iconImage}
        circle={isA.includes(core.classes.agent)}
        className={className}
      />
    );
  }

  if (emoji) {
    return (
      <EmojiGlyph aria-hidden className={className}>
        {emoji}
      </EmojiGlyph>
    );
  }

  if (requireCustom) {
    return null;
  }

  const Icon =
    fallbackIcon ?? getIconForClass(isA[0], undefined, classShortname);

  return <Icon className={className} />;
}

interface GlyphImageProps {
  subject: string;
  circle?: boolean;
  className?: string;
}

/**
 * Renders an icon/avatar File as a small image. The file is already tiny
 * (baked client-side at upload), so this is a plain <img> — local blob when
 * offline, the raw download URL otherwise. No server rendition machinery.
 */
function GlyphImage({
  subject,
  circle,
  className,
}: GlyphImageProps): JSX.Element | null {
  const file = useResource(subject);
  const [downloadUrl] = useString(file, server.properties.downloadUrl);
  const src = useFileObjectUrl(file, downloadUrl);

  // The box is there from the first render, so whatever sits beside the glyph
  // does not move when the picture arrives; `AvatarImg` fills it with a
  // placeholder until then and retries a load that failed.
  return (
    <IconBox $circle={!!circle} className={className}>
      <AvatarImg src={src} alt='' />
    </IconBox>
  );
}

const IconBox = styled.span<{ $circle: boolean }>`
  display: inline-block;
  width: 1.2em;
  height: 1.2em;
  border-radius: ${p => (p.$circle ? '50%' : '20%')};
  overflow: hidden;
  vertical-align: -0.25em;
  flex-shrink: 0;
`;

const EmojiGlyph = styled.span`
  line-height: 1;
`;
