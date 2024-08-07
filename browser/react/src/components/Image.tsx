import type { Resource, Server } from '@tomic/lib';
import React from 'react';
import { server, useResource, useString } from '../index.js';

const imageFormatsWithBasicSupport = new Set([
  'image/svg+xml',
  'image/vnd.adobe.photoshop',
  'image/heif',
  'image/heif-sequence',
  'image/heic-sequence',
  'image/avif-sequence',
  'image/gif',
  'image/heic',
  'image/heif',
]);

const imageFormatsWithFullSupport = new Set([
  'image/png',
  'image/jpeg',
  'image/vnd.microsoft.icon',
  'image/webp',
  'image/bmp',
  'image/tiff',
  'image/avif',
]);

const DEFAULT_SIZES = [100, 300, 500, 800, 1200, 1600, 2000];

type SizeIndicationKey = `${number}px`;
type Unit = number | `${number}${'px' | 'vw' | 'em' | 'rem' | 'ch'}`;

export type SizeIndication =
  | {
      [key: SizeIndicationKey]: Unit;
      default: Unit;
    }
  | Unit;

interface ImageInnerProps
  extends Omit<
    React.ImgHTMLAttributes<HTMLPictureElement>,
    'resource' | 'src'
  > {
  resource: Resource<Server.File>;
  /**
   * SizeIndication is used to help the browser choose the right image size to fetch.
   * By default, the browser looks at the entire viewport width and chooses the smallest version that still covers this width.
   * This is often too big so we should help by giving it an approximation of the size of the image relative to the viewport.
   *
   * When the unit given is a number it is interpreted as a percentage of the viewport width. If your image is displayed in a static size you can also pass a string like '4rem'.
   * Note that percentages don't work as the browser doesn't know the size of the parent element yet.
   *
   * ```jsx
   * <Image
   *  className='inline-image'
   *  subject='http://myatomicserver.com/files/1664878581079-hiker.jpg'
   *  alt='a person standing in front of a mountain'
   *  sizeIndication={50} // the image is about 50% of the viewport width
   * />
   * ```
   * When the image size changes based on media queries we can give the browser a more detailed indication.
   * ```jsx
   * <Image
   *  className='inline-image'
   *  subject='http://myatomicserver.com/files/1664878581079-hiker.jpg'
   *  alt='a person standing in front of a mountain'
   *  sizeIndication={{
   *    '500px': 100, // On screens smaller than 500px the image is displayed at full width.
   *    default: 50, // the image is about 50% of the viewport when no media query matches
   *  }}
   * />
   * ```
   */
  sizeIndication?: SizeIndication;
  /** Alt text for the image, if you can't add alt text it's best practice to pass an empty string */
  alt: string;
  /** Quality setting used by the image encoders, defaults to 60 (more than enough in most cases). Should be between 0 - 100 */
  quality?: number;
}

export interface ImageProps extends Omit<ImageInnerProps, 'resource'> {
  /** Subject of the file resource */
  subject: string;
}

/**
 * Takes the subject of a file resource and renders it as an image.
 * Uses AtomicServer to automatically generate avif and webp versions of the image and scale them to different sizes.
 * To help the browser choose the best size to load use the `sizeIndication` prop.
 *
 * Throws when the file is not an image.
 * @example
 * ```jsx
 * <Image
 *  subject='http://myatomicserver.com/files/1664878581079-hiker.jpg'
 *  alt='a person standing in front of a mountain'
 *  className='article-inline-image'
 *  loading='lazy'
 *  sizeIndication={{
 *    '500px': 100, // On screens smaller than 500px the image is displayed at full width.
 *    default: 50, // the image is about 50% of the viewport when no media query matches
 *  }}
 * />
 * ```
 */
export const Image: React.FC<ImageProps> = ({ subject, ...props }) => {
  const resource = useResource(subject);
  const [mimeType] = useString(resource, server.properties.mimetype);

  if (resource.loading) {
    return null;
  }

  if (!resource.hasClasses(server.classes.file)) {
    throw new Error('Incompatible resource class, resource is not a file');
  }

  // If the resource does have a file class but mimetype is still undefined, it's still loading so we return null until the value is available
  if (mimeType === undefined) {
    return null;
  }

  if (imageFormatsWithBasicSupport.has(mimeType)) {
    return <BasicImage resource={resource} {...props} />;
  }

  if (!imageFormatsWithFullSupport.has(mimeType)) {
    throw new Error('Incompatible or missing mime-type: ' + mimeType);
  }

  return <ImageInner resource={resource} {...props} />;
};

const ImageInner: React.FC<ImageInnerProps> = ({
  resource,
  sizeIndication,
  quality = 60,
  ...props
}) => {
  const [downloadUrl] = useString(resource, server.properties.downloadUrl);
  const toSrcSet = buildSrcSet(downloadUrl ?? '');

  return (
    <picture>
      <source
        srcSet={toSrcSet('avif', quality, DEFAULT_SIZES)}
        type='image/avif'
        sizes={indicationToSizes(sizeIndication)}
        height={resource.props.imageHeight}
        width={resource.props.imageWidth}
      />
      <source
        srcSet={toSrcSet('webp', quality, DEFAULT_SIZES)}
        type='image/webp'
        sizes={indicationToSizes(sizeIndication)}
        height={resource.props.imageHeight}
        width={resource.props.imageWidth}
      />
      {/* eslint-disable-next-line jsx-a11y/alt-text */}
      <img
        src={downloadUrl}
        {...props}
        height={resource.props.imageHeight}
        width={resource.props.imageWidth}
      />
    </picture>
  );
};

const BasicImage: React.FC<ImageInnerProps> = ({
  resource,
  sizeIndication: _sizeIndication,
  quality: _quality,
  ...props // html image atrributes only
}) => {
  const [downloadUrl] = useString(resource, server.properties.downloadUrl);

  // eslint-disable-next-line jsx-a11y/alt-text
  return <img src={downloadUrl} {...props} />;
};

const indicationToSizes = (indication: SizeIndication | undefined): string => {
  if (indication === undefined) {
    return '100vw';
  }

  if (typeof indication === 'number' || typeof indication === 'string') {
    return parseUnit(indication);
  }

  return Object.entries(indication)
    .map(([key, value]) =>
      key === 'default'
        ? parseUnit(value)
        : `(max-width: ${key}) ${parseUnit(value)}`,
    )
    .join(', ');
};

const parseUnit = (unit: Unit): string =>
  typeof unit === 'number' ? `${unit}vw` : unit;

const toUrl = (
  base: string,
  format?: string,
  quality?: number,
  width?: number,
) => {
  const url = new URL(base);
  const queryParams = new URLSearchParams();
  format && queryParams.set('f', format);
  width && queryParams.set('w', width.toString());
  quality && queryParams.set('q', quality.toString());
  url.search = queryParams.toString();

  return url.toString();
};

const buildSrcSet =
  (base: string) =>
  (format: string, quality: number, sizes: number[]): string => {
    return sizes
      .map(size => {
        return `${toUrl(base, format, quality, size)} ${size}w`;
      })
      .join(', ');
  };
