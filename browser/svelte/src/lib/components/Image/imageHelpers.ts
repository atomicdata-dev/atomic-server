type SizeIndicationKey = `${number}px`;
export type Unit = number | `${number}${'px' | 'vw' | 'em' | 'rem' | 'ch'}`;

export type SizeIndication =
	| {
			[key: SizeIndicationKey]: Unit;
			default: Unit;
	  }
	| Unit;

export const imageFormatsWithBasicSupport = new Set([
	'image/svg+xml',
	'image/vnd.adobe.photoshop',
	'image/heif',
	'image/heif-sequence',
	'image/heic-sequence',
	'image/avif-sequence',
	'image/gif',
	'image/heic',
	'image/heif'
]);

export const imageFormatsWithFullSupport = new Set([
	'image/png',
	'image/jpeg',
	'image/vnd.microsoft.icon',
	'image/webp',
	'image/bmp',
	'image/tiff',
	'image/avif'
]);

export const DEFAULT_SIZES = [100, 300, 500, 800, 1200, 1600, 2000];

export const indicationToSizes = (indication: SizeIndication | undefined): string => {
	if (indication === undefined) {
		return '100vw';
	}

	if (typeof indication === 'number' || typeof indication === 'string') {
		return parseUnit(indication);
	}

	return Object.entries(indication)
		.map(([key, value]) =>
			key === 'default' ? parseUnit(value) : `(max-width: ${key}) ${parseUnit(value)}`
		)
		.join(', ');
};

const parseUnit = (unit: Unit): string => (typeof unit === 'number' ? `${unit}vw` : unit);

const toUrl = (base: string, format?: string, quality?: number, width?: number) => {
	const url = new URL(base);
	const queryParams = new URLSearchParams();
	if (format) queryParams.set('f', format);
	if (width !== undefined) queryParams.set('w', width.toString());
	if (quality !== undefined) queryParams.set('q', quality.toString());
	url.search = queryParams.toString();

	return url.toString();
};

export const buildSrcSet =
	(base: string) =>
	(format: string, quality: number, sizes: number[]): string => {
		return sizes
			.map((size) => {
				return `${toUrl(base, format, quality, size)} ${size}w`;
			})
			.join(', ');
	};
