import { urls } from '@tomic/react';

export function formatNumber(
  value: number | undefined,
  fractionDigits: number | undefined,
  formatting?: string,
): string {
  if (value === undefined) {
    return '';
  }

  // Bad data like negative values will cause a crash so we need to make it valid before formatting.
  const fixedFractionDigits = fixInvalidFractionDigits(fractionDigits);

  if (formatting === urls.instances.numberFormats.percentage) {
    const formatter = new Intl.NumberFormat('default', {
      style: 'percent',
      minimumFractionDigits: fixedFractionDigits,
    });

    return formatter.format(value / 100);
  }

  const formatter = new Intl.NumberFormat('default', {
    style: 'decimal',
    minimumFractionDigits: fixedFractionDigits,
  });

  return formatter.format(value);
}

function fixInvalidFractionDigits(
  fractionDigits: number | undefined,
): number | undefined {
  if (fractionDigits === undefined) {
    return undefined;
  }

  // INTL only supports 0-20 fraction digits
  return Math.min(20, Math.max(0, fractionDigits));
}
