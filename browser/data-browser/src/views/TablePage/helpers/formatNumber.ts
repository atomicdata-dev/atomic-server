import { urls } from '@tomic/react';

export function formatNumber(
  value: number | undefined,
  numberOfDecimalPlaces: number,
  formatting?: string,
): string {
  if (value === undefined) {
    return '';
  }

  if (formatting === urls.instances.numberFormats.percentage) {
    const formatter = new Intl.NumberFormat('default', {
      style: 'percent',
      minimumFractionDigits: numberOfDecimalPlaces,
    });

    return formatter.format(value);
  }

  const formatter = new Intl.NumberFormat('default', {
    style: 'decimal',
    minimumFractionDigits: numberOfDecimalPlaces,
  });

  return formatter.format(value);
}
