export const buildFormatters = (
  withTime: boolean,
): {
  longDateFormatter: Intl.DateTimeFormat;
  numericDateFormatter: Intl.DateTimeFormat;
  timeFormatter: Intl.DateTimeFormat;
} => {
  const timeFormatting: Intl.DateTimeFormatOptions = {
    hour: 'numeric',
    minute: 'numeric',
  };

  const dateBase: Intl.DateTimeFormatOptions = {
    day: 'numeric',
    year: 'numeric',
  };

  const timeFormatter = new Intl.DateTimeFormat('default', timeFormatting);

  const longDateFormatter = new Intl.DateTimeFormat('default', {
    ...dateBase,
    ...(withTime ? timeFormatting : {}),
    month: 'long',
  });

  const numericDateFormatter = new Intl.DateTimeFormat('default', {
    ...dateBase,
    ...(withTime ? timeFormatting : {}),
    month: 'numeric',
  });

  return { longDateFormatter, numericDateFormatter, timeFormatter };
};
