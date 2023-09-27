export const camelCaseify = (str: string) =>
  str.replace(/-([a-z])/g, g => {
    return g[1].toUpperCase();
  });
