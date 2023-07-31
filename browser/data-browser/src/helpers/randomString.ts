export const randomString = (length = 15) => {
  const chars =
    'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  let result = '';

  for (let i = 0; i < length; i++) {
    result += chars[Math.floor(Math.random() * chars.length)];
  }

  return result;
};

export const randomSubject = (parent: string, prefix?: string) => {
  return `${parent}${prefix ? `/${prefix}/` : ''}${randomString(15)}`;
};
